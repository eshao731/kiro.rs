//! 中转层 prompt cache（无外部依赖）
//!
//! Kiro 上游不下发 cache_creation / cache_read token 字段（实测 meteringEvent
//! 只给 credit 计费量），所以这里在中转层自行模拟"提示词缓存"，复现 Anthropic
//! 滑动窗口缓存的「稳定片段复用」语义：
//!
//! - system / tools 使用长 TTL 独立缓存；
//! - messages 使用完整消息前缀 + 每个历史消息前缀做滑动窗口匹配；
//! - 单条长消息和 tool_result 也单独做短 TTL 片段，避免前面动态内容污染整条链。
//!
//! 跨轮命中的关键：上一轮完整 messages 会成为下一轮的某个历史前缀，即使 system
//! 头部、tools 或 metadata 每轮变化，稳定的历史消息片段仍可命中。
//!
//! 内存 + JSON 落盘：每分钟一次写到 `cache_dir/cache_metering.json`，启动时读
//! 回过期记录会被丢掉。**不依赖 Redis 或任何外部 KV**。

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// 默认条目上限（防止内存无限增长）。多片段缓存比单链缓存条目更多，容量稍放大。
const DEFAULT_CAPACITY: usize = 32768;
/// TTL 上限，防止误配置导致条目常驻。
const MAX_TTL_SECS: i64 = 24 * 3600;
/// 默认短 TTL（5min，ephemeral 默认值）。
const DEFAULT_SHORT_TTL_SECS: i64 = 5 * 60;
/// 默认长 TTL（1h，与 Anthropic ttl="1h" 对齐）。
const DEFAULT_LONG_TTL_SECS: i64 = 3600;
const MIN_SEGMENT_CHARS: usize = 64;
const MIN_MESSAGE_BLOCK_CHARS: usize = 256;

/// 单个缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// 该前缀段累计的估算 token 数
    pub tokens: u32,
    /// 过期时间戳（unix 秒）
    pub expires_at: i64,
    /// 上次命中时间（用于 LRU 淘汰）
    pub last_hit_at: i64,
}

/// 一次查询的结果（每段一份）
#[derive(Debug, Clone, Copy)]
pub struct SegmentResult {
    /// 该段是否命中
    pub hit: bool,
    /// 该段累计 tokens（保留供调试 / 调用方扩展，dead_code 抑制）
    #[allow(dead_code)]
    pub tokens: u32,
}

/// `compute_cache_usage` 的结果：缓存计费量 + 比例分摊所需的 estimate 口径基准。
///
/// `cache_creation` / `cache_read` 是按 `estimate_tokens` 口径算出的「被缓存覆盖
/// 前缀」的拆分；但最终上报要换算到**真实 total 口径**（contextUsage 真值或
/// `count_tokens` 估算），两个估算器尺度不同，所以这里额外带出两个 estimate 口径
/// 的基准量，供调用方做**无量纲比例分摊**：
///   - `cache_covered_est` = 被缓存覆盖前缀的 estimate token（= creation + read）
///   - `prompt_total_est`  = 整个 prompt（含最深断点之后未缓存尾部）的 estimate token
///
/// 调用方据此算 `prefix_ratio = cache_covered_est / prompt_total_est`，再乘到真实
/// total 上得到缓存覆盖部分，剩余即未缓存的 `input_tokens`，三者互斥相加 == total。
#[derive(Debug, Clone, Copy)]
pub struct CacheUsage {
    /// 缓存读取 token（estimate 口径，最深命中段累计）。
    /// creation 部分 = `cache_covered_est − cache_read`，无需单独存储。
    pub cache_read: i32,
    /// 被缓存覆盖前缀的 estimate token 总量（read + creation）。
    pub cache_covered_est: i32,
    /// 整个 prompt 的 estimate token 总量（比例分摊的分母）。
    pub prompt_total_est: i32,
    /// 缓存覆盖最多可计入的真实输入 token 比例。
    pub max_savings_ratio: f64,
}

impl Default for CacheUsage {
    fn default() -> Self {
        Self {
            cache_read: 0,
            cache_covered_est: 0,
            prompt_total_est: 0,
            max_savings_ratio: 0.90,
        }
    }
}

impl CacheUsage {
    /// 按真实 total 口径做互斥分摊，返回 `(input_tokens, cache_creation, cache_read)`。
    ///
    /// `total_real` 是最终上报口径的全量 prompt token（contextUsage 真值优先，
    /// 否则 `count_tokens` 估算）。三者满足 `input + creation + read == total_real`。
    ///
    /// 无缓存覆盖（`cache_covered_est == 0`）或基准缺失时，直接返回
    /// `(total_real, 0, 0)`——全部计入 input，不凭空造缓存计数。
    pub fn split_against_total(&self, total_real: i32) -> (i32, i32, i32) {
        let total = total_real.max(0);
        if self.cache_covered_est <= 0 || self.prompt_total_est <= 0 {
            return (total, 0, 0);
        }
        // 比例无量纲，跨估算器成立；clamp 到 [0, total] 防止 estimate 偏差越界。
        let ratio = (self.cache_covered_est as f64 / self.prompt_total_est as f64).clamp(0.0, 1.0);
        let cache_total = ((total as f64) * ratio).round() as i32;
        let max_cache_total =
            ((total as f64) * self.max_savings_ratio.clamp(0.0, 1.0)).floor() as i32;
        let cache_total = cache_total.min(total).min(max_cache_total.max(0));
        // 在缓存覆盖部分内部，按 estimate 口径的 read/creation 占比二次拆分。
        let read = if self.cache_covered_est > 0 {
            ((cache_total as f64) * (self.cache_read as f64 / self.cache_covered_est as f64))
                .round() as i32
        } else {
            0
        };
        let read = read.clamp(0, cache_total);
        let creation = cache_total - read;
        let input = total - cache_total;
        (input, creation, read)
    }
}

/// 进程内提示词缓存
pub struct CacheMeter {
    inner: Mutex<Inner>,
    persist_path: Option<PathBuf>,
    max_savings_ratio: f64,
    short_ttl_secs: i64,
    long_ttl_secs: i64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<u64, CacheEntry>,
    /// 自上次落盘后是否有变化
    dirty: bool,
}

impl CacheMeter {
    /// 创建一个空 cache。`persist_path` 为 `Some` 时会自动从该文件加载历史。
    pub fn new(persist_path: Option<PathBuf>) -> Self {
        Self::with_max_savings_ratio(persist_path, 0.90)
    }

    /// 创建一个空 cache，并限制最终 cache_creation/cache_read 占输入 token 的最大比例。
    pub fn with_max_savings_ratio(persist_path: Option<PathBuf>, max_savings_ratio: f64) -> Self {
        Self::with_config(
            persist_path,
            max_savings_ratio,
            DEFAULT_SHORT_TTL_SECS as u64,
            DEFAULT_LONG_TTL_SECS as u64,
        )
    }

    /// 创建一个空 cache，并设置短/长 TTL 与最终缓存计入口径。
    pub fn with_config(
        persist_path: Option<PathBuf>,
        max_savings_ratio: f64,
        short_ttl_secs: u64,
        long_ttl_secs: u64,
    ) -> Self {
        let mut inner = Inner::default();
        if let Some(path) = persist_path.as_ref() {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(entries) = serde_json::from_slice::<HashMap<u64, CacheEntry>>(&bytes) {
                    let now = now_secs();
                    for (k, v) in entries {
                        if v.expires_at > now {
                            inner.entries.insert(k, v);
                        }
                    }
                    tracing::info!(
                        "CacheMeter 重建：从 {} 加载 {} 条有效记录",
                        path.display(),
                        inner.entries.len()
                    );
                }
            }
        }
        Self {
            inner: Mutex::new(inner),
            persist_path,
            max_savings_ratio: max_savings_ratio.clamp(0.0, 1.0),
            short_ttl_secs: normalize_ttl(short_ttl_secs, DEFAULT_SHORT_TTL_SECS),
            long_ttl_secs: normalize_ttl(long_ttl_secs, DEFAULT_LONG_TTL_SECS),
        }
    }

    /// 查询一组前缀段哈希，返回每段命中情况；命中段会刷新 last_hit_at。
    ///
    /// `segment_hashes` 顺序必须与请求中 cache_control 断点顺序一致；
    /// `segment_tokens` 是每段累计 tokens（即 segment_hashes[i] 对应的整段累加值）。
    pub fn lookup(&self, segment_hashes: &[u64], segment_tokens: &[u32]) -> Vec<SegmentResult> {
        debug_assert_eq!(segment_hashes.len(), segment_tokens.len());
        let now = now_secs();
        let mut inner = self.inner.lock();
        let mut out = Vec::with_capacity(segment_hashes.len());
        for (h, t) in segment_hashes.iter().zip(segment_tokens.iter()) {
            let hit = match inner.entries.get_mut(h) {
                Some(entry) if entry.expires_at > now => {
                    entry.last_hit_at = now;
                    true
                }
                _ => false,
            };
            out.push(SegmentResult { hit, tokens: *t });
        }
        out
    }

    /// 把一组前缀段写入缓存（用于 miss 后登记 / 续期）。`ttl_secs` clip 到 [60, MAX_TTL_SECS]。
    pub fn record(&self, segment_hashes: &[u64], segment_tokens: &[u32], ttl_secs: i64) {
        debug_assert_eq!(segment_hashes.len(), segment_tokens.len());
        let ttl = ttl_secs.clamp(60, MAX_TTL_SECS);
        let ttls = vec![ttl; segment_hashes.len()];
        self.record_segments(segment_hashes, segment_tokens, &ttls);
    }

    /// 把一组片段写入缓存，每个片段可有独立 TTL。
    pub fn record_segments(
        &self,
        segment_hashes: &[u64],
        segment_tokens: &[u32],
        ttl_secs: &[i64],
    ) {
        debug_assert_eq!(segment_hashes.len(), segment_tokens.len());
        debug_assert_eq!(segment_hashes.len(), ttl_secs.len());
        let now = now_secs();
        let mut inner = self.inner.lock();
        for ((h, t), ttl) in segment_hashes
            .iter()
            .zip(segment_tokens.iter())
            .zip(ttl_secs.iter())
        {
            let ttl = (*ttl).clamp(60, MAX_TTL_SECS);
            inner.entries.insert(
                *h,
                CacheEntry {
                    tokens: *t,
                    expires_at: now + ttl,
                    last_hit_at: now,
                },
            );
        }
        inner.dirty = true;
        // 容量超限：按 last_hit_at 淘汰最旧的若干条
        if inner.entries.len() > DEFAULT_CAPACITY {
            let drop_n = inner.entries.len() - DEFAULT_CAPACITY;
            let mut victims: Vec<(u64, i64)> = inner
                .entries
                .iter()
                .map(|(k, v)| (*k, v.last_hit_at))
                .collect();
            victims.sort_by_key(|x| x.1);
            for (k, _) in victims.into_iter().take(drop_n) {
                inner.entries.remove(&k);
            }
        }
    }

    /// 把当前快照写到 persist_path（仅在 dirty 时实际落盘）
    pub fn flush_to_disk(&self) {
        let path = match self.persist_path.clone() {
            Some(p) => p,
            None => return,
        };
        let snapshot = {
            let mut inner = self.inner.lock();
            if !inner.dirty {
                return;
            }
            inner.dirty = false;
            inner.entries.clone()
        };
        let json = match serde_json::to_vec(&snapshot) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("CacheMeter 序列化失败: {}", e);
                return;
            }
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, json) {
            tracing::warn!("CacheMeter 落盘失败 {}: {}", path.display(), e);
        }
    }

    /// 启动后台周期任务：定期 flush + 清理过期条目
    pub fn spawn_background(self: Arc<Self>) {
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(60);
            loop {
                tokio::time::sleep(interval).await;
                let Some(cache) = weak.upgrade() else { return };
                cache.evict_expired();
                cache.flush_to_disk();
            }
        });
    }

    /// 删除已过期条目（lookup 不命中过期时只是返回 miss，不会顺手清理；
    /// 这里在后台周期里清一次，避免内存膨胀）。
    pub fn evict_expired(&self) {
        let now = now_secs();
        let mut inner = self.inner.lock();
        let before = inner.entries.len();
        inner.entries.retain(|_, v| v.expires_at > now);
        if inner.entries.len() != before {
            inner.dirty = true;
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 解析 cache_control 的 ttl 字符串（"5m" / "1h"）→ 秒
pub fn parse_ttl(ttl: Option<&str>) -> i64 {
    match ttl {
        Some(s) if s.eq_ignore_ascii_case("1h") => DEFAULT_LONG_TTL_SECS,
        Some(s) if s.eq_ignore_ascii_case("5m") => DEFAULT_SHORT_TTL_SECS,
        _ => DEFAULT_SHORT_TTL_SECS,
    }
}

fn normalize_ttl(value: u64, default: i64) -> i64 {
    if value == 0 {
        default
    } else {
        (value as i64).clamp(60, MAX_TTL_SECS)
    }
}

/// `Arc<CacheMeter>` 别名
pub type SharedCacheMeter = Arc<CacheMeter>;

// ============================================================================
// 与请求体协议层的接线
// ============================================================================

use super::types::{Message, MessagesRequest};

#[derive(Debug, Clone, Copy)]
enum SegmentKind {
    Prefix,
    MessagePrefix,
    MessageBlock,
    ToolResult,
}

/// 协议层提取出来的一个可复用片段。
#[derive(Debug, Clone)]
struct Segment {
    hash: u64,
    kind: SegmentKind,
    name: &'static str,
    byte_len: usize,
    token_estimate: u32,
    ttl_secs: i64,
    should_store: bool,
}

/// 调用 CacheMeter 计算本次请求的缓存覆盖情况，并把所有断点（含命中段）记录回
/// cache、刷新 TTL。返回 [`CacheUsage`]，由调用方在拿到真实 total 后做互斥分摊。
///
/// 这里采用旧本地实现验证过的多片段滑动窗口策略：system/tools、完整 messages、
/// 历史 message prefix、长 message block、tool_result 分开命中。这样前面某个动态
/// 块变化时，不会污染整条累计 hash 链。
pub fn compute_cache_usage(cache: &CacheMeter, req: &MessagesRequest, key_id: u64) -> CacheUsage {
    let (segments, prompt_total_est) = extract_segments(req, key_id, cache);
    if segments.is_empty() {
        return CacheUsage {
            prompt_total_est: prompt_total_est as i32,
            max_savings_ratio: cache.max_savings_ratio,
            ..Default::default()
        };
    }

    let hashes: Vec<u64> = segments.iter().map(|s| s.hash).collect();
    let tokens: Vec<u32> = segments.iter().map(|s| s.token_estimate).collect();
    let results = cache.lookup(&hashes, &tokens);

    let mut cache_read_est = 0u32;
    let mut best_message_prefix_hit_tokens = 0u32;
    let mut message_block_hit_bytes = 0usize;
    let full_message_prefix_bytes = segments
        .iter()
        .filter(|segment| {
            matches!(segment.kind, SegmentKind::MessagePrefix) && segment.should_store
        })
        .map(|segment| segment.byte_len)
        .max()
        .unwrap_or(0);
    let mut stored_est = 0u32;

    for (segment, result) in segments.iter().zip(results.iter()) {
        match segment.kind {
            SegmentKind::Prefix | SegmentKind::ToolResult => {
                if result.hit {
                    cache_read_est = cache_read_est.saturating_add(segment.token_estimate);
                } else if segment.should_store {
                    stored_est = stored_est.saturating_add(segment.token_estimate);
                }
            }
            SegmentKind::MessagePrefix => {
                if result.hit {
                    let estimated = estimate_message_prefix_tokens(
                        segment.byte_len,
                        full_message_prefix_bytes,
                        prompt_total_est,
                    );
                    best_message_prefix_hit_tokens = best_message_prefix_hit_tokens.max(estimated);
                } else if segment.should_store {
                    stored_est = stored_est.saturating_add(segment.token_estimate);
                }
            }
            SegmentKind::MessageBlock => {
                if result.hit {
                    message_block_hit_bytes =
                        message_block_hit_bytes.saturating_add(segment.byte_len);
                } else if segment.should_store {
                    stored_est = stored_est.saturating_add(segment.token_estimate);
                }
            }
        }
    }

    let message_block_hit_tokens = if message_block_hit_bytes > 0 {
        estimate_message_prefix_tokens(
            message_block_hit_bytes,
            full_message_prefix_bytes,
            prompt_total_est,
        )
    } else {
        0
    };
    cache_read_est =
        cache_read_est.saturating_add(best_message_prefix_hit_tokens.max(message_block_hit_tokens));
    cache_read_est = cache_read_est.min(prompt_total_est);

    let cache_creation_est = stored_est.min(prompt_total_est.saturating_sub(cache_read_est));
    let covered = cache_read_est.saturating_add(cache_creation_est);

    if tracing::enabled!(tracing::Level::DEBUG) {
        let dump: Vec<String> = segments
            .iter()
            .zip(results.iter())
            .enumerate()
            .map(|(i, (s, r))| {
                format!(
                    "[{i}] {} {:?} bytes={} tok={} store={} hit={}",
                    s.name, s.kind, s.byte_len, s.token_estimate, s.should_store, r.hit
                )
            })
            .collect();
        tracing::debug!(
            "CacheMeter: {} segments, msgs={}, read_est={}, creation_est={} | {}",
            segments.len(),
            req.messages.len(),
            cache_read_est,
            cache_creation_est,
            dump.join(", ")
        );
    }

    let store: Vec<&Segment> = segments.iter().filter(|s| s.should_store).collect();
    let store_hashes: Vec<u64> = store.iter().map(|s| s.hash).collect();
    let store_tokens: Vec<u32> = store.iter().map(|s| s.token_estimate).collect();
    let store_ttls: Vec<i64> = store.iter().map(|s| s.ttl_secs).collect();
    cache.record_segments(&store_hashes, &store_tokens, &store_ttls);

    CacheUsage {
        cache_read: cache_read_est as i32,
        cache_covered_est: covered as i32,
        prompt_total_est: prompt_total_est as i32,
        max_savings_ratio: cache.max_savings_ratio,
    }
}

fn extract_segments(req: &MessagesRequest, key_id: u64, cache: &CacheMeter) -> (Vec<Segment>, u32) {
    let mut segments: Vec<Segment> = Vec::new();
    let prompt_total_est = crate::token::count_all_tokens(
        req.model.clone(),
        req.system.clone(),
        req.messages.clone(),
        req.tools.clone(),
    )
    .max(0) as u32;

    let salt = format!("key:{key_id}");
    if let Some(system) = req.system.as_ref() {
        if let Ok(value) = serde_json::to_value(system) {
            push_segment(
                &mut segments,
                SegmentKind::Prefix,
                "system",
                cache.long_ttl_secs,
                &salt,
                &value,
                true,
                MIN_SEGMENT_CHARS,
            );
        }
    }
    if let Some(tools) = req.tools.as_ref() {
        if let Ok(value) = serde_json::to_value(tools) {
            push_segment(
                &mut segments,
                SegmentKind::Prefix,
                "tools",
                cache.long_ttl_secs,
                &salt,
                &value,
                true,
                MIN_SEGMENT_CHARS,
            );
        }
    }

    if !req.messages.is_empty() {
        let full_messages = serde_json::Value::Array(
            req.messages
                .iter()
                .filter_map(|message| serde_json::to_value(message).ok())
                .collect(),
        );
        push_segment(
            &mut segments,
            SegmentKind::MessagePrefix,
            "message-prefix",
            cache.short_ttl_secs,
            &salt,
            &full_messages,
            true,
            MIN_SEGMENT_CHARS,
        );

        for end in 1..req.messages.len() {
            let history_prefix = serde_json::Value::Array(
                req.messages[..end]
                    .iter()
                    .filter_map(|message| serde_json::to_value(message).ok())
                    .collect(),
            );
            push_segment(
                &mut segments,
                SegmentKind::MessagePrefix,
                "message-prefix",
                cache.short_ttl_secs,
                &salt,
                &history_prefix,
                false,
                MIN_SEGMENT_CHARS,
            );
        }

        for message in &req.messages {
            if message_has_tool_result(message) {
                continue;
            }
            if let Ok(value) = serde_json::to_value(message) {
                push_segment(
                    &mut segments,
                    SegmentKind::MessageBlock,
                    "message-block",
                    cache.short_ttl_secs,
                    &salt,
                    &value,
                    true,
                    MIN_MESSAGE_BLOCK_CHARS,
                );
            }
        }
    }

    for msg in &req.messages {
        collect_tool_result_segments(msg, &mut |value| {
            push_segment(
                &mut segments,
                SegmentKind::ToolResult,
                "tool-result",
                cache.short_ttl_secs,
                &salt,
                value,
                true,
                MIN_SEGMENT_CHARS,
            );
        });
    }

    (segments, prompt_total_est)
}

fn push_segment(
    segments: &mut Vec<Segment>,
    kind: SegmentKind,
    name: &'static str,
    ttl_secs: i64,
    salt: &str,
    value: &serde_json::Value,
    should_store: bool,
    min_chars: usize,
) {
    let Ok(canonical) = serde_json::to_vec(value) else {
        return;
    };
    if canonical.len() < min_chars {
        return;
    }

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(&canonical);
    let digest = hasher.finalize();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest[..8]);

    segments.push(Segment {
        hash: u64::from_be_bytes(buf),
        kind,
        name,
        byte_len: canonical.len(),
        token_estimate: estimate_tokens_from_bytes(canonical.len()),
        ttl_secs,
        should_store,
    });
}

fn estimate_tokens_from_bytes(bytes: usize) -> u32 {
    ((bytes as f64) / 4.0).ceil().max(1.0) as u32
}

fn estimate_message_prefix_tokens(
    prefix_bytes: usize,
    full_message_bytes: usize,
    raw_input_tokens: u32,
) -> u32 {
    if prefix_bytes == 0 || full_message_bytes == 0 || raw_input_tokens == 0 {
        return estimate_tokens_from_bytes(prefix_bytes);
    }
    let ratio = (prefix_bytes as f64 / full_message_bytes as f64).clamp(0.0, 1.0);
    ((raw_input_tokens as f64) * ratio).floor().max(1.0) as u32
}

fn message_has_tool_result(message: &Message) -> bool {
    let mut found = false;
    collect_tool_result_segments(message, &mut |_| {
        found = true;
    });
    found
}

fn collect_tool_result_segments<'a>(
    message: &'a Message,
    visitor: &mut impl FnMut(&'a serde_json::Value),
) {
    if let serde_json::Value::Array(blocks) = &message.content {
        for block in blocks {
            let is_tool_result = block
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind == "tool_result");
            if is_tool_result {
                visitor(block);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_miss_then_record_then_hit() {
        let cache = CacheMeter::new(None);
        let hashes = [1u64, 2u64];
        let tokens = [10u32, 25u32];
        let r1 = cache.lookup(&hashes, &tokens);
        assert!(r1.iter().all(|s| !s.hit));

        cache.record(&hashes, &tokens, 300);
        let r2 = cache.lookup(&hashes, &tokens);
        assert!(r2.iter().all(|s| s.hit));
    }

    #[test]
    fn ttl_expiry_makes_entry_miss() {
        let cache = CacheMeter::new(None);
        cache.record(&[42], &[100], 60);
        // 手动让条目过期
        {
            let mut inner = cache.inner.lock();
            if let Some(e) = inner.entries.get_mut(&42) {
                e.expires_at = now_secs() - 1;
            }
        }
        let r = cache.lookup(&[42], &[100]);
        assert!(!r[0].hit);
    }

    #[test]
    fn evict_expired_removes_dead_entries() {
        let cache = CacheMeter::new(None);
        cache.record(&[1, 2], &[5, 5], 60);
        {
            let mut inner = cache.inner.lock();
            for (_, v) in inner.entries.iter_mut() {
                v.expires_at = now_secs() - 1;
            }
        }
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn parse_ttl_handles_known_values() {
        assert_eq!(parse_ttl(Some("1h")), 3600);
        assert_eq!(parse_ttl(Some("5m")), 300);
        assert_eq!(parse_ttl(None), 300);
        assert_eq!(parse_ttl(Some("garbage")), 300);
    }

    #[test]
    fn flush_and_reload_round_trip() {
        let tmp = std::env::temp_dir().join(format!("kiro-pc-{}.json", now_secs()));
        let cache = CacheMeter::new(Some(tmp.clone()));
        cache.record(&[7], &[42], 600);
        cache.flush_to_disk();

        let cache2 = CacheMeter::new(Some(tmp.clone()));
        let r = cache2.lookup(&[7], &[42]);
        assert!(r[0].hit);

        let _ = std::fs::remove_file(&tmp);
    }

    fn build_request_with_system_breakpoint() -> super::super::types::MessagesRequest {
        use super::super::types::{CacheControl, Message, MessagesRequest, SystemMessage};
        MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 32,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::Value::String("Hello".to_string()),
            }],
            stream: false,
            system: Some(vec![SystemMessage {
                text: "You are a helpful assistant. ".repeat(100),
                cache_control: Some(CacheControl {
                    cache_type: "ephemeral".to_string(),
                    ttl: None,
                }),
            }]),
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        }
    }

    #[test]
    fn compute_cache_usage_first_miss_then_hit() {
        let cache = CacheMeter::new(None);
        let req = build_request_with_system_breakpoint();

        // 第一次：所有段都 miss → 覆盖前缀全部算 creation（read == 0）。
        let u1 = compute_cache_usage(&cache, &req, 1);
        assert!(u1.cache_covered_est > 0, "first call should cover prefix");
        assert_eq!(u1.cache_read, 0, "first call has nothing cached to read");
        // 用真实 total 分摊：全部进 creation，input = total − covered。
        let total = u1.prompt_total_est; // 取 estimate total 作为「真实 total」便于断言
        let (in1, cc1, cr1) = u1.split_against_total(total);
        assert!(cc1 > 0, "first call creation>0, cc={}", cc1);
        assert_eq!(cr1, 0);
        assert_eq!(in1 + cc1 + cr1, total, "互斥口径必须自洽");

        // 第二次：相同请求 → 命中，覆盖前缀全部算 read（creation == 0）。
        let u2 = compute_cache_usage(&cache, &req, 1);
        assert!(u2.cache_read > 0, "second call should hit");
        let (in2, cc2, cr2) = u2.split_against_total(total);
        assert_eq!(cc2, 0, "second call creation should be 0, got {}", cc2);
        assert!(cr2 > 0, "second call read>0, cr={}", cr2);
        assert_eq!(in2 + cc2 + cr2, total, "互斥口径必须自洽");
        // 两次拆分的「缓存覆盖部分」一致：第一次的 creation == 第二次的 read。
        assert_eq!(cc1, cr2);
    }

    #[test]
    fn split_against_total_is_mutually_exclusive() {
        // input + creation + read 必须恒等于 total，且缓存覆盖比例正确分摊。
        let u = CacheUsage {
            cache_read: 30,
            cache_covered_est: 80, // creation 部分 = 50
            prompt_total_est: 100,
            ..Default::default()
        };
        // covered 占 prompt 的 80% → 真实 total=1000 时缓存覆盖 800。
        let (input, creation, read) = u.split_against_total(1000);
        assert_eq!(input + creation + read, 1000);
        assert_eq!(input, 200, "尾部 20% 是未缓存 input");
        // 覆盖部分 800 内按 read:creation = 30:50 拆分 → read=300, creation=500。
        assert_eq!(read, 300);
        assert_eq!(creation, 500);
    }

    #[test]
    fn split_against_total_no_cache_all_input() {
        let u = CacheUsage {
            cache_read: 0,
            cache_covered_est: 0,
            prompt_total_est: 100,
            ..Default::default()
        };
        assert_eq!(u.split_against_total(500), (500, 0, 0));
    }

    #[test]
    fn split_against_total_respects_max_savings_ratio() {
        let u = CacheUsage {
            cache_read: 30,
            cache_covered_est: 80,
            prompt_total_est: 100,
            max_savings_ratio: 0.5,
        };
        let (input, creation, read) = u.split_against_total(1000);
        assert_eq!(input + creation + read, 1000);
        assert_eq!(input, 500);
        assert_eq!(creation + read, 500);
        assert_eq!(read, 188);
        assert_eq!(creation, 312);
    }

    #[test]
    fn compute_cache_usage_single_message_no_prefix() {
        // 单条 user 消息、无 system/tools：没有可缓存的历史前缀（最后一条不切段）
        // → covered=0，total 全进 input。
        use super::super::types::{Message, MessagesRequest};
        let cache = CacheMeter::new(None);
        let req = MessagesRequest {
            model: "x".to_string(),
            max_tokens: 8,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::Value::String("Hello".to_string()),
            }],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        };
        let u = compute_cache_usage(&cache, &req, 1);
        assert_eq!(u.cache_covered_est, 0);
        assert_eq!(u.split_against_total(123), (123, 0, 0));
    }

    /// 构造一个普通工具，input_schema 的顶层 key 按给定顺序插入。
    /// 用于验证：无论插入顺序如何，工具片段 hash 都稳定（BTreeMap 保证）。
    fn build_tool_with_schema_order(insert_required_first: bool) -> super::super::types::Tool {
        use super::super::types::Tool;
        let mut schema = std::collections::BTreeMap::new();
        // 故意用不同的插入顺序，模拟上游 JSON 解析的不确定迭代序。
        if insert_required_first {
            schema.insert("required".to_string(), serde_json::json!([]));
            schema.insert("properties".to_string(), serde_json::json!({}));
            schema.insert("type".to_string(), serde_json::json!("object"));
        } else {
            schema.insert("type".to_string(), serde_json::json!("object"));
            schema.insert("properties".to_string(), serde_json::json!({}));
            schema.insert("required".to_string(), serde_json::json!([]));
        }
        Tool {
            tool_type: None,
            name: "my_tool".to_string(),
            description: "desc".to_string(),
            input_schema: schema,
            max_uses: None,
            cache_control: None,
        }
    }

    #[test]
    fn compute_cache_usage_tools_hit_regardless_of_schema_order() {
        use super::super::types::{CacheControl, Message, MessagesRequest};

        let make_req = |insert_required_first: bool| {
            let mut tool = build_tool_with_schema_order(insert_required_first);
            tool.cache_control = Some(CacheControl {
                cache_type: "ephemeral".to_string(),
                ttl: None,
            });
            MessagesRequest {
                model: "claude-sonnet-4-5-20250929".to_string(),
                max_tokens: 32,
                messages: vec![Message {
                    role: "user".to_string(),
                    content: serde_json::Value::String("Hello".to_string()),
                }],
                stream: false,
                system: None,
                tools: Some(vec![tool]),
                tool_choice: None,
                thinking: None,
                output_config: None,
                metadata: None,
            }
        };

        let cache = CacheMeter::new(None);
        // 第一次：用一种插入顺序，应写缓存（miss → read==0）。
        let u1 = compute_cache_usage(&cache, &make_req(false), 1);
        assert!(u1.cache_covered_est > 0, "first call should cover prefix");
        assert_eq!(u1.cache_read, 0);

        // 第二次：换一种插入顺序但逻辑等价，应命中缓存（read 等于第一次覆盖前缀）。
        let u2 = compute_cache_usage(&cache, &make_req(true), 1);
        assert!(u2.cache_read > 0, "schema 顺序不应影响 tools 片段命中");
    }

    /// 构造一条带 cache_control 的 user/assistant 文本消息。
    fn msg_with_cc(role: &str, text: &str, with_cc: bool) -> super::super::types::Message {
        use super::super::types::Message;
        let block = if with_cc {
            serde_json::json!({
                "type": "text",
                "text": text,
                "cache_control": {"type": "ephemeral"}
            })
        } else {
            serde_json::json!({"type": "text", "text": text})
        };
        Message {
            role: role.to_string(),
            content: serde_json::Value::Array(vec![block]),
        }
    }

    fn req_with_messages(
        messages: Vec<super::super::types::Message>,
    ) -> super::super::types::MessagesRequest {
        use super::super::types::MessagesRequest;
        MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 32,
            messages,
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        }
    }

    /// 模拟 Claude Code 真实工具调用序列：tool_use(assistant) / tool_result(user)
    /// 块每轮回传时带每次新生成的 id。验证前缀链对「含 id 漂移的工具块」仍能命中。
    #[test]
    fn tool_call_history_still_hits_despite_id_drift() {
        let body = "analyze the repository structure carefully ".repeat(15);
        // assistant 轮：一个 tool_use 块，input 是工具参数，id 每轮可能不同。
        let assistant_tool = |id: &str| {
            use super::super::types::Message;
            Message {
                role: "assistant".to_string(),
                content: serde_json::json!([
                    {"type": "text", "text": body},
                    {"type": "tool_use", "id": id, "name": "bash", "input": {"cmd": "ls"}}
                ]),
            }
        };
        // user 轮：tool_result 块，tool_use_id 对应上面的 id。
        let user_result = |id: &str| {
            use super::super::types::Message;
            Message {
                role: "user".to_string(),
                content: serde_json::json!([
                    {"type": "tool_result", "tool_use_id": id, "content": body}
                ]),
            }
        };
        let user_text = |t: &str| msg_with_cc("user", t, false);

        let cache = CacheMeter::new(None);
        // Turn 1: user → assistant(tool_use #a) → user(tool_result #a) → assistant(text) → user(新问题)
        let turn1 = req_with_messages(vec![
            user_text(&body),
            assistant_tool("toolu_aaa"),
            user_result("toolu_aaa"),
            msg_with_cc("assistant", &body, false),
            user_text("next question one"),
        ]);
        let u1 = compute_cache_usage(&cache, &turn1, 1);
        assert!(u1.cache_covered_est > 0);
        assert_eq!(u1.cache_read, 0, "turn1 无历史可命中");

        // Turn 2: 追加 assistant(text) + user(新问题)。前 5 条历史逐字节不变。
        let turn2 = req_with_messages(vec![
            user_text(&body),
            assistant_tool("toolu_aaa"),
            user_result("toolu_aaa"),
            msg_with_cc("assistant", &body, false),
            user_text("next question one"),
            msg_with_cc("assistant", &body, false),
            user_text("next question two"),
        ]);
        let u2 = compute_cache_usage(&cache, &turn2, 1);
        assert!(
            u2.cache_read > 0,
            "turn2 应命中 turn1 的历史前缀（即便工具块带 id）"
        );
        assert!(u2.cache_read > 0, "命中的历史片段应产生 cache_read");
    }

    #[test]
    fn multi_turn_prefix_chain_produces_read_hit() {
        // 前缀链模型：turn4 在 turn3 基础上追加 a/u 一对，历史前缀逐字节不变，
        // 所以 turn4 应命中 turn3 写入的最深历史前缀段（cache_read > 0）。
        let cache = CacheMeter::new(None);
        let body = "the quick brown fox jumps over the lazy dog ".repeat(20);

        // 第 3 轮：u,a,u,a,u（5 条）。切段：除最后一条外，每条 message 一个前缀段
        // → idx 0,1,2,3 共 4 个段（无 system/tools）。
        let turn3 = req_with_messages(vec![
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, true),
        ]);
        let u3 = compute_cache_usage(&cache, &turn3, 1);
        assert!(u3.cache_covered_est > 0, "turn3 should create cache");
        assert_eq!(u3.cache_read, 0, "turn3 has no prior cache to read");

        // 第 4 轮：追加 a3,u4（7 条）。历史 idx 0..=5 切段，最后一条 idx6 不切。
        // turn3 的最深段在 idx3（其前缀=u,a,u,a），turn4 的 idx3 段前缀逐字节相同
        // → 命中。turn4 还新增 idx4,5 两个更深的历史前缀段。
        let turn4 = req_with_messages(vec![
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, true),
        ]);
        let u4 = compute_cache_usage(&cache, &turn4, 1);
        assert!(u4.cache_read > 0, "turn4 should hit a prior-turn prefix");
        assert!(
            u4.cache_covered_est >= u4.cache_read,
            "covered 至少应包含 read 部分"
        );
    }

    #[test]
    fn prefix_chain_works_without_any_cache_control() {
        // 新模型不依赖 cache_control：只要有跨轮稳定的历史前缀就能命中。
        // 这复现 Anthropic 自动前缀缓存语义，与旧"必须有 cache_control"策略不同。
        let cache = CacheMeter::new(None);
        let body = "lorem ipsum dolor sit amet ".repeat(20);
        let turn1 = req_with_messages(vec![
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, false),
        ]);
        let u1 = compute_cache_usage(&cache, &turn1, 1);
        assert!(u1.cache_covered_est > 0, "应为历史前缀创建缓存段");
        assert_eq!(u1.cache_read, 0);

        let turn2 = req_with_messages(vec![
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, false),
            msg_with_cc("assistant", &body, false),
            msg_with_cc("user", &body, false),
        ]);
        let u2 = compute_cache_usage(&cache, &turn2, 1);
        assert!(u2.cache_read > 0, "无 cache_control 也应跨轮命中历史前缀");
    }

    /// 复现实测根因：system[0] 是每轮变化的动态头（无 cache_control），
    /// 其后是带 cache_control 的稳定大块。跳过动态头后，稳定前缀应跨轮命中。
    #[test]
    fn dynamic_system_header_does_not_break_cache_hit() {
        use super::super::types::{CacheControl, Message, MessagesRequest, SystemMessage};
        let stable_sys = "You are a coding assistant. ".repeat(200);
        let body = "implement the feature step by step ".repeat(15);

        let make_req = |dyn_header: &str, msgs: Vec<Message>| MessagesRequest {
            model: "claude-opus-4-8".to_string(),
            max_tokens: 64,
            messages: msgs,
            stream: false,
            system: Some(vec![
                // sys[0]：每轮变化的动态头（如当前时间），无 cache_control。
                SystemMessage {
                    text: dyn_header.to_string(),
                    cache_control: None,
                },
                // sys[1]：稳定大块，带 cache_control。
                SystemMessage {
                    text: stable_sys.clone(),
                    cache_control: Some(CacheControl {
                        cache_type: "ephemeral".to_string(),
                        ttl: None,
                    }),
                },
            ]),
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        };

        let cache = CacheMeter::new(None);
        // Turn 1：动态头 = "now=1001"，3 条消息。
        let u1 = compute_cache_usage(
            &cache,
            &make_req(
                "now=1001",
                vec![
                    msg_with_cc("user", &body, false),
                    msg_with_cc("assistant", &body, false),
                    msg_with_cc("user", &body, false),
                ],
            ),
            1,
        );
        assert!(u1.cache_covered_est > 0);
        assert_eq!(u1.cache_read, 0, "turn1 无历史可命中");

        // Turn 2：动态头变成 "now=2002"（不同！），追加一对 a/u。
        // 跳过动态头后，sys[1]+历史前缀逐字节不变 → 必须命中。
        let u2 = compute_cache_usage(
            &cache,
            &make_req(
                "now=2002",
                vec![
                    msg_with_cc("user", &body, false),
                    msg_with_cc("assistant", &body, false),
                    msg_with_cc("user", &body, false),
                    msg_with_cc("assistant", &body, false),
                    msg_with_cc("user", &body, false),
                ],
            ),
            1,
        );
        assert!(
            u2.cache_read > 0,
            "动态 system 头变化不应破坏稳定前缀命中（实测根因）"
        );
    }

    /// 会话隔离：相同前缀内容，不同客户端 Key（key_id）之间不应互相命中。
    #[test]
    fn different_key_id_does_not_cross_hit() {
        let cache = CacheMeter::new(None);
        let body = "shared system prompt and history ".repeat(20);
        let msgs = || {
            vec![
                msg_with_cc("user", &body, false),
                msg_with_cc("assistant", &body, false),
                msg_with_cc("user", &body, false),
            ]
        };
        // Key=1 建立缓存。
        let a = compute_cache_usage(&cache, &req_with_messages(msgs()), 1);
        assert!(a.cache_covered_est > 0);
        assert_eq!(a.cache_read, 0);
        // Key=2 相同内容，但隔离种子不同 → 不命中（视为新建）。
        let b = compute_cache_usage(&cache, &req_with_messages(msgs()), 2);
        assert_eq!(b.cache_read, 0, "不同 key_id 不应命中彼此的前缀");
        // Key=1 再来一次相同内容 → 命中自己上次写入的。
        let c = compute_cache_usage(&cache, &req_with_messages(msgs()), 1);
        assert!(c.cache_read > 0, "同一 key_id 应命中自己的前缀");
    }

    /// metadata.user_id 里 session 变化不应打碎同一 client key 的技术缓存命中。
    #[test]
    fn metadata_session_does_not_fragment_cache() {
        use super::super::types::{Message, MessagesRequest, Metadata};
        let body = "conversation prefix that stays stable ".repeat(20);
        let make = |session: &str| MessagesRequest {
            model: "claude-opus-4-8".to_string(),
            max_tokens: 64,
            messages: vec![
                Message {
                    role: "user".into(),
                    content: serde_json::json!([{"type":"text","text":body}]),
                },
                Message {
                    role: "assistant".into(),
                    content: serde_json::json!([{"type":"text","text":body}]),
                },
                Message {
                    role: "user".into(),
                    content: serde_json::json!([{"type":"text","text":body}]),
                },
            ],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: Some(Metadata {
                user_id: Some(format!("user_abc_account__session_{session}")),
            }),
        };
        let cache = CacheMeter::new(None);
        let s1a = compute_cache_usage(&cache, &make("aaa"), 0);
        assert_eq!(s1a.cache_read, 0);
        let s2 = compute_cache_usage(&cache, &make("bbb"), 0);
        assert!(
            s2.cache_read > 0,
            "session 变化不应阻止同一 key 的稳定前缀命中"
        );
    }

    /// 含图片的历史段：covered 应计入图片的 Anthropic 口径 token，且跨轮稳定命中。
    #[test]
    fn image_block_contributes_tokens_and_hits() {
        use super::super::types::{Message, MessagesRequest};
        // 用 image_resize 的同款 PNG 生成器造一张 750×750（≈750 token）的真图。
        let png = make_test_png(750, 750);
        let make = |trailing: &str| MessagesRequest {
            model: "m".to_string(),
            max_tokens: 8,
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type":"image","source":{"type":"base64","media_type":"image/png","data": png}},
                        {"type":"text","text":"describe"}
                    ]),
                },
                Message {
                    role: "assistant".to_string(),
                    content: serde_json::json!("a pixel"),
                },
                Message {
                    role: "user".to_string(),
                    content: serde_json::json!(trailing),
                },
            ],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        };

        let cache = CacheMeter::new(None);
        // Turn 1：含图的 user 是历史第一段，应写入稳定片段。
        let u1 = compute_cache_usage(&cache, &make("q1"), 1);
        assert!(u1.cache_covered_est > 0);
        assert_eq!(u1.cache_read, 0);

        // Turn 2：追加一轮，含图历史逐字节不变 → 命中。
        let u2 = compute_cache_usage(&cache, &make("q2"), 1);
        assert!(u2.cache_read > 0, "含图历史应跨轮命中");
    }

    /// 测试用 PNG 生成器（与 image_resize 测试同款，渐变填充更接近真实压缩比）。
    fn make_test_png(w: u32, h: u32) -> String {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        use image::{ImageFormat, Rgb, RgbImage};
        use std::io::Cursor;
        let mut img = RgbImage::new(w, h);
        for y in 0..h {
            for x in 0..w {
                img.put_pixel(x, y, Rgb([(x % 256) as u8, (y % 256) as u8, 128]));
            }
        }
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .unwrap();
        B64.encode(&buf)
    }
}
