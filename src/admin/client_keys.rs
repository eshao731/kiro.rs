//! 客户端 API Key 管理
//!
//! 中转站对外分发的"客户端 Key"层。程序生成的 Key 以 `sk-` 开头；鉴权时不校验
//! 前缀，只按完整 Key 精确匹配，并按 Key 维度记录调用次数与累计 Token。
//!
//! 与上游 Kiro 凭据（`KiroCredentials`，`ksk_*`）相互独立：
//! - 上游凭据池：服务对接 Kiro 的"出口"
//! - 客户端 Key：中转站对外的"入口"
//!
//! 持久化为 `client_api_keys.json`（与 `credentials.json` 同目录）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// 单条客户端 Key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientKey {
    pub id: u64,
    /// 明文 Key（中转站场景，校验需原值，不做 hash）
    pub key: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub total_calls: u64,
    #[serde(default)]
    pub total_input_tokens: u64,
    #[serde(default)]
    pub total_output_tokens: u64,
    #[serde(default)]
    pub total_cache_creation_tokens: u64,
    #[serde(default)]
    pub total_cache_read_tokens: u64,
    /// 累计 credit 计费量（meteringEvent.usage 累加）
    #[serde(default)]
    pub total_credits: f64,
    /// 绑定的账号分组名（可选）
    ///
    /// 设置后，用该 Key 发起的请求只会调度到 groups 包含此分组名的上游账号（严格隔离）。
    /// None 表示不绑定分组，可使用全部账号。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// 系统 Key（由 config.json apiKey bootstrap 生成，不可删除、可轮换）。
    /// 老数据无此字段，默认 false。
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_system: bool,
}

/// 客户端 Key 管理器
///
/// 内部双索引：
/// - `by_key: HashMap<String, u64>` —— 用于 Key 判重和索引维护
/// - `entries: HashMap<u64, ClientKey>` —— 用于按 id 读写明细和鉴权扫描
///
/// 校验比对仍使用 `subtle::ConstantTimeEq` 防止时序攻击。
pub struct ClientKeyManager {
    inner: RwLock<Inner>,
    path: Option<PathBuf>,
}

struct Inner {
    entries: HashMap<u64, ClientKey>,
    by_key: HashMap<String, u64>,
    next_id: u64,
}

impl ClientKeyManager {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                entries: HashMap::new(),
                by_key: HashMap::new(),
                next_id: 1,
            }),
            path: None,
        }
    }

    /// 从文件加载（不存在时返回空管理器）
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries: Vec<ClientKey> = if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            if content.trim().is_empty() {
                Vec::new()
            } else {
                serde_json::from_str(&content)?
            }
        } else {
            Vec::new()
        };

        let mut by_key = HashMap::with_capacity(entries.len());
        let mut by_id = HashMap::with_capacity(entries.len());
        let mut max_id = 0u64;
        for ck in entries {
            max_id = max_id.max(ck.id);
            by_key.insert(ck.key.clone(), ck.id);
            by_id.insert(ck.id, ck);
        }

        Ok(Self {
            inner: RwLock::new(Inner {
                entries: by_id,
                by_key,
                next_id: max_id + 1,
            }),
            path: Some(path),
        })
    }

    fn save_locked(&self, inner: &Inner) {
        let path = match &self.path {
            Some(p) => p,
            None => return,
        };
        let mut list: Vec<&ClientKey> = inner.entries.values().collect();
        list.sort_by_key(|k| k.id);
        match serde_json::to_string_pretty(&list) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::warn!("写入客户端 Key 文件失败: {}", e);
                }
            }
            Err(e) => tracing::warn!("序列化客户端 Key 失败: {}", e),
        }
    }

    /// 列表（按 id 升序）
    pub fn list(&self) -> Vec<ClientKey> {
        let inner = self.inner.read();
        let mut list: Vec<ClientKey> = inner.entries.values().cloned().collect();
        list.sort_by_key(|k| k.id);
        list
    }

    /// 创建新 Key（生成明文随机串），返回新建条目
    pub fn create(
        &self,
        name: String,
        description: Option<String>,
        group: Option<String>,
    ) -> ClientKey {
        self.create_with_key(name, description, group, generate_client_key())
    }

    /// 用指定明文创建 Key。
    /// 若该明文已存在则跳过，返回已存在的条目。
    pub fn create_with_key(
        &self,
        name: String,
        description: Option<String>,
        group: Option<String>,
        plaintext: String,
    ) -> ClientKey {
        let mut inner = self.inner.write();
        // 防止创建重复明文
        if let Some(&id) = inner.by_key.get(&plaintext) {
            return inner
                .entries
                .get(&id)
                .cloned()
                .expect("by_key 与 entries 应一致");
        }
        let id = inner.next_id;
        inner.next_id += 1;
        let entry = ClientKey {
            id,
            key: plaintext.clone(),
            name,
            description,
            disabled: false,
            created_at: Utc::now().to_rfc3339(),
            last_used_at: None,
            total_calls: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cache_creation_tokens: 0,
            total_cache_read_tokens: 0,
            total_credits: 0.0,
            group: group.filter(|g| !g.trim().is_empty()),
            is_system: false,
        };
        inner.by_key.insert(plaintext, id);
        inner.entries.insert(id, entry.clone());
        self.save_locked(&inner);
        entry
    }

    /// 将 `config.json` 的 `apiKey` 同步为唯一的系统 Key（每次启动调用）。
    ///
    /// `config.apiKey` 是权威值，固定占用 `id=0`。已有 `id=0` 且配置值变化时替换
    /// 明文、重新启用，并保留名称、描述、分组和统计；不存在时才使用传入的默认元数据
    /// 创建。与当前或上一个系统 Key 明文冲突的非系统条目会被移除，确保同一明文只
    /// 对应一个 id，且配置变更后旧系统 Key 立即失效。
    pub fn sync_system_key(&self, name: String, description: Option<String>, plaintext: String) {
        let mut inner = self.inner.write();
        let previous_key = inner.entries.get(&0).map(|entry| entry.key.clone());
        let mut changed = false;

        if let Some(entry) = inner.entries.get_mut(&0) {
            if entry.key != plaintext {
                entry.key = plaintext.clone();
                entry.disabled = false;
                changed = true;
            }
            if !entry.is_system {
                entry.is_system = true;
                changed = true;
            }
        } else {
            inner.entries.insert(
                0,
                ClientKey {
                    id: 0,
                    key: plaintext.clone(),
                    name,
                    description,
                    disabled: false,
                    created_at: Utc::now().to_rfc3339(),
                    last_used_at: None,
                    total_calls: 0,
                    total_input_tokens: 0,
                    total_output_tokens: 0,
                    total_cache_creation_tokens: 0,
                    total_cache_read_tokens: 0,
                    total_credits: 0.0,
                    group: None,
                    is_system: true,
                },
            );
            changed = true;
        }

        let entries_before = inner.entries.len();
        inner.entries.retain(|id, entry| {
            *id == 0
                || (entry.key != plaintext
                    && previous_key
                        .as_deref()
                        .map(|old_key| entry.key != old_key)
                        .unwrap_or(true))
        });
        changed |= inner.entries.len() != entries_before;

        for (id, entry) in inner.entries.iter_mut() {
            if *id != 0 && entry.is_system {
                entry.is_system = false;
                changed = true;
            }
        }

        let by_key: HashMap<String, u64> = inner
            .entries
            .iter()
            .map(|(id, entry)| (entry.key.clone(), *id))
            .collect();
        changed |= inner.by_key != by_key;
        inner.by_key = by_key;

        if changed {
            self.save_locked(&inner);
        }
    }

    pub fn delete(&self, id: u64) -> bool {
        let mut inner = self.inner.write();
        // 系统 Key 拒绝删除
        if inner.entries.get(&id).map(|e| e.is_system).unwrap_or(false) {
            return false;
        }
        let removed = match inner.entries.remove(&id) {
            Some(e) => {
                inner.by_key.remove(&e.key);
                true
            }
            None => false,
        };
        if removed {
            self.save_locked(&inner);
        }
        removed
    }

    pub fn set_disabled(&self, id: u64, disabled: bool) -> bool {
        let mut inner = self.inner.write();
        let updated = match inner.entries.get_mut(&id) {
            Some(e) => {
                e.disabled = disabled;
                true
            }
            None => false,
        };
        if updated {
            self.save_locked(&inner);
        }
        updated
    }

    pub fn update_meta(
        &self,
        id: u64,
        name: Option<String>,
        description: Option<Option<String>>,
        group: Option<Option<String>>,
    ) -> bool {
        let mut inner = self.inner.write();
        let updated = match inner.entries.get_mut(&id) {
            Some(e) => {
                if let Some(n) = name {
                    e.name = n;
                }
                if let Some(d) = description {
                    e.description = d;
                }
                if let Some(g) = group {
                    e.group = g.filter(|s| !s.trim().is_empty());
                }
                true
            }
            None => false,
        };
        if updated {
            self.save_locked(&inner);
        }
        updated
    }

    /// 返回指定 Key 绑定的分组名（None 表示未绑定或 Key 不存在）
    pub fn group_of(&self, id: u64) -> Option<String> {
        self.inner
            .read()
            .entries
            .get(&id)
            .and_then(|e| e.group.clone())
    }

    /// 列出所有当前被引用的分组名（仅去重，不带计数）。
    pub fn used_group_names(&self) -> Vec<String> {
        let inner = self.inner.read();
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in inner.entries.values() {
            if let Some(g) = &e.group {
                set.insert(g.clone());
            }
        }
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        list
    }

    /// 统计指定分组被多少把 Key 绑定（用于分组管理页 / 删除前提示）。
    pub fn count_with_group(&self, group: &str) -> usize {
        self.inner
            .read()
            .entries
            .values()
            .filter(|e| e.group.as_deref() == Some(group))
            .count()
    }

    /// 指定 id 的 Key 是否为系统 Key（不存在也返回 false）。
    pub fn is_system(&self, id: u64) -> bool {
        self.inner
            .read()
            .entries
            .get(&id)
            .map(|e| e.is_system)
            .unwrap_or(false)
    }

    /// 把所有引用 `old` 的 Key 的 group 字段改为 `new`（分组改名级联用）。
    /// 返回受影响的 Key 数。
    pub fn rename_group(&self, old: &str, new: &str) -> usize {
        let mut inner = self.inner.write();
        let mut affected = 0usize;
        for entry in inner.entries.values_mut() {
            if entry.group.as_deref() == Some(old) {
                entry.group = Some(new.to_string());
                affected += 1;
            }
        }
        if affected > 0 {
            self.save_locked(&inner);
        }
        affected
    }

    /// 把所有引用 `name` 的 Key 的 group 字段清空（强删分组级联用）。
    /// 返回受影响的 Key 数。
    pub fn clear_group(&self, name: &str) -> usize {
        let mut inner = self.inner.write();
        let mut affected = 0usize;
        for entry in inner.entries.values_mut() {
            if entry.group.as_deref() == Some(name) {
                entry.group = None;
                affected += 1;
            }
        }
        if affected > 0 {
            self.save_locked(&inner);
        }
        affected
    }

    /// 轮换 Key 值：旧 Key 立即失效，生成新明文，保留 id/name/description/group/统计/disabled/is_system。
    /// 用于「明文遗失」「下游怀疑泄漏」场景，比删后重建更安全（不会丢统计与分组绑定）。
    /// 命中且替换成功返回新条目（含新明文）；id 不存在返回 None。
    /// 注意：系统 Key 轮换后调用方需把新明文同步写回 config.json apiKey，避免下次启动恢复配置中的旧值。
    pub fn rotate(&self, id: u64) -> Option<ClientKey> {
        let new_key = generate_client_key();
        let mut inner = self.inner.write();
        // 取出旧条目并从 by_key 索引摘除
        let old_key = inner.entries.get(&id).map(|e| e.key.clone())?;
        inner.by_key.remove(&old_key);
        // 写入新明文 + 索引（is_system 等其余字段保留不变）
        let entry = inner.entries.get_mut(&id)?;
        entry.key = new_key.clone();
        let snapshot = entry.clone();
        inner.by_key.insert(new_key, id);
        self.save_locked(&inner);
        Some(snapshot)
    }

    /// 重置计数（保留 Key 与名称）
    pub fn reset_stats(&self, id: u64) -> bool {
        let mut inner = self.inner.write();
        let updated = match inner.entries.get_mut(&id) {
            Some(e) => {
                e.total_calls = 0;
                e.total_input_tokens = 0;
                e.total_output_tokens = 0;
                e.total_cache_creation_tokens = 0;
                e.total_cache_read_tokens = 0;
                e.total_credits = 0.0;
                true
            }
            None => false,
        };
        if updated {
            self.save_locked(&inner);
        }
        updated
    }

    /// 校验 Key，命中且未禁用则返回 id；同时更新 `last_used_at`/`total_calls`
    ///
    /// 用 `ConstantTimeEq` 对所有 active Key 做常量时间比对，防止时序攻击；
    /// Key 的前缀和格式不参与鉴权，允许 `config.apiKey` 使用自定义值。
    pub fn verify_and_touch(&self, presented: &str) -> Option<u64> {
        let mut inner = self.inner.write();
        // 扫描所有 entry 做常量时间比较，避免 HashMap 短路泄露
        let mut hit_id: Option<u64> = None;
        for (id, ck) in inner.entries.iter() {
            if ck.disabled {
                continue;
            }
            if ck.key.as_bytes().ct_eq(presented.as_bytes()).into() {
                hit_id = Some(*id);
                // 不 break，继续完整扫描以保持常量时间
            }
        }
        let id = hit_id?;
        if let Some(entry) = inner.entries.get_mut(&id) {
            entry.total_calls += 1;
            entry.last_used_at = Some(Utc::now().to_rfc3339());
        }
        // 不在每次请求都落盘（高频写入），由 record_usage / 定期 flush 持久化
        Some(id)
    }

    /// 在请求结束时累计 Token 用量并落盘
    pub fn record_usage(
        &self,
        id: u64,
        input_tokens: u64,
        output_tokens: u64,
        cache_creation_tokens: u64,
        cache_read_tokens: u64,
        credits: f64,
    ) {
        let mut inner = self.inner.write();
        if let Some(entry) = inner.entries.get_mut(&id) {
            entry.total_input_tokens += input_tokens;
            entry.total_output_tokens += output_tokens;
            entry.total_cache_creation_tokens += cache_creation_tokens;
            entry.total_cache_read_tokens += cache_read_tokens;
            if credits.is_finite() && credits > 0.0 {
                entry.total_credits += credits;
            }
            entry.last_used_at = Some(Utc::now().to_rfc3339());
        }
        self.save_locked(&inner);
    }

    /// 获取统计后的 active Key 数（未禁用）
    pub fn active_count(&self) -> usize {
        self.inner
            .read()
            .entries
            .values()
            .filter(|e| !e.disabled)
            .count()
    }
}

impl Default for ClientKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// serde 辅助：bool 为 false 时跳过序列化
fn is_false(b: &bool) -> bool {
    !b
}

/// 生成 `sk-` 前缀 + 32 位 base62 随机字符串
pub fn generate_client_key() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let body: String = (0..32)
        .map(|_| {
            let idx = fastrand::usize(..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("sk-{}", body)
}

/// 脱敏展示：保留前 8 个字符（含前缀）和后 4 个字符
pub fn mask_client_key(key: &str) -> String {
    let char_count = key.chars().count();
    if char_count <= 12 {
        return key.to_string();
    }
    let start: String = key.chars().take(8).collect();
    let end: String = key.chars().skip(char_count - 4).collect();
    format!("{start}...{end}")
}

/// 默认管理器路径（相对凭据目录）
pub fn default_path_in(dir: &Path) -> PathBuf {
    dir.join("client_api_keys.json")
}

/// Arc 包装，便于注入 axum State
pub type SharedClientKeyManager = Arc<ClientKeyManager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify() {
        let mgr = ClientKeyManager::new();
        let entry = mgr.create("test".to_string(), None, None);
        assert!(entry.key.starts_with("sk-"));
        assert_eq!(mgr.verify_and_touch(&entry.key), Some(entry.id));
        // 未登记的 Key 拒绝
        assert_eq!(mgr.verify_and_touch("nope"), None);
    }

    #[test]
    fn system_key_can_use_legacy_sk_prefix() {
        let mgr = ClientKeyManager::new();
        mgr.sync_system_key("默认密钥".into(), None, "sk-kiro-abc".into());
        assert_eq!(mgr.verify_and_touch("sk-kiro-abc"), Some(0));
    }

    #[test]
    fn disabled_key_rejected() {
        let mgr = ClientKeyManager::new();
        let entry = mgr.create("test".to_string(), None, None);
        mgr.set_disabled(entry.id, true);
        assert_eq!(mgr.verify_and_touch(&entry.key), None);
        mgr.set_disabled(entry.id, false);
        assert_eq!(mgr.verify_and_touch(&entry.key), Some(entry.id));
    }

    #[test]
    fn record_usage_accumulates() {
        let mgr = ClientKeyManager::new();
        let entry = mgr.create("test".to_string(), None, None);
        mgr.record_usage(entry.id, 100, 50, 0, 0, 0.0);
        mgr.record_usage(entry.id, 200, 30, 5, 10, 1.5);
        let list = mgr.list();
        let e = list.iter().find(|x| x.id == entry.id).unwrap();
        assert_eq!(e.total_input_tokens, 300);
        assert_eq!(e.total_output_tokens, 80);
        assert_eq!(e.total_cache_creation_tokens, 5);
        assert_eq!(e.total_cache_read_tokens, 10);
    }

    #[test]
    fn mask_format() {
        assert_eq!(mask_client_key("sk-abcdefghijklmnop"), "sk-abcde...mnop");
        assert_eq!(mask_client_key("short"), "short");
        assert_eq!(mask_client_key("密钥🔐测试abcdefgh"), "密钥🔐测试abc...efgh");
    }

    #[test]
    fn rotate_replaces_key_but_keeps_metadata_and_stats() {
        let mgr = ClientKeyManager::new();
        let entry = mgr.create("kb".to_string(), Some("desc".into()), Some("groupA".into()));
        // 累计一些统计
        mgr.record_usage(entry.id, 100, 50, 5, 10, 1.5);
        let old_key = entry.key.clone();
        let rotated = mgr.rotate(entry.id).expect("rotate should succeed");
        // 新 Key 与旧 Key 不同，且使用统一生成前缀
        assert_ne!(rotated.key, old_key);
        assert!(rotated.key.starts_with("sk-"));
        // 元数据保留
        assert_eq!(rotated.id, entry.id);
        assert_eq!(rotated.name, "kb");
        assert_eq!(rotated.description.as_deref(), Some("desc"));
        assert_eq!(rotated.group.as_deref(), Some("groupA"));
        // 统计保留
        assert_eq!(rotated.total_input_tokens, 100);
        assert_eq!(rotated.total_output_tokens, 50);
        // 旧 Key 立即失效
        assert_eq!(mgr.verify_and_touch(&old_key), None);
        // 新 Key 命中
        assert_eq!(mgr.verify_and_touch(&rotated.key), Some(entry.id));
    }

    #[test]
    fn rotate_unknown_id_returns_none() {
        let mgr = ClientKeyManager::new();
        assert!(mgr.rotate(999).is_none());
    }

    #[test]
    fn sync_system_key_uses_id_zero() {
        let mgr = ClientKeyManager::new();
        mgr.sync_system_key("默认密钥".into(), None, "custom-api-key".into());
        assert!(mgr.is_system(0));
        assert_eq!(mgr.list().first().map(|k| k.id), Some(0));
        assert_eq!(mgr.verify_and_touch("custom-api-key"), Some(0));
        mgr.sync_system_key("默认密钥".into(), None, "custom-api-key".into());
        assert_eq!(mgr.list().iter().filter(|k| k.is_system).count(), 1);
    }

    #[test]
    fn sync_system_key_replaces_config_value_and_revokes_old_key() {
        let mgr = ClientKeyManager::new();
        mgr.sync_system_key("默认密钥".into(), Some("初始描述".into()), "custom-a".into());
        mgr.update_meta(
            0,
            Some("保留名称".into()),
            Some(Some("保留描述".into())),
            Some(Some("group-a".into())),
        );
        mgr.record_usage(0, 100, 50, 5, 10, 1.5);
        assert_eq!(mgr.verify_and_touch("custom-a"), Some(0));
        mgr.set_disabled(0, true);

        let conflicting = mgr.create_with_key(
            "冲突密钥".into(),
            None,
            None,
            "custom-b".into(),
        );
        assert_ne!(conflicting.id, 0);

        mgr.sync_system_key("默认密钥".into(), None, "custom-b".into());

        assert_eq!(mgr.verify_and_touch("custom-a"), None);
        assert_eq!(mgr.verify_and_touch("custom-b"), Some(0));
        let entries = mgr.list();
        assert_eq!(entries.len(), 1);
        let system = &entries[0];
        assert_eq!(system.id, 0);
        assert!(system.is_system);
        assert_eq!(system.name, "保留名称");
        assert_eq!(system.description.as_deref(), Some("保留描述"));
        assert_eq!(system.group.as_deref(), Some("group-a"));
        assert!(!system.disabled);
        assert_eq!(system.total_input_tokens, 100);
        assert_eq!(system.total_output_tokens, 50);
    }

    #[test]
    fn sync_system_key_migrates_misplaced_key_to_id_zero() {
        let mgr = ClientKeyManager::new();
        mgr.create_with_key("默认密钥".into(), None, None, "custom-api-key".into());
        assert_eq!(mgr.list().first().map(|key| key.id), Some(1));
        mgr.sync_system_key("默认密钥".into(), None, "custom-api-key".into());
        assert_eq!(mgr.verify_and_touch("custom-api-key"), Some(0));
        assert_eq!(mgr.list().len(), 1);
        assert!(mgr.is_system(0));
    }

    #[test]
    fn system_key_cannot_be_deleted() {
        let mgr = ClientKeyManager::new();
        mgr.sync_system_key("默认密钥".into(), None, "custom-api-key".into());
        assert!(!mgr.delete(0), "系统密钥 id=0 不可删除");
        assert!(mgr.is_system(0));
    }
}
