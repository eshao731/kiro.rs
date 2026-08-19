//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多凭据故障转移和重试
//! 支持按凭据级 endpoint 切换不同 Kiro API 端点

use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::admin::trace_db::{TraceAttempt, TraceSink, outcome, truncate_snippet};
use crate::http_client::{ProxyConfig, build_api_client};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::error::UpstreamRateLimitError;
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::{MultiTokenManager, RateLimitSoftThrottleError};
use crate::model::config::TlsBackend;
use parking_lot::Mutex;

/// 每个凭据的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
///
/// 注：上游 429 多为账号级速率配额（SERVICE_REQUEST_RATE_EXCEEDED），高峰期
/// 多账号同时触顶时，过多重试会在账号间连环撞墙、放大限流。故上限取较小值，
/// 配合 429 专用长退避（见 retry_delay_throttle），被限时尽早返回而非耗尽配额。
const MAX_TOTAL_RETRIES: usize = 4;

/// HTTP Client 缓存容量上限（不含常驻的全局代理 client）。
/// 代理池条目较多时，避免每个不同代理都常驻一个 reqwest::Client 导致内存无界增长。
const CLIENT_CACHE_CAP: usize = 64;

/// 带容量上限的 HTTP Client 缓存。
///
/// - key 为 effective proxy 配置（None = 直连/全局回退）
/// - 受保护 key（全局代理对应的 effective 配置）永不被淘汰
/// - 超出容量时按插入顺序淘汰最旧的「非受保护」条目
struct ClientCache {
    map: HashMap<Option<ProxyConfig>, Client>,
    /// 插入顺序（仅记录可淘汰的非受保护 key）
    order: std::collections::VecDeque<Option<ProxyConfig>>,
    /// 受保护、不参与淘汰的 key（全局代理）
    protected: Option<ProxyConfig>,
    cap: usize,
}

impl ClientCache {
    fn new(protected: Option<ProxyConfig>, initial: Client, cap: usize) -> Self {
        let mut map = HashMap::new();
        map.insert(protected.clone(), initial);
        Self {
            map,
            order: std::collections::VecDeque::new(),
            protected,
            cap,
        }
    }

    fn get(&self, key: &Option<ProxyConfig>) -> Option<Client> {
        self.map.get(key).cloned()
    }

    /// 插入新条目，必要时淘汰最旧的非受保护条目
    fn insert(&mut self, key: Option<ProxyConfig>, client: Client) {
        if key == self.protected || self.map.contains_key(&key) {
            self.map.insert(key, client);
            return;
        }
        while self.order.len() >= self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, client);
    }
}

/// API 调用结果，附带本次实际命中的上游凭据 ID（用于用量统计）
pub struct KiroCallResult {
    pub response: reqwest::Response,
    pub credential_id: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("凭据所有上游端点均在冷却，请 {retry_after_secs} 秒后重试")]
struct AllEndpointsCoolingError {
    retry_after_secs: u64,
}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多凭据故障转移和重试机制
/// 按凭据 `endpoint` 字段选择 [`KiroEndpoint`] 实现
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于凭据无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// Client 缓存：key = effective proxy config, value = reqwest::Client
    /// 不同代理配置的凭据使用不同的 Client，共享相同代理的凭据复用 Client。
    /// 带容量上限淘汰（全局代理 client 常驻），避免代理数量增长导致内存无界增长。
    client_cache: Mutex<ClientCache>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 端点实现注册表（key: endpoint 名称）
    endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
    /// 默认端点名称（凭据未指定 endpoint 时使用）
    default_endpoint: String,
    /// 凭据 × 端点的临时冷却。
    ///
    /// 端点 429 后即使备用端点成功，也必须保留主端点冷却；否则下一次请求会再次
    /// 先撞同一个已限流端点，持续放大上游风控风险。
    endpoint_cooldowns: Mutex<HashMap<(u64, String), Instant>>,
    /// 已尝试过 profileArn 解析的凭据 ID（进程内）。
    ///
    /// 避免对「无 Enterprise profile」的账号（如纯 BuilderID）在每次请求都重复调用
    /// `ListAvailableProfiles`。命中真实 ARN 的账号会把 ARN 持久化进凭据，之后
    /// 通过 `streaming_profile_arn()` 直接命中，不再进入解析路径。
    profile_resolution_attempted: Mutex<HashSet<u64>>,
}

impl KiroProvider {
    /// 返回共享凭据管理器，供模型发现等只读控制面逻辑复用。
    pub fn token_manager(&self) -> &Arc<MultiTokenManager> {
        &self.token_manager
    }

    /// 创建带代理配置和端点注册表的 KiroProvider 实例
    ///
    /// # Arguments
    /// * `token_manager` - 多凭据 Token 管理器
    /// * `proxy` - 全局代理配置
    /// * `endpoints` - 端点名 → 实现的注册表（至少包含 `default_endpoint` 对应条目）
    /// * `default_endpoint` - 凭据未显式指定 endpoint 时使用的名称
    pub fn with_proxy(
        token_manager: Arc<MultiTokenManager>,
        proxy: Option<ProxyConfig>,
        endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
        default_endpoint: String,
    ) -> Self {
        assert!(
            endpoints.contains_key(&default_endpoint),
            "默认端点 {} 未在 endpoints 注册表中",
            default_endpoint
        );
        let tls_backend = token_manager.config().tls_backend;
        // 预热：构建全局代理对应的 Client（作为受保护的常驻条目）
        let initial_client = build_api_client(proxy.as_ref(), 720, tls_backend)
            .expect("创建 HTTP 客户端失败");
        let client_cache = ClientCache::new(proxy.clone(), initial_client, CLIENT_CACHE_CAP);

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(client_cache),
            tls_backend,
            endpoints,
            default_endpoint,
            endpoint_cooldowns: Mutex::new(HashMap::new()),
            profile_resolution_attempted: Mutex::new(HashSet::new()),
        }
    }

    /// 根据凭据的代理配置获取（或创建并缓存）对应的 reqwest::Client
    fn client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client);
        }
        let client = build_api_client(effective.as_ref(), 720, self.tls_backend)?;
        cache.insert(effective, client.clone());
        Ok(client)
    }

    /// 用指定 endpoint 构造并发送一次 API 请求，返回原始响应（不读取 body）。
    async fn execute_api_request(
        &self,
        endpoint: &Arc<dyn KiroEndpoint>,
        ctx: &crate::kiro::token_manager::CallContext,
        machine_id: &str,
        config: &crate::model::config::Config,
        request_body: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let rctx = RequestContext {
            credentials: &ctx.credentials,
            token: &ctx.token,
            machine_id,
            config,
        };

        let url = endpoint.api_url(&rctx);
        let body = endpoint.transform_api_body(request_body, &rctx);

        tracing::debug!("使用端点 [{}] POST {}", endpoint.name(), url);
        tracing::debug!("实际发送请求体: {}", body);

        let base = self
            .client_for(&ctx.credentials)?
            .post(&url)
            .body(body)
            .header("content-type", endpoint.content_type())
            .header("Connection", "close");
        let request = endpoint.decorate_api(base, &rctx);

        let request = request
            .build()
            .map_err(|e| anyhow::anyhow!("构建请求失败: {}", e))?;
        if tracing::enabled!(tracing::Level::DEBUG) {
            for (k, v) in request.headers() {
                tracing::debug!("  header {}: {}", k, v.to_str().unwrap_or("<binary>"));
            }
        }
        Ok(self.client_for(&ctx.credentials)?.execute(request).await?)
    }

    /// 根据凭据选择 endpoint 实现
    fn endpoint_for(
        &self,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        let name = credentials
            .endpoint
            .as_deref()
            .unwrap_or(&self.default_endpoint);
        self.endpoints
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未知端点: {}", name))
    }

    /// API 请求选择端点；配置的首选端点仍在冷却时直接使用未冷却的备用端点。
    fn endpoint_for_api_request(
        &self,
        credential_id: u64,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        let endpoint = self.endpoint_for(credentials)?;
        let endpoint_name = endpoint.name();
        let Some(primary_remaining) =
            self.endpoint_cooldown_remaining(credential_id, endpoint_name)
        else {
            return Ok(endpoint);
        };

        let mut retry_after = primary_remaining;
        if let Some(fallback_name) = endpoint.fallback_endpoint() {
            match self.endpoint_cooldown_remaining(credential_id, fallback_name) {
                None => {
                    if let Some(fallback) = self.endpoints.get(fallback_name).cloned() {
                        tracing::warn!(
                            "凭据 #{} 端点 [{}] 仍在冷却（剩余 {}s），本次直接使用备用端点 [{}]",
                            credential_id,
                            endpoint_name,
                            primary_remaining.as_secs().max(1),
                            fallback_name
                        );
                        return Ok(fallback);
                    }
                }
                Some(fallback_remaining) => {
                    retry_after = retry_after.min(fallback_remaining);
                }
            }
        }

        Err(AllEndpointsCoolingError {
            retry_after_secs: retry_after.as_secs().max(1),
        }
        .into())
    }

    fn endpoint_cooldown_remaining(
        &self,
        credential_id: u64,
        endpoint_name: &str,
    ) -> Option<Duration> {
        if self.token_manager.get_never_cooldown() {
            self.endpoint_cooldowns.lock().clear();
            return None;
        }
        let key = (credential_id, endpoint_name.to_string());
        let now = Instant::now();
        let mut cooldowns = self.endpoint_cooldowns.lock();
        match cooldowns.get(&key).copied() {
            Some(until) if until > now => Some(until.duration_since(now)),
            Some(_) => {
                cooldowns.remove(&key);
                None
            }
            None => None,
        }
    }

    fn mark_endpoint_rate_limited(
        &self,
        credential_id: u64,
        endpoint_name: &str,
        cooldown: Duration,
    ) {
        if self.token_manager.get_never_cooldown() {
            tracing::warn!(
                "凭据 #{} 端点 [{}] 命中 429，永远不冷却模式下不记录端点冷却",
                credential_id,
                endpoint_name
            );
            return;
        }
        let key = (credential_id, endpoint_name.to_string());
        let until = Instant::now() + cooldown;
        let mut cooldowns = self.endpoint_cooldowns.lock();
        cooldowns
            .entry(key)
            .and_modify(|previous| {
                if until > *previous {
                    *previous = until;
                }
            })
            .or_insert(until);
        tracing::warn!(
            "凭据 #{} 端点 [{}] 命中 429，端点冷却 {} 秒",
            credential_id,
            endpoint_name,
            cooldown.as_secs()
        );
    }

    /// 在发起请求前，确保 Enterprise / IdC 账号的真实 profileArn 已解析并写入 `ctx`。
    ///
    /// 流式端点强制要求 profileArn；Enterprise / IdC 账号必须先把 BuilderID
    /// 占位符解析为真实 ARN，纯 BuilderID 账号则回退占位符。
    /// 仅对「OAuth 凭据 + profileArn 缺失或为占位符」的账号触发一次上游
    /// `ListAvailableProfiles` 查询（进程内去重）：
    /// - 命中真实 ARN → 写回 `ctx.credentials.profile_arn` 并由 token_manager 持久化；
    ///   之后该凭据的 `streaming_profile_arn()` 直接命中，不再进入此路径。
    /// - 无 Enterprise profile（纯 BuilderID 等）→ 保持占位符回退逻辑，并标记已尝试，
    ///   避免每次请求重复查询。
    async fn ensure_profile_arn(
        &self,
        ctx: &mut crate::kiro::token_manager::CallContext,
    ) -> anyhow::Result<()> {
        use crate::kiro::model::credentials::is_placeholder_profile_arn;

        if ctx.credentials.is_api_key_credential() {
            return Ok(());
        }
        let needs = match ctx.credentials.profile_arn.as_deref() {
            None => true,
            Some(arn) => is_placeholder_profile_arn(arn),
        };
        if !needs {
            return Ok(());
        }
        // 进程内去重：仅在「拿到上游确定结果」后才标记已尝试，避免一次网络抖动
        // 把账号永久卡在占位符上（重启前不再重试）。
        if self.profile_resolution_attempted.lock().contains(&ctx.id) {
            return Ok(());
        }
        match self
            .token_manager
            .resolve_profile_arn_for(ctx.id, &ctx.token)
            .await
        {
            Ok(Some(arn)) => {
                ctx.credentials.profile_arn = Some(arn);
                self.profile_resolution_attempted.lock().insert(ctx.id);
            }
            Ok(None) => {
                // 上游确认该账号无 Enterprise profile（纯 BuilderID 等）：标记已尝试，
                // 后续请求回退到占位符逻辑，不再重复查询。
                self.profile_resolution_attempted.lock().insert(ctx.id);
            }
            Err(e) => {
                if is_rate_limit_error(&e) {
                    return Err(e);
                }
                let msg = e.to_string();
                if msg.contains("AWS Builder ID is not supported for this operation") {
                    self.profile_resolution_attempted.lock().insert(ctx.id);
                    tracing::warn!(
                        "凭据 #{} 不支持 ListAvailableProfiles，按 BuilderID 占位 profileArn 继续",
                        ctx.id
                    );
                } else {
                    // 网络/瞬态错误：不标记，下次请求再试；本次按原 profileArn 继续
                    tracing::warn!(
                        "凭据 #{} 解析真实 profileArn 失败（按原 profileArn 继续）: {}",
                        ctx.id,
                        e
                    );
                }
            }
        }
        Ok(())
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多凭据故障转移（见 [`Self::call_api_with_retry`]）。
    /// `sink` 可选，用于逐跳上报链路追踪。
    pub async fn call_api(
        &self,
        request_body: &str,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        self.call_api_with_retry(request_body, false, sink, group).await
    }

    /// 发送流式 API 请求
    pub async fn call_api_stream(
        &self,
        request_body: &str,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        self.call_api_with_retry(request_body, true, sink, group).await
    }

    /// 发送 MCP API 请求（WebSearch 等工具调用）
    pub async fn call_mcp(
        &self,
        request_body: &str,
        group: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        self.call_mcp_with_retry(request_body, group).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(
        &self,
        request_body: &str,
        group: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count_in_group(group).max(1);
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();

        for attempt in 0..max_retries {
            // MCP 调用不涉及模型选择，但必须遵守客户端 Key 的凭据分组隔离。
            let mut ctx = match self.token_manager.acquire_context(None, group).await {
                Ok(c) => c,
                Err(e) => {
                    if is_rate_limit_error(&e) {
                        return Err(e);
                    }
                    if let Some(rate_limit) = take_rate_limit_error(&mut last_error) {
                        return Err(rate_limit);
                    }
                    last_error = Some(e);
                    continue;
                }
            };
            let _in_flight = self.token_manager.in_flight_guard(ctx.id);

            // Pure MCP routes (including Web Search) require the same Enterprise / IdC
            // profileArn resolution as regular model calls.
            self.ensure_profile_arn(&mut ctx).await?;

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    // endpoint 解析失败：记为失败，换下一张凭据
                    self.token_manager
                        .report_failure_for_request(ctx.id, None, group);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.mcp_url(&rctx);
            let body = endpoint.transform_mcp_body(request_body, &rctx);

            let base = self
                .client_for(&ctx.credentials)?
                .post(&url)
                .body(body)
                .header("content-type", endpoint.content_type())
                .header("Connection", "close");
            let request = endpoint.decorate_mcp(base, &rctx);

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "MCP 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();
            let rate_limit_error = (status.as_u16() == 429)
                .then(|| UpstreamRateLimitError::from_headers(response.headers()));

            // 成功响应
            if status.is_success() {
                self.token_manager.report_success_for_request(ctx.id, None);
                return Ok(response);
            }

            // 失败响应
            let body = response.text().await.unwrap_or_default();

            // 402 额度用尽
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                let has_available = self
                    .token_manager
                    .report_quota_exhausted_for_request(ctx.id, None, group);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 400 Bad Request
            if status.as_u16() == 400 {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 401/403 凭据问题
            if matches!(status.as_u16(), 401 | 403) {
                // 403 + 明确封禁文案：账号被封禁，立即禁用且不参与自愈（受配置开关控制）
                if status.as_u16() == 403
                    && self.token_manager.get_suspended_detection_enabled()
                    && endpoint.is_account_suspended(&body)
                {
                    let has_available = self
                        .token_manager
                        .report_suspended_for_request(ctx.id, None, group);
                    if !has_available {
                        anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                    }
                    last_error = Some(anyhow::anyhow!("MCP 请求失败（账号封禁）: {} {}", status, body));
                    continue;
                }

                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if Self::handle_force_refresh_result(
                        self.token_manager.force_refresh_token_for(ctx.id).await,
                    )? {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self
                    .token_manager
                    .report_failure_for_request(ctx.id, None, group);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 瞬态错误
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                tracing::warn!(
                    "MCP 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                last_error = if let Some(rate_limit) = rate_limit_error {
                    if !rate_limit.should_retry_locally() {
                        return Err(rate_limit.into());
                    }
                    Some(rate_limit.into())
                } else {
                    Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body))
                };
                if attempt + 1 < max_retries {
                    // 429 限流用更长退避；408/5xx 仍用通用快速退避
                    let delay = if status.as_u16() == 429 {
                        Self::retry_delay_throttle(attempt)
                    } else {
                        Self::retry_delay(attempt)
                    };
                    sleep(delay).await;
                }
                continue;
            }

            // 其他 4xx
            if status.is_client_error() {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 兜底
            last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("MCP 请求失败：已达到最大重试次数（{}次）", max_retries)
        }))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个凭据最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(凭据数量 × 每凭据重试次数, MAX_TOTAL_RETRIES)
    /// - 普通 429 自定义重试开启后，从首次普通 429 起改用配置的立即重试预算
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        // 重试预算按当前请求所属分组的账号数计算，避免小分组按全局账号数获得过多无效重试
        let total_credentials = self.token_manager.total_count_in_group(group).max(1);
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut ordinary_429_retries = Ordinary429RetryState::new(
            self.token_manager.get_ordinary_429_retry_count(),
        );
        // 自定义预算只有在普通 429 真正出现后才会激活。这里仅提供足够的循环槽位；
        // 未命中普通 429 的请求仍由 allows_attempt() 严格限制在旧预算内。
        let max_attempt_slots = ordinary_429_retries.max_attempt_slots(max_retries);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息
        let model = Self::extract_model_from_request(request_body);

        for attempt in 0..max_attempt_slots {
            let attempt_limit = ordinary_429_retries.current_attempt_limit(max_retries);
            if !ordinary_429_retries.allows_attempt(attempt, max_retries) {
                break;
            }
            let attempt_start = Instant::now();
            // 获取调用上下文（绑定 index、credentials、token）
            let mut ctx = match self.token_manager.acquire_context(model.as_deref(), group).await {
                Ok(c) => c,
                Err(e) => {
                    Self::emit_attempt(
                        sink, attempt, 0, "", None, outcome::UNKNOWN,
                        Some(&e.to_string()), attempt_start,
                    );
                    if is_rate_limit_error(&e) {
                        return Err(e);
                    }
                    if let Some(rate_limit) = take_rate_limit_error(&mut last_error) {
                        return Err(rate_limit);
                    }
                    last_error = Some(e);
                    continue;
                }
            };
            let _in_flight = self.token_manager.in_flight_guard(ctx.id);

            // 确保 Enterprise / IdC 账号的真实 profileArn 已解析（流式端点强制要求）
            self.ensure_profile_arn(&mut ctx).await?;

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for_api_request(ctx.id, &ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    if let Some(cooling) = e.downcast_ref::<AllEndpointsCoolingError>() {
                        tracing::warn!(
                            "凭据 #{} 的所有上游端点均在冷却，切换其他凭据（最早 {}s 后恢复）",
                            ctx.id,
                            cooling.retry_after_secs
                        );
                        let remaining =
                            self.token_manager
                                .report_temporary_cooldown_for_request(
                                    ctx.id,
                                    Duration::from_secs(cooling.retry_after_secs),
                                    model.as_deref(),
                                    group,
                                    "所有上游端点均冷却",
                                );
                        let rate_limit = UpstreamRateLimitError::new(Some(
                            cooling.retry_after_secs.to_string(),
                        ));
                        if remaining == 0 {
                            return Err(rate_limit.into());
                        }
                        last_error = Some(rate_limit.into());
                        continue;
                    }
                    Self::emit_attempt(
                        sink, attempt, ctx.id, "", None, outcome::UNKNOWN,
                        Some(&e.to_string()), attempt_start,
                    );
                    if is_rate_limit_error(&e) {
                        return Err(e);
                    }
                    last_error = Some(e);
                    self.token_manager
                        .report_failure_for_request(ctx.id, model.as_deref(), group);
                    continue;
                }
            };
            let endpoint_name = endpoint.name();

            let response = match self
                .execute_api_request(&endpoint, &ctx, &machine_id, config, request_body)
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "API 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        attempt_limit,
                        e
                    );
                    Self::emit_attempt(
                        sink, attempt, ctx.id, endpoint_name, None,
                        outcome::NETWORK_ERROR, Some(&e.to_string()), attempt_start,
                    );
                    // 网络错误通常是上游/链路瞬态问题，不应导致"禁用凭据"或"切换凭据"
                    // （否则一段时间网络抖动会把所有凭据都误禁用，需要重启才能恢复）
                    last_error = Some(e);
                    if ordinary_429_retries.has_next_attempt(attempt, max_retries) {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();
            let rate_limit_error = (status.as_u16() == 429)
                .then(|| UpstreamRateLimitError::from_headers(response.headers()));

            // 成功响应
            if status.is_success() {
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::SUCCESS, None, attempt_start,
                );
                self.token_manager
                    .report_success_for_request(ctx.id, model.as_deref());
                return Ok(KiroCallResult {
                    response,
                    credential_id: ctx.id,
                });
            }

            // 失败响应：读取 body 用于日志/错误信息
            let body = response.text().await.unwrap_or_default();
            let ordinary_429 =
                is_ordinary_429(status.as_u16(), endpoint.as_ref(), &body);

            // 402 Payment Required 且额度用尽：禁用凭据并故障转移
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                tracing::warn!(
                    "API 请求失败（额度已用尽，禁用凭据并切换，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    attempt_limit,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::QUOTA_EXHAUSTED, Some(&body), attempt_start,
                );

                let has_available = self.token_manager.report_quota_exhausted_for_request(
                    ctx.id,
                    model.as_deref(),
                    group,
                );
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 400 Bad Request - 大多数请求问题重试无意义；模型不支持是凭据级能力差异，
            // 需记录模型级避让并切换到其它凭据尝试。
            if status.as_u16() == 400 {
                if endpoint.is_model_unsupported(&body) {
                    let Some(model_id) = model.as_deref() else {
                        Self::emit_attempt(
                            sink,
                            attempt,
                            ctx.id,
                            endpoint_name,
                            Some(400),
                            outcome::MODEL_UNSUPPORTED,
                            Some(&body),
                            attempt_start,
                        );
                        anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
                    };
                    let Some(remaining) = self
                        .token_manager
                        .report_model_unsupported(ctx.id, model_id, group)
                    else {
                        tracing::warn!(
                            "API 请求失败（凭据 #{} 不支持模型 {}，模型退让已关闭）: {}",
                            ctx.id,
                            model_id,
                            body
                        );
                        Self::emit_attempt(
                            sink,
                            attempt,
                            ctx.id,
                            endpoint_name,
                            Some(400),
                            outcome::MODEL_UNSUPPORTED,
                            Some(&body),
                            attempt_start,
                        );
                        anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
                    };
                    tracing::warn!(
                        "API 请求失败（凭据 #{} 不支持模型 {}，本模型后续避让该凭据并切换，尝试 {}/{}）: {}",
                        ctx.id,
                        model_id,
                        attempt + 1,
                        attempt_limit,
                        body
                    );
                    Self::emit_attempt(
                        sink,
                        attempt,
                        ctx.id,
                        endpoint_name,
                        Some(400),
                        outcome::MODEL_UNSUPPORTED,
                        Some(&body),
                        attempt_start,
                    );
                    last_error = Some(anyhow::anyhow!(
                        "{} API 请求失败（凭据 #{} 不支持当前模型，已记录模型级避让）: {} {}",
                        api_type,
                        ctx.id,
                        status,
                        body
                    ));
                    if remaining == 0 {
                        anyhow::bail!(
                            "{} API 请求失败：所有凭据都不支持当前模型或已不可用。原始响应: {} {}",
                            api_type,
                            status,
                            body
                        );
                    }
                    continue;
                }
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(400),
                    outcome::BAD_REQUEST, Some(&body), attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 401/403 - 更可能是凭据/权限问题：计入失败并允许故障转移
            if matches!(status.as_u16(), 401 | 403) {
                // 403 + 明确封禁文案：账号被封禁，立即禁用且不参与自愈（受配置开关控制）
                if status.as_u16() == 403
                    && self.token_manager.get_suspended_detection_enabled()
                    && endpoint.is_account_suspended(&body)
                {
                    tracing::error!(
                        "API 请求失败（账号被封禁，禁用凭据 #{} 并切换，尝试 {}/{}）: {} {}",
                        ctx.id,
                        attempt + 1,
                        max_retries,
                        status,
                        body
                    );
                    Self::emit_attempt(
                        sink, attempt, ctx.id, endpoint_name, Some(403),
                        outcome::ACCOUNT_SUSPENDED, Some(&body), attempt_start,
                    );

                    let has_available = self.token_manager.report_suspended_for_request(
                        ctx.id,
                        model.as_deref(),
                        group,
                    );
                    if !has_available {
                        anyhow::bail!(
                            "{} API 请求失败（所有凭据已用尽）: {} {}",
                            api_type,
                            status,
                            body
                        );
                    }
                    last_error = Some(anyhow::anyhow!(
                        "{} API 请求失败（账号封禁）: {} {}",
                        api_type,
                        status,
                        body
                    ));
                    continue;
                }

                tracing::warn!(
                    "API 请求失败（可能为凭据错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    attempt_limit,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::AUTH_FAILED, Some(&body), attempt_start,
                );

                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if Self::handle_force_refresh_result(
                        self.token_manager.force_refresh_token_for(ctx.id).await,
                    )? {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available =
                    self.token_manager
                        .report_failure_for_request(ctx.id, model.as_deref(), group);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 429 端点降级：先用同一凭据切到备用端点换桶重试。
            // 备用端点也失败后，再按主端点响应分类为账号风控或瞬态退避。
            if status.as_u16() == 429 {
                let endpoint_cooldown_secs = self
                    .token_manager
                    .get_account_throttle_cooldown_secs()
                    .max(1);
                self.mark_endpoint_rate_limited(
                    ctx.id,
                    endpoint_name,
                    Duration::from_secs(endpoint_cooldown_secs),
                );
                let account_throttled = !self.token_manager.get_never_cooldown()
                    && self.token_manager.get_account_throttle_failover()
                    && endpoint.is_account_throttled(&body);
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(429),
                    if account_throttled {
                        outcome::ACCOUNT_THROTTLED
                    } else {
                        outcome::TRANSIENT
                    },
                    Some(&body),
                    attempt_start,
                );

                if let Some(fb_name) = endpoint.fallback_endpoint() {
                    let fallback_available = if let Some(remaining) =
                        self.endpoint_cooldown_remaining(ctx.id, fb_name)
                    {
                        tracing::warn!(
                            "备用端点 [{}] 仍在冷却（凭据 #{}，剩余 {}s），跳过本次降级",
                            fb_name,
                            ctx.id,
                            remaining.as_secs().max(1)
                        );
                        false
                    } else {
                        true
                    };
                    if let Some(fb_endpoint) = fallback_available
                        .then(|| self.endpoints.get(fb_name).cloned())
                        .flatten()
                    {
                        tracing::info!(
                            "端点 [{}] 限流 429，凭据 #{} 降级到备用端点 [{}] 重试（换桶不换号）",
                            endpoint_name,
                            ctx.id,
                            fb_name
                        );
                        let fb_start = Instant::now();
                        match self
                            .execute_api_request(
                                &fb_endpoint,
                                &ctx,
                                &machine_id,
                                config,
                                request_body,
                            )
                            .await
                        {
                            Ok(fb_resp) if fb_resp.status().is_success() => {
                                let fb_status = fb_resp.status();
                                Self::emit_attempt(
                                    sink,
                                    attempt,
                                    ctx.id,
                                    fb_name,
                                    Some(fb_status.as_u16()),
                                    outcome::SUCCESS,
                                    None,
                                    fb_start,
                                );
                                self.token_manager
                                    .report_success_for_request(ctx.id, model.as_deref());
                                tracing::info!(
                                    "凭据 #{} 在备用端点 [{}] 成功（主端点 [{}] 此前 429）",
                                    ctx.id,
                                    fb_name,
                                    endpoint_name
                                );
                                return Ok(KiroCallResult {
                                    response: fb_resp,
                                    credential_id: ctx.id,
                                });
                            }
                            Ok(fb_resp) => {
                                let fb_status = fb_resp.status();
                                let fb_body = fb_resp.text().await.unwrap_or_default();
                                if fb_status.as_u16() == 429 {
                                    self.mark_endpoint_rate_limited(
                                        ctx.id,
                                        fb_name,
                                        Duration::from_secs(endpoint_cooldown_secs),
                                    );
                                }
                                Self::emit_attempt(
                                    sink,
                                    attempt,
                                    ctx.id,
                                    fb_name,
                                    Some(fb_status.as_u16()),
                                    outcome::TRANSIENT,
                                    Some(&fb_body),
                                    fb_start,
                                );
                                tracing::warn!(
                                    "备用端点 [{}] 也失败（{}），落回主端点 429 分类处理",
                                    fb_name,
                                    fb_status
                                );
                            }
                            Err(e) => {
                                Self::emit_attempt(
                                    sink,
                                    attempt,
                                    ctx.id,
                                    fb_name,
                                    None,
                                    outcome::NETWORK_ERROR,
                                    Some(&e.to_string()),
                                    fb_start,
                                );
                                tracing::warn!(
                                    "备用端点 [{}] 请求发送失败（{}），落回主端点 429 分类处理",
                                    fb_name,
                                    e
                                );
                            }
                        }
                    }
                }
            }

            // 429 + suspicious activity = 账号级临时风控
            // 仅当前凭据被针对，故障转移到其它凭据可立即恢复（受配置开关控制）。
            if status.as_u16() == 429
                && !self.token_manager.get_never_cooldown()
                && self.token_manager.get_account_throttle_failover()
                && endpoint.is_account_throttled(&body)
            {
                let cooldown_secs = self
                    .token_manager
                    .get_account_throttle_cooldown_secs()
                    .max(1);
                let cooldown = std::time::Duration::from_secs(cooldown_secs);
                tracing::warn!(
                    "API 请求失败（账号级风控，凭据 #{} 冷却 {}s 并切换，尝试 {}/{}）: {}",
                    ctx.id,
                    cooldown_secs,
                    attempt + 1,
                    attempt_limit,
                    body
                );

                let remaining = self
                    .token_manager
                    .report_account_throttled_for_request(
                        ctx.id,
                        cooldown,
                        model.as_deref(),
                        group,
                    );
                // 账号级风控通常不返回 Retry-After；此时使用本地实际冷却时间，
                // 让下游网关在同一时段内也停止调度该虚拟账号。
                let (rate_limit_error, must_wait_for_upstream) =
                    account_rate_limit_with_fallback(rate_limit_error, cooldown_secs);

                // 上游给出明确等待时间时必须立即交给客户端遵守，不能在同一请求中
                // 提前换号重试。无有效 Retry-After 时仍允许按既有策略故障转移。
                if must_wait_for_upstream {
                    return Err(rate_limit_error.into());
                }

                if remaining == 0 {
                    return Err(rate_limit_error.into());
                }
                last_error = Some(rate_limit_error.into());
                continue;
            }

            // 客户端请求格式错误（messages 数组违反协议）：根因在调用方，重试无意义
            // 上游常以 5xx 返回，必须在下方"瞬态错误重试"分支之前拦截，否则会被当作
            // 上游故障重试 max_retries 次，把一个坏请求放大成多次 503（503 风暴）。
            // 直接终止：不重试、不切换凭据、不计入凭据失败。
            if endpoint.is_client_validation_error(&body) {
                tracing::warn!(
                    "API 请求失败（客户端请求格式错误，不重试）: {} {}",
                    status,
                    body
                );
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::BAD_REQUEST, Some(&body), attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 524 / gateway timeout：上游边缘层超时，继续在本次请求内重试通常只会
            // 放大客户端等待时间和 Claude 端 Retrying 轮数；快速返回，让客户端下一次调用
            // 重新建连。
            if status.as_u16() == 524 || endpoint.is_gateway_timeout(&body) {
                tracing::warn!(
                    "API 请求失败（上游网关超时，不重试）: {} {}",
                    status,
                    body
                );
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::TRANSIENT,
                    Some(&body),
                    attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 429/408/5xx - 瞬态上游错误：重试但不禁用或切换凭据
            // （避免 429 high traffic / 502 high load 等瞬态错误把所有凭据锁死）
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                tracing::warn!(
                    "API 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    attempt_limit,
                    status,
                    body
                );
                if status.as_u16() != 429 {
                    Self::emit_attempt(
                        sink,
                        attempt,
                        ctx.id,
                        endpoint_name,
                        Some(status.as_u16()),
                        outcome::TRANSIENT,
                        Some(&body),
                        attempt_start,
                    );
                    last_error = Some(anyhow::anyhow!(
                        "{} API 请求失败: {} {}",
                        api_type,
                        status,
                        body
                    ));
                } else {
                    let report = self.token_manager.report_rate_limited(ctx.id);
                    if self.token_manager.get_never_cooldown() {
                        tracing::warn!(
                            "凭据 #{} 普通 429 已记录：永远不冷却模式，不进入任何本地冷却，剩余可调度账号 {}",
                            ctx.id,
                            report.remaining_available
                        );
                    } else if report.concurrency_limit == 0 {
                        tracing::warn!(
                            "凭据 #{} 普通 429 已记录：不限并发模式，不进入本地软冷却，剩余可调度账号 {}",
                            ctx.id,
                            report.remaining_available
                        );
                    } else {
                        tracing::warn!(
                            "凭据 #{} 普通 429 软限流已生效：冷却 {}s，连续 {} 次，动态并发上限 {}，剩余可调度账号 {}",
                            ctx.id,
                            report.cooldown_secs,
                            report.consecutive_count,
                            report.concurrency_limit,
                            report.remaining_available
                        );
                    }
                    let propagated = match rate_limit_error {
                        Some(rate_limit)
                            if should_propagate_ordinary_429_immediately(
                                &rate_limit,
                                ordinary_429 && ordinary_429_retries.enabled(),
                            ) =>
                        {
                            return Err(rate_limit.into());
                        }
                        Some(rate_limit) if rate_limit.retry_after().is_some() => rate_limit,
                        _ if report.cooldown_secs > 0 => {
                            UpstreamRateLimitError::new(Some(report.cooldown_secs.to_string()))
                        }
                        _ => UpstreamRateLimitError::new(None),
                    };

                    if ordinary_429 && ordinary_429_retries.enabled() {
                        if ordinary_429_retries.activate_or_retry(attempt) {
                            tracing::warn!(
                                "普通 429 自定义立即重试已触发：当前外层尝试 {}，最多额外立即重试 {} 次（忽略 Retry-After）",
                                attempt + 1,
                                ordinary_429_retries.configured_retries()
                            );
                            last_error = Some(propagated.into());
                            continue;
                        }

                        // 自定义预算耗尽后直接传播最后一次普通 429；不再回落到旧预算，
                        // 也不在最后一次失败后额外等待。
                        return Err(propagated.into());
                    }
                    last_error = Some(propagated.into());
                }
                if ordinary_429_retries.has_next_attempt(attempt, max_retries) {
                    // 429 限流用更长退避给账号配额恢复时间；408/5xx 仍用通用快速退避
                    let delay = if status.as_u16() == 429 {
                        Self::retry_delay_throttle(attempt)
                    } else {
                        Self::retry_delay(attempt)
                    };
                    sleep(delay).await;
                }
                continue;
            }

            // 其他 4xx - 通常为请求/配置问题：直接返回，不计入凭据失败
            if status.is_client_error() {
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::BAD_REQUEST, Some(&body), attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 兜底：当作可重试的瞬态错误处理（不切换凭据）
            tracing::warn!(
                "API 请求失败（未知错误，尝试 {}/{}）: {} {}",
                attempt + 1,
                attempt_limit,
                status,
                body
            );
            Self::emit_attempt(
                sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                outcome::UNKNOWN, Some(&body), attempt_start,
            );
            last_error = Some(anyhow::anyhow!(
                "{} API 请求失败: {} {}",
                api_type,
                status,
                body
            ));
            if ordinary_429_retries.has_next_attempt(attempt, max_retries) {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        // 所有重试都失败
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "{} API 请求失败：已达到最大重试次数（{}次）",
                api_type,
                ordinary_429_retries.current_attempt_limit(max_retries)
            )
        }))
    }

    /// 向 trace sink 上报一跳结果（sink 为 None 时无开销）
    #[allow(clippy::too_many_arguments)]
    fn emit_attempt(
        sink: Option<&dyn TraceSink>,
        attempt: usize,
        credential_id: u64,
        endpoint: &str,
        http_status: Option<u16>,
        outcome: &str,
        error_body: Option<&str>,
        started: Instant,
    ) {
        let Some(sink) = sink else { return };
        sink.on_attempt(TraceAttempt {
            attempt: attempt as u32,
            credential_id,
            endpoint: endpoint.to_string(),
            http_status,
            outcome: outcome.to_string(),
            error_snippet: error_body.and_then(truncate_snippet),
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 2_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }

    /// 429 限流专用退避：比通用退避更长。
    ///
    /// 上游 429（SERVICE_REQUEST_RATE_EXCEEDED）是账号级速率配额耗尽，需要更长
    /// 时间恢复；用通用的 ≤2s 快速退避只会让请求在配额恢复前反复撞墙、持续触顶。
    /// 这里 base 1s、封顶 8s，给账号配额留出恢复窗口。
    fn retry_delay_throttle(attempt: usize) -> Duration {
        const BASE_MS: u64 = 1_000;
        const MAX_MS: u64 = 8_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }

    /// 返回是否刷新成功；类型化刷新 429 原样传播，其他刷新失败交回调用方按认证失败处理。
    fn handle_force_refresh_result(result: anyhow::Result<()>) -> anyhow::Result<bool> {
        match result {
            Ok(()) => Ok(true),
            Err(error) if is_rate_limit_error(&error) => Err(error),
            Err(_) => Ok(false),
        }
    }
}

fn is_rate_limit_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UpstreamRateLimitError>().is_some()
        || error.downcast_ref::<RateLimitSoftThrottleError>().is_some()
}

fn take_rate_limit_error(last_error: &mut Option<anyhow::Error>) -> Option<anyhow::Error> {
    if last_error
        .as_ref()
        .is_some_and(|error| error.downcast_ref::<UpstreamRateLimitError>().is_some())
    {
        last_error.take()
    } else {
        None
    }
}

/// 普通 429 的可选外层立即重试预算。
///
/// 配置未开启时，循环边界完全沿用旧的凭据数预算。配置开启后也不会预先扩大普通
/// 请求的重试次数；只有第一次普通 429 才会激活一个从当前尝试开始计算的边界，确保
/// 最多再执行配置数量的外层尝试。
#[derive(Debug)]
struct Ordinary429RetryState {
    configured_retries: usize,
    attempt_limit: Option<usize>,
}

impl Ordinary429RetryState {
    fn new(configured_retries: i32) -> Self {
        Self {
            configured_retries: configured_retries.max(0) as usize,
            attempt_limit: None,
        }
    }

    fn enabled(&self) -> bool {
        self.configured_retries > 0
    }

    fn configured_retries(&self) -> usize {
        self.configured_retries
    }

    fn max_attempt_slots(&self, legacy_attempt_limit: usize) -> usize {
        legacy_attempt_limit.saturating_add(self.configured_retries)
    }

    fn current_attempt_limit(&self, legacy_attempt_limit: usize) -> usize {
        self.attempt_limit.unwrap_or(legacy_attempt_limit)
    }

    fn allows_attempt(&self, attempt: usize, legacy_attempt_limit: usize) -> bool {
        attempt < self.current_attempt_limit(legacy_attempt_limit)
    }

    fn has_next_attempt(&self, attempt: usize, legacy_attempt_limit: usize) -> bool {
        attempt.saturating_add(1) < self.current_attempt_limit(legacy_attempt_limit)
    }

    /// 激活首次普通 429 的预算，并返回当前失败后是否还允许一次外层尝试。
    fn activate_or_retry(&mut self, attempt: usize) -> bool {
        debug_assert!(self.enabled());
        let configured_retries = self.configured_retries;
        let attempt_limit = *self.attempt_limit.get_or_insert_with(|| {
            attempt
                .saturating_add(1)
                .saturating_add(configured_retries)
        });
        attempt.saturating_add(1) < attempt_limit
    }
}

fn should_propagate_ordinary_429_immediately(
    rate_limit: &UpstreamRateLimitError,
    custom_retry_enabled: bool,
) -> bool {
    !custom_retry_enabled && !rate_limit.should_retry_locally()
}

/// “普通 429”只包括全局过载/请求过多，不包括带 suspicious activity 特征的
/// 账号级临时风控。后者即使在永远不冷却模式下落入瞬态错误分支，也不能激活本预算。
fn is_ordinary_429(status: u16, endpoint: &dyn KiroEndpoint, body: &str) -> bool {
    status == 429 && !endpoint.is_account_throttled(body)
}

/// 为账号风控 429 补齐本地冷却时间，并区分上游是否明确要求等待。
fn account_rate_limit_with_fallback(
    rate_limit: Option<UpstreamRateLimitError>,
    cooldown_secs: u64,
) -> (UpstreamRateLimitError, bool) {
    let must_wait_for_upstream = rate_limit
        .as_ref()
        .is_some_and(|error| !error.should_retry_locally());
    let error = match rate_limit {
        Some(error) if error.retry_after().is_some() => error,
        _ => UpstreamRateLimitError::new(Some(cooldown_secs.to_string())),
    };
    (error, must_wait_for_upstream)
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use crate::kiro::endpoint::{IdeEndpoint, RuntimeEndpoint};

    fn endpoint_cooldown_test_provider_with_config(
        config: crate::model::config::Config,
    ) -> (KiroProvider, KiroCredentials) {
        let credentials = KiroCredentials::default();
        let token_manager = Arc::new(
            MultiTokenManager::new(
                config,
                vec![credentials.clone()],
                None,
                None,
                false,
            )
            .unwrap(),
        );
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert("ide".to_string(), Arc::new(IdeEndpoint::new()));
        endpoints.insert("runtime".to_string(), Arc::new(RuntimeEndpoint::new()));
        (
            KiroProvider::with_proxy(token_manager, None, endpoints, "ide".to_string()),
            credentials,
        )
    }

    fn endpoint_cooldown_test_provider() -> (KiroProvider, KiroCredentials) {
        endpoint_cooldown_test_provider_with_config(crate::model::config::Config::default())
    }

    #[test]
    fn endpoint_429_cooldown_routes_next_request_directly_to_fallback() {
        let (provider, credentials) = endpoint_cooldown_test_provider();
        provider.mark_endpoint_rate_limited(1, "ide", Duration::from_secs(300));

        let selected = provider
            .endpoint_for_api_request(1, &credentials)
            .expect("备用端点未冷却时应直接降级");

        assert_eq!(selected.name(), "runtime");
    }

    #[test]
    fn both_endpoint_cooldowns_exhaust_the_credential() {
        let (provider, credentials) = endpoint_cooldown_test_provider();
        provider.mark_endpoint_rate_limited(1, "ide", Duration::from_secs(300));
        provider.mark_endpoint_rate_limited(1, "runtime", Duration::from_secs(300));

        let error = match provider.endpoint_for_api_request(1, &credentials) {
            Ok(_) => panic!("两个端点都冷却时不应继续撞上游"),
            Err(error) => error,
        };

        assert!(error.downcast_ref::<AllEndpointsCoolingError>().is_some());
    }

    #[test]
    fn never_cooldown_ignores_and_clears_endpoint_cooldowns() {
        let mut config = crate::model::config::Config::default();
        config.never_cooldown = true;
        let (provider, credentials) = endpoint_cooldown_test_provider_with_config(config);

        provider.mark_endpoint_rate_limited(1, "ide", Duration::from_secs(300));
        provider.mark_endpoint_rate_limited(1, "runtime", Duration::from_secs(300));

        let selected = provider
            .endpoint_for_api_request(1, &credentials)
            .expect("永远不冷却模式应继续使用首选端点");

        assert_eq!(selected.name(), "ide");
        assert!(provider.endpoint_cooldowns.lock().is_empty());
    }

    #[test]
    fn preserves_typed_rate_limit_when_later_credential_selection_fails() {
        let mut last_error = Some(anyhow::Error::new(UpstreamRateLimitError::new(Some(
            "45".to_string(),
        ))));

        // A concurrent request may cool the final credential before the next acquisition.
        // The earlier upstream 429 must win over the later generic selection failure.
        let returned = take_rate_limit_error(&mut last_error)
            .unwrap_or_else(|| anyhow::anyhow!("所有凭据均已禁用"));

        let rate_limit = returned
            .downcast_ref::<UpstreamRateLimitError>()
            .expect("应保留最初的类型化 429");
        assert_eq!(rate_limit.retry_after(), Some("45"));
        assert!(last_error.is_none());
    }

    #[test]
    fn does_not_relabel_generic_error_as_rate_limit() {
        let mut last_error = Some(anyhow::anyhow!("所有凭据均已禁用"));
        assert!(take_rate_limit_error(&mut last_error).is_none());
        assert!(last_error.is_some());
    }

    #[test]
    fn account_rate_limit_uses_cooldown_when_retry_after_is_missing() {
        let (error, must_wait) = account_rate_limit_with_fallback(
            Some(UpstreamRateLimitError::new(None)),
            300,
        );

        assert_eq!(error.retry_after(), Some("300"));
        assert!(!must_wait, "无上游等待值时仍可按账号冷却策略故障转移");
    }

    #[test]
    fn account_rate_limit_honors_explicit_upstream_retry_after() {
        let (error, must_wait) = account_rate_limit_with_fallback(
            Some(UpstreamRateLimitError::new(Some("90".to_string()))),
            300,
        );

        assert_eq!(error.retry_after(), Some("90"));
        assert!(must_wait, "上游明确要求等待时不得在内部提前重试");
    }

    #[test]
    fn force_refresh_rate_limit_is_propagated_instead_of_counted_as_auth_failure() {
        let error = anyhow::Error::new(UpstreamRateLimitError::new(Some("60".to_string())));
        let returned = KiroProvider::handle_force_refresh_result(Err(error))
            .expect_err("强制刷新 429 应立即传播");

        let rate_limit = returned
            .downcast_ref::<UpstreamRateLimitError>()
            .expect("应保留类型化 429");
        assert_eq!(rate_limit.retry_after(), Some("60"));
    }

    #[test]
    fn generic_force_refresh_failure_remains_an_auth_failure() {
        let outcome = KiroProvider::handle_force_refresh_result(Err(anyhow::anyhow!(
            "invalid refresh token",
        )))
        .unwrap();
        assert!(!outcome);
    }

    #[test]
    fn current_acquire_rate_limit_is_detected_before_outer_retry() {
        let error = anyhow::Error::new(UpstreamRateLimitError::new(Some("30".to_string())));
        assert!(is_rate_limit_error(&error));
    }

    #[test]
    fn disabled_ordinary_429_retry_values_preserve_legacy_attempt_limit() {
        for configured in [0, -1] {
            let state = Ordinary429RetryState::new(configured);
            assert!(!state.enabled());
            assert_eq!(state.max_attempt_slots(3), 3);
            assert!(state.allows_attempt(2, 3));
            assert!(!state.allows_attempt(3, 3));
        }
    }

    #[test]
    fn custom_ordinary_429_budget_activates_only_after_an_ordinary_429() {
        let mut state = Ordinary429RetryState::new(5);

        // 预留的循环槽位不能让从未命中过普通 429 的请求突破旧预算。
        assert_eq!(state.max_attempt_slots(3), 8);
        assert!(!state.allows_attempt(3, 3));

        assert!(state.activate_or_retry(0));
        assert_eq!(state.current_attempt_limit(3), 6);
        assert!(state.allows_attempt(5, 3));
        assert!(!state.allows_attempt(6, 3));
    }

    #[test]
    fn custom_ordinary_429_budget_allows_exactly_n_additional_attempts() {
        let mut state = Ordinary429RetryState::new(2);

        assert!(state.activate_or_retry(0), "首次 429 后应允许第 1 次重试");
        assert!(state.activate_or_retry(1), "应允许第 2 次重试");
        assert!(
            !state.activate_or_retry(2),
            "第 3 次外层尝试仍为 429 时预算应耗尽"
        );
        assert_eq!(state.current_attempt_limit(4), 3);
    }

    #[test]
    fn custom_ordinary_429_budget_starts_at_the_first_matching_attempt() {
        let mut state = Ordinary429RetryState::new(2);

        assert!(state.activate_or_retry(2));
        assert_eq!(state.current_attempt_limit(3), 5);
        assert!(state.has_next_attempt(3, 3));
        assert!(!state.has_next_attempt(4, 3));
    }

    #[test]
    fn custom_ordinary_429_retry_overrides_retry_after_until_budget_exhaustion() {
        let rate_limit = UpstreamRateLimitError::new(Some("60".to_string()));

        assert!(should_propagate_ordinary_429_immediately(
            &rate_limit,
            false
        ));
        assert!(!should_propagate_ordinary_429_immediately(
            &rate_limit,
            true
        ));
    }

    #[test]
    fn ordinary_429_excludes_suspicious_activity_account_throttles() {
        let endpoint = IdeEndpoint::new();
        let ordinary =
            r#"{"message":"Too many requests, please wait before trying again.","reason":null}"#;
        let suspicious = r#"{"message":"Due to suspicious activity, we are imposing temporary limits on how frequently your account (d-example) can send a request to Kiro while we investigate.","reason":null}"#;

        assert!(is_ordinary_429(429, &endpoint, ordinary));
        assert!(!is_ordinary_429(429, &endpoint, suspicious));
        assert!(!is_ordinary_429(503, &endpoint, ordinary));
    }
}
