//! Admin API 中间件

use std::sync::Arc;

use parking_lot::RwLock;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};

use super::client_keys::SharedClientKeyManager;
use super::groups::SharedGroupManager;
use super::service::AdminService;
use super::types::AdminErrorResponse;
use super::usage_stats::SharedAggregator;
use super::trace_db::SharedTraceStore;
use crate::common::auth;

/// Admin API 共享状态
#[derive(Clone)]
pub struct AdminState {
    /// 登录API密钥（管理面板登录用，运行时可修改）
    pub admin_api_key: Arc<RwLock<String>>,
    /// 运维凭据导入 API 密钥（独立于管理面板密钥）
    pub credential_import_api_key: Option<Arc<str>>,
    /// Admin 服务
    pub service: Arc<AdminService>,
    /// 客户端 Key 管理器（与 anthropic 路由共享）
    pub client_keys: SharedClientKeyManager,
    /// 用量聚合器（与 anthropic 路由共享）
    pub usage_aggregator: SharedAggregator,
    /// 请求链路追踪存储（与 anthropic 路由共享）
    pub trace_store: SharedTraceStore,
    /// 账号分组注册表（持久化到 groups.json）
    pub groups: SharedGroupManager,
}

impl AdminState {
    pub fn new(
        admin_api_key: impl Into<String>,
        service: AdminService,
        client_keys: SharedClientKeyManager,
        usage_aggregator: SharedAggregator,
        trace_store: SharedTraceStore,
        groups: SharedGroupManager,
    ) -> Self {
        Self {
            admin_api_key: Arc::new(RwLock::new(admin_api_key.into())),
            credential_import_api_key: None,
            service: Arc::new(service),
            client_keys,
            usage_aggregator,
            trace_store,
            groups,
        }
    }

    pub fn with_credential_import_api_key(mut self, api_key: Option<String>) -> Self {
        self.credential_import_api_key = api_key
            .filter(|key| !key.trim().is_empty())
            .map(Arc::<str>::from);
        self
    }
}

/// Admin API 认证中间件 — 校验登录API密钥（adminApiKey）
pub async fn admin_auth_middleware(
    State(state): State<AdminState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let api_key = auth::extract_api_key(&request);

    let current_key = state.admin_api_key.read().clone();
    match api_key {
        Some(key) if auth::constant_time_eq(&key, &current_key) => next.run(request).await,
        _ => {
            let error = AdminErrorResponse::authentication_error();
            (StatusCode::UNAUTHORIZED, Json(error)).into_response()
        }
    }
}

/// 运维凭据导入 API 认证中间件。
///
/// 只接受专用的 `x-credential-import-key` 请求头，不接受 adminApiKey 或 Bearer 认证。
pub async fn credential_import_auth_middleware(
    State(state): State<AdminState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let authenticated =
        credential_import_key_matches(&request, state.credential_import_api_key.as_deref());

    if authenticated {
        next.run(request).await
    } else {
        let error = AdminErrorResponse::credential_import_authentication_error();
        (StatusCode::UNAUTHORIZED, Json(error)).into_response()
    }
}

fn credential_import_key_matches(request: &Request<Body>, expected_key: Option<&str>) -> bool {
    let supplied_key = request
        .headers()
        .get("x-credential-import-key")
        .and_then(|value| value.to_str().ok());

    expected_key
        .zip(supplied_key)
        .is_some_and(|(expected, supplied)| auth::constant_time_eq(supplied, expected))
}

#[cfg(test)]
mod tests {
    use super::credential_import_key_matches;
    use axum::{body::Body, http::Request};

    #[test]
    fn credential_import_auth_accepts_only_dedicated_header() {
        let request = Request::builder()
            .header("x-credential-import-key", "ops-secret")
            .body(Body::empty())
            .unwrap();
        assert!(credential_import_key_matches(&request, Some("ops-secret")));
    }

    #[test]
    fn credential_import_auth_rejects_admin_header_and_missing_config() {
        let request = Request::builder()
            .header("x-api-key", "ops-secret")
            .body(Body::empty())
            .unwrap();
        assert!(!credential_import_key_matches(&request, Some("ops-secret")));

        let request = Request::builder()
            .header("x-credential-import-key", "ops-secret")
            .body(Body::empty())
            .unwrap();
        assert!(!credential_import_key_matches(&request, None));
    }
}
