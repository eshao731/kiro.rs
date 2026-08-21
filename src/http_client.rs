//! HTTP Client 构建模块
//!
//! 提供统一的 HTTP Client 构建功能，支持代理配置

use reqwest::{Client, Proxy};
use std::time::Duration;

use crate::model::config::TlsBackend;

/// 代理配置
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ProxyConfig {
    /// 代理地址，支持 http/https/socks5
    pub url: String,
    /// 代理认证用户名
    pub username: Option<String>,
    /// 代理认证密码
    pub password: Option<String>,
}

impl ProxyConfig {
    /// 从 url 创建代理配置
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: None,
            password: None,
        }
    }

    /// 设置认证信息
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Rotate the session number used by 711proxy sticky residential proxies.
    ///
    /// This intentionally only handles the provider's documented URL shape. Other
    /// proxies must keep their configured URL unchanged.
    pub fn rotate_711proxy_session(&self) -> Option<Self> {
        if !self.url.to_ascii_lowercase().contains("711proxy.com") {
            return None;
        }

        let marker = "session-";
        let marker_start = self.url.to_ascii_lowercase().find(marker)?;
        let digits_start = marker_start + marker.len();
        let digits_end = self.url[digits_start..]
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii_digit())
            .map(|(offset, _)| digits_start + offset)
            .unwrap_or(self.url.len());
        if digits_end == digits_start {
            return None;
        }

        let old_session = &self.url[digits_start..digits_end];
        let mut next_session = fastrand::u64(10_000_000..100_000_000).to_string();
        if next_session == old_session {
            next_session = (next_session.parse::<u64>().unwrap_or(10_000_000) + 1).to_string();
        }

        let mut rotated = self.clone();
        rotated
            .url
            .replace_range(digits_start..digits_end, &next_session);
        Some(rotated)
    }
}

/// 构建 HTTP Client
///
/// # Arguments
/// * `proxy` - 可选的代理配置
/// * `timeout_secs` - 超时时间（秒）
///
/// # Returns
/// 配置好的 reqwest::Client
pub fn build_client(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    build_client_inner(proxy, timeout_secs, tls_backend, false)
}

/// Build the client used for Kiro model API calls.
pub fn build_api_client(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    // Keep reqwest's default HTTP negotiation. Forcing HTTP/1.1 through a
    // SOCKS5 proxy caused a higher rate of truncated streaming response bodies.
    build_client_inner(proxy, timeout_secs, tls_backend, false)
}

fn build_client_inner(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
    tls_backend: TlsBackend,
    proxy_http1_only: bool,
) -> anyhow::Result<Client> {
    let mut builder = Client::builder().timeout(Duration::from_secs(timeout_secs));

    if proxy_http1_only {
        builder = builder.http1_only();
    }

    match tls_backend {
        TlsBackend::Rustls => {
            builder = builder.use_rustls_tls();
        }
        TlsBackend::NativeTls => {
            #[cfg(feature = "native-tls")]
            {
                builder = builder.use_native_tls();
            }
            #[cfg(not(feature = "native-tls"))]
            {
                anyhow::bail!("此构建版本未包含 native-tls 后端，请在配置中改用 rustls");
            }
        }
    }

    if let Some(proxy_config) = proxy {
        let mut proxy = Proxy::all(&proxy_config.url)?;

        // 设置代理认证
        if let (Some(username), Some(password)) = (&proxy_config.username, &proxy_config.password) {
            proxy = proxy.basic_auth(username, password);
        }

        builder = builder.proxy(proxy);
        tracing::debug!("HTTP Client 使用代理: {}", proxy_config.url);
    }

    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_new() {
        let config = ProxyConfig::new("http://127.0.0.1:7890");
        assert_eq!(config.url, "http://127.0.0.1:7890");
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_proxy_config_with_auth() {
        let config = ProxyConfig::new("socks5://127.0.0.1:1080").with_auth("user", "pass");
        assert_eq!(config.url, "socks5://127.0.0.1:1080");
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
    }

    #[test]
    fn test_build_client_without_proxy() {
        let client = build_client(None, 30, TlsBackend::Rustls);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_with_proxy() {
        let config = ProxyConfig::new("http://127.0.0.1:7890");
        let client = build_client(Some(&config), 30, TlsBackend::Rustls);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_api_client_with_proxy() {
        let config = ProxyConfig::new("socks5h://127.0.0.1:1080");
        assert!(build_api_client(Some(&config), 30, TlsBackend::Rustls).is_ok());
    }

    #[test]
    fn test_rotate_711proxy_session_only_changes_session_digits() {
        let config = ProxyConfig::new(
            "socks5h://USER-zone-custom-region-US-session-21330988-sessTime-180-sessAuto-1:pass@global.rotgb.711proxy.com:10000",
        );
        let rotated = config.rotate_711proxy_session().expect("711proxy session");
        assert!(rotated.url.contains("sessTime-180-sessAuto-1"));
        assert_ne!(rotated.url, config.url);
        assert!(rotated.url.contains("global.rotgb.711proxy.com:10000"));
    }

    #[test]
    fn test_rotate_711proxy_session_ignores_other_proxies() {
        let config = ProxyConfig::new("socks5h://proxy.example/session-123");
        assert!(config.rotate_711proxy_session().is_none());
    }
}
