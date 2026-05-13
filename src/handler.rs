use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{config::Config, matcher::Matcher};

pub struct AppState {
    pub config: Config,
    pub matcher: Matcher,
}

#[derive(Deserialize)]
pub struct PluginRequest {
    pub op: String,
    pub content: serde_json::Value,
}

#[derive(Serialize)]
pub struct PluginResponse {
    pub reject: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unchange: Option<bool>,
}

impl PluginResponse {
    fn allow() -> Self {
        Self { reject: false, reject_reason: None, unchange: Some(true) }
    }

    fn block(reason: impl Into<String>) -> Self {
        Self { reject: true, reject_reason: Some(reason.into()), unchange: None }
    }
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PluginRequest>,
) -> Json<PluginResponse> {
    if req.op != "NewUserConn" {
        return Json(PluginResponse::allow());
    }

    let proxy_name = req.content["proxy_name"].as_str().unwrap_or("");
    let remote_addr = req.content["remote_addr"].as_str().unwrap_or("");

    let ip = match remote_addr.parse::<SocketAddr>() {
        Ok(addr) => addr.ip(),
        Err(_) => return Json(PluginResponse::block("invalid remote address")),
    };

    let providers = state.config.providers_for(proxy_name);

    match state.matcher.is_blocked(ip, providers) {
        Some(provider) => {
            tracing::info!(proxy = proxy_name, ip = %ip, provider, "blocked");
            Json(PluginResponse::block(format!("IP blocked: {}", provider)))
        }
        None => {
            tracing::debug!(proxy = proxy_name, ip = %ip, "allowed");
            Json(PluginResponse::allow())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::{body::Body, http::Request, routing::post, Router};
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn make_app(block: Vec<String>) -> Router {
        let config = Config {
            listen: "127.0.0.1:7200".into(),
            block,
            proxies: HashMap::new(),
        };
        let state = Arc::new(AppState {
            config,
            matcher: Matcher::build(),
        });
        Router::new().route("/handler", post(handle)).with_state(state)
    }

    async fn post_json(app: Router, body: &str) -> serde_json::Value {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/handler")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn blocks_private_ip() {
        let app = make_app(vec!["private".into()]);
        let body = r#"{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"test","proxy_type":"tcp","remote_addr":"10.0.0.1:12345","user":{}}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], true);
        assert!(resp["reject_reason"].as_str().unwrap().contains("blocked"));
    }

    #[tokio::test]
    async fn allows_public_ip() {
        let app = make_app(vec!["private".into()]);
        let body = r#"{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"test","proxy_type":"tcp","remote_addr":"8.8.8.8:12345","user":{}}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], false);
        assert_eq!(resp["unchange"], true);
    }

    #[tokio::test]
    async fn passes_through_non_newuserconn_ops() {
        let app = make_app(vec!["all".into()]);
        let body = r#"{"version":"0.1.0","op":"Login","content":{"client_address":"10.0.0.1:999"}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], false);
        assert_eq!(resp["unchange"], true);
    }

    #[tokio::test]
    async fn rejects_invalid_remote_addr() {
        let app = make_app(vec!["private".into()]);
        let body = r#"{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"test","proxy_type":"tcp","remote_addr":"not-an-ip","user":{}}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], true);
        assert_eq!(resp["reject_reason"], "invalid remote address");
    }

    #[tokio::test]
    async fn per_proxy_override_blocks_ip() {
        use crate::config::ProxyConfig;
        let mut proxies = HashMap::new();
        proxies.insert(
            "restricted".to_string(),
            ProxyConfig { block: vec!["private".into()] },
        );
        let config = Config {
            listen: "127.0.0.1:7200".into(),
            block: vec![],  // global allows everything
            proxies,
        };
        let state = Arc::new(AppState {
            config,
            matcher: Matcher::build(),
        });
        let app = Router::new().route("/handler", post(handle)).with_state(state);
        let body = r#"{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"restricted","proxy_type":"tcp","remote_addr":"10.0.0.1:12345","user":{}}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], true);
    }
}
