use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{config::Config, dynblock::DynBlockStore, ipdata::IpDataClient, matcher::Matcher};

pub struct AppState {
    pub config: Config,
    pub matcher: Matcher,
    pub dynblock: Arc<DynBlockStore>,
    pub ipdata: Option<Arc<IpDataClient>>,
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

    // Step 1: static compile-time CIDR check
    let providers = state.config.providers_for(proxy_name);
    if let Some(provider) = state.matcher.is_blocked(ip, providers) {
        tracing::info!(proxy = proxy_name, ip = %ip, provider, "blocked");
        return Json(PluginResponse::block(format!("IP blocked: {}", provider)));
    }

    // Step 2: dynamic SQLite-backed block list
    if state.dynblock.is_blocked(ip) {
        tracing::info!(proxy = proxy_name, ip = %ip, "blocked by dynamic list");
        return Json(PluginResponse::block("IP blocked: dynamic"));
    }

    // Step 3: ipdata threat check (skipped if no API key configured)
    if let Some(ipdata_client) = &state.ipdata {
        match ipdata_client.lookup(ip).await {
            Ok(info) => {
                let is_threat = info.threat.as_ref().is_some_and(|t| {
                    t.is_tor
                        || t.is_proxy
                        || t.is_known_attacker
                        || t.is_known_abuser
                        || t.is_threat
                        || t.is_bogon
                });
                if is_threat {
                    match &info.asn {
                        Some(asn) if !asn.route.is_empty() => {
                            if let Err(e) = state.dynblock.add(
                                &asn.route,
                                &asn.asn,
                                &asn.name,
                                "threat detected",
                            ) {
                                tracing::error!(
                                    cidr = asn.route,
                                    error = %e,
                                    "failed to persist blocked route"
                                );
                            }
                        }
                        _ => {
                            state.dynblock.add_ephemeral(ip);
                        }
                    }
                    tracing::info!(proxy = proxy_name, ip = %ip, "blocked: threat detected");
                    return Json(PluginResponse::block("IP blocked: threat detected"));
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, ip = %ip, "ipdata lookup failed, allowing");
            }
        }
    }

    tracing::debug!(proxy = proxy_name, ip = %ip, "allowed");
    Json(PluginResponse::allow())
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
            ipdata_api_key: None,
            db_path: String::new(),
        };
        let state = Arc::new(AppState {
            config,
            matcher: Matcher::build(),
            dynblock: Arc::new(crate::dynblock::DynBlockStore::open(":memory:").unwrap()),
            ipdata: None,
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
            block: vec![],
            proxies,
            ipdata_api_key: None,
            db_path: String::new(),
        };
        let state = Arc::new(AppState {
            config,
            matcher: Matcher::build(),
            dynblock: Arc::new(crate::dynblock::DynBlockStore::open(":memory:").unwrap()),
            ipdata: None,
        });
        let app = Router::new().route("/handler", post(handle)).with_state(state);
        let body = r#"{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"restricted","proxy_type":"tcp","remote_addr":"10.0.0.1:12345","user":{}}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], true);
    }

    #[tokio::test]
    async fn dynblock_blocks_ip() {
        let dynblock = Arc::new(crate::dynblock::DynBlockStore::open(":memory:").unwrap());
        dynblock
            .add("203.0.113.0/24", "AS64496", "Test Net", "threat detected")
            .unwrap();
        let config = Config {
            listen: "127.0.0.1:7200".into(),
            block: vec![],
            proxies: HashMap::new(),
            ipdata_api_key: None,
            db_path: String::new(),
        };
        let state = Arc::new(AppState {
            config,
            matcher: Matcher::build(),
            dynblock,
            ipdata: None,
        });
        let app = Router::new().route("/handler", post(handle)).with_state(state);
        let body = r#"{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"test","proxy_type":"tcp","remote_addr":"203.0.113.50:12345","user":{}}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], true);
        assert_eq!(resp["reject_reason"], "IP blocked: dynamic");
    }

    #[tokio::test]
    async fn ipdata_none_allows_clean_ip() {
        let app = make_app(vec!["private".into()]);
        let body = r#"{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"test","proxy_type":"tcp","remote_addr":"8.8.8.8:12345","user":{}}}"#;
        let resp = post_json(app, body).await;
        assert_eq!(resp["reject"], false);
        assert_eq!(resp["unchange"], true);
    }
}
