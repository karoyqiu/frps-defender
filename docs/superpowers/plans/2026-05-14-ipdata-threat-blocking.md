# ipdata Threat-Based Dynamic ASN Blocking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ipdata.co threat detection to frps-defender so that IPs flagged as threats are blocked and their ASN route is persisted in SQLite to block future connections without re-querying the API.

**Architecture:** Static CIDR check runs first (unchanged), then a dynamic in-memory/SQLite block list, then an optional ipdata API call. On threat detection, the ASN route CIDR is written to SQLite and loaded into memory; subsequent connections from the same route hit step 2 and never reach the API. If ipdata is unconfigured or fails, the request falls through as allowed.

**Tech Stack:** Rust, axum 0.7, ipdata 0.1.1, rusqlite 0.32 (bundled), ipnet 2, tokio 1

---

### Task 1: Add Dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add ipdata and rusqlite to Cargo.toml**

Replace the `[dependencies]` section with:

```toml
[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ipnet = "2"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
ipdata = "0.1.1"
rusqlite = { version = "0.32", features = ["bundled"] }
```

- [ ] **Step 2: Verify deps resolve**

```bash
cargo build
```

Expected: compiles without errors (may be slow on first build — rusqlite bundles SQLite from source).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add ipdata and rusqlite dependencies"
```

---

### Task 2: Extend Config with ipdata and DB Fields

**Files:**
- Modify: `src/config.rs`

- [ ] **Step 1: Write failing tests for new config fields**

Add to the `#[cfg(test)] mod tests` block in `src/config.rs`:

```rust
#[test]
fn ipdata_api_key_loads_from_file() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, r#"{{"ipdata_api_key":"test-key-123"}}"#).unwrap();
    let config = Config::load(f.path(), true).unwrap();
    assert_eq!(config.ipdata_api_key.as_deref(), Some("test-key-123"));
}

#[test]
fn ipdata_api_key_defaults_to_none() {
    let path = Path::new("/nonexistent/path/config.json");
    let config = Config::load(path, false).unwrap();
    assert!(config.ipdata_api_key.is_none());
}

#[test]
fn db_path_defaults_correctly() {
    let path = Path::new("/nonexistent/path/config.json");
    let config = Config::load(path, false).unwrap();
    assert_eq!(config.db_path, "/var/tmp/frps-defender/blocks.db");
}

#[test]
fn db_path_loads_from_file() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, r#"{{"db_path":"/custom/path/blocks.db"}}"#).unwrap();
    let config = Config::load(f.path(), true).unwrap();
    assert_eq!(config.db_path, "/custom/path/blocks.db");
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test config
```

Expected: compile error — `Config` has no fields `ipdata_api_key` or `db_path`.

- [ ] **Step 3: Add fields to Config and update Default**

In `src/config.rs`, add the `default_db_path` function and update `Config` and its `Default` impl:

```rust
fn default_db_path() -> String {
    "/var/tmp/frps-defender/blocks.db".to_string()
}
```

Update the `Config` struct:

```rust
#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_block")]
    pub block: Vec<String>,
    #[serde(default)]
    pub proxies: HashMap<String, ProxyConfig>,
    pub ipdata_api_key: Option<String>,
    #[serde(default = "default_db_path")]
    pub db_path: String,
}
```

Update the `Default` impl:

```rust
impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            block: default_block(),
            proxies: HashMap::new(),
            ipdata_api_key: None,
            db_path: default_db_path(),
        }
    }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cargo test config
```

Expected: all config tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: add ipdata_api_key and db_path to Config"
```

---

### Task 3: Implement DynBlockStore

**Files:**
- Create: `src/dynblock.rs`
- Modify: `src/main.rs` (add `mod dynblock;`)

- [ ] **Step 1: Declare the module in main.rs**

Add `mod dynblock;` to `src/main.rs` after the existing module declarations:

```rust
mod config;
mod dynblock;
mod handler;
mod matcher;
mod ranges;
```

- [ ] **Step 2: Create src/dynblock.rs with failing tests only**

Create `src/dynblock.rs` with just the test module to confirm tests fail before implementation:

```rust
use anyhow::Result;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::sync::{Mutex, RwLock};

pub struct DynBlockStore {
    conn: Mutex<Connection>,
    nets: RwLock<Vec<IpNet>>,
}

impl DynBlockStore {
    pub fn open(path: &str) -> Result<Self> {
        todo!()
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        todo!()
    }

    pub fn add(&self, cidr: &str, asn: &str, asn_name: &str, reason: &str) -> Result<()> {
        todo!()
    }

    pub fn add_ephemeral(&self, ip: IpAddr) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory() -> DynBlockStore {
        DynBlockStore::open(":memory:").unwrap()
    }

    #[test]
    fn empty_store_allows_all() {
        let store = in_memory();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!store.is_blocked(ip));
    }

    #[test]
    fn add_route_blocks_ip_in_range() {
        let store = in_memory();
        store.add("1.2.3.0/24", "AS12345", "Test Corp", "threat detected").unwrap();
        assert!(store.is_blocked("1.2.3.99".parse().unwrap()));
        assert!(!store.is_blocked("1.2.4.1".parse().unwrap()));
    }

    #[test]
    fn add_ephemeral_blocks_exact_ip_only() {
        let store = in_memory();
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        store.add_ephemeral(ip);
        assert!(store.is_blocked("5.6.7.8".parse().unwrap()));
        assert!(!store.is_blocked("5.6.7.9".parse().unwrap()));
    }

    #[test]
    fn duplicate_add_is_idempotent() {
        let store = in_memory();
        store.add("10.0.0.0/8", "AS1", "Org", "threat").unwrap();
        store.add("10.0.0.0/8", "AS1", "Org", "threat").unwrap();
        assert!(store.is_blocked("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap().to_string();
        {
            let store = DynBlockStore::open(&path_str).unwrap();
            store.add("192.168.1.0/24", "AS99", "Private", "test").unwrap();
        }
        let store2 = DynBlockStore::open(&path_str).unwrap();
        assert!(store2.is_blocked("192.168.1.100".parse().unwrap()));
    }
}
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
cargo test dynblock
```

Expected: panics on `todo!()` — confirms tests are wired correctly.

- [ ] **Step 4: Implement DynBlockStore**

Replace the `impl DynBlockStore` block in `src/dynblock.rs` with:

```rust
impl DynBlockStore {
    pub fn open(path: &str) -> Result<Self> {
        if path != ":memory:" {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocked_routes (
                cidr      TEXT PRIMARY KEY,
                asn       TEXT NOT NULL,
                asn_name  TEXT NOT NULL,
                reason    TEXT NOT NULL,
                added_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        let nets: Vec<IpNet> = {
            let mut stmt = conn.prepare("SELECT cidr FROM blocked_routes")?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .filter_map(|cidr| cidr.parse().ok())
                .collect()
        };
        Ok(Self {
            conn: Mutex::new(conn),
            nets: RwLock::new(nets),
        })
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.nets.read().unwrap().iter().any(|net| net.contains(&ip))
    }

    pub fn add(&self, cidr: &str, asn: &str, asn_name: &str, reason: &str) -> Result<()> {
        let net: IpNet = cidr.parse()?;
        self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO blocked_routes (cidr, asn, asn_name, reason) \
             VALUES (?1, ?2, ?3, ?4)",
            params![cidr, asn, asn_name, reason],
        )?;
        self.nets.write().unwrap().push(net);
        Ok(())
    }

    pub fn add_ephemeral(&self, ip: IpAddr) {
        let net = match ip {
            IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 128).unwrap()),
        };
        self.nets.write().unwrap().push(net);
    }
}
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
cargo test dynblock
```

Expected: all 5 dynblock tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/dynblock.rs src/main.rs
git commit -m "feat: add DynBlockStore with SQLite-backed dynamic CIDR blocking"
```

---

### Task 4: Update AppState and Request Handler

**Files:**
- Modify: `src/handler.rs`

- [ ] **Step 1: Write failing tests for new handler behavior**

Add these two tests to the `#[cfg(test)] mod tests` block in `src/handler.rs`:

```rust
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test handler
```

Expected: compile errors — `AppState` missing `dynblock` and `ipdata` fields, `make_app` constructs old `Config`.

- [ ] **Step 3: Replace src/handler.rs with updated implementation**

Replace the entire contents of `src/handler.rs`:

```rust
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{config::Config, dynblock::DynBlockStore, matcher::Matcher};

pub struct AppState {
    pub config: Config,
    pub matcher: Matcher,
    pub dynblock: Arc<DynBlockStore>,
    pub ipdata: Option<Arc<ipdata::IpData>>,
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
        match ipdata_client.lookup(&ip.to_string()).await {
            Ok(info) => {
                let is_threat = info.threat.as_ref().map_or(false, |t| {
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
```

- [ ] **Step 4: Run all tests**

```bash
cargo test
```

Expected: all tests pass. If `ipdata::IpData` is not `Send + Sync`, the compiler will emit a clear error — check the ipdata crate docs for the correct wrapper type.

- [ ] **Step 5: Commit**

```bash
git add src/handler.rs
git commit -m "feat: add dynblock and ipdata threat check to handler pipeline"
```

---

### Task 5: Wire Everything in main.rs

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Update main.rs to initialize DynBlockStore and IpData client**

Replace the entire contents of `src/main.rs`:

```rust
mod config;
mod dynblock;
mod handler;
mod matcher;
mod ranges;

use axum::{routing::post, Router};
use clap::Parser;
use handler::AppState;
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_CONFIG: &str = "/etc/frps-defender/config.json";

#[derive(Parser)]
#[command(name = "frps-defender", about = "frp server plugin: block connections by IP range")]
struct Args {
    /// Path to JSON config file
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let config = match args.config {
        Some(path) => config::Config::load(&path, true)?,
        None => config::Config::load(&PathBuf::from(DEFAULT_CONFIG), false)?,
    };

    let listen: std::net::SocketAddr = config.listen.parse()?;
    let matcher = matcher::Matcher::build();
    let dynblock = Arc::new(dynblock::DynBlockStore::open(&config.db_path)?);
    let ipdata = config
        .ipdata_api_key
        .as_deref()
        .map(ipdata::IpData::new)
        .map(Arc::new);

    if ipdata.is_some() {
        tracing::info!("ipdata threat detection enabled");
    }

    let state = Arc::new(AppState { config, matcher, dynblock, ipdata });

    let app = Router::new()
        .route("/handler", post(handler::handle))
        .with_state(state);

    tracing::info!("listening on {}", listen);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

- [ ] **Step 2: Build release binary**

```bash
cargo build --release
```

Expected: compiles cleanly. Binary at `target/release/frps-defender`.

- [ ] **Step 3: Run full test suite**

```bash
cargo test
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire DynBlockStore and ipdata client into server startup"
```

---

## Self-Review

**Spec coverage:**
- ✅ ipdata crate used for threat detection
- ✅ Any threat flag triggers ASN route blocking
- ✅ SQLite persistence via DynBlockStore
- ✅ In-memory cache for fast per-request checks
- ✅ Fallback to current behavior on ipdata failure
- ✅ ASN absent → /32 memory-only
- ✅ Default db_path at `/var/tmp/frps-defender/blocks.db`
- ✅ API key via config file field

**Placeholder scan:** No TBDs, all code steps complete.

**Type consistency:**
- `DynBlockStore::open(path: &str)` used in Task 3, Task 4, Task 5 ✅
- `DynBlockStore::add(&str, &str, &str, &str) -> Result<()>` consistent across tasks ✅
- `DynBlockStore::add_ephemeral(IpAddr)` consistent ✅
- `AppState { config, matcher, dynblock, ipdata }` field names consistent across tasks ✅
- `Config { listen, block, proxies, ipdata_api_key, db_path }` consistent ✅
