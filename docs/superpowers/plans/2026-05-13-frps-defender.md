# frps-defender Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust binary that acts as an frp server plugin, blocking `NewUserConn` requests whose source IP matches embedded provider CIDR ranges.

**Architecture:** Single binary with IP ranges baked in at compile time via `build.rs` codegen from vendored plain-text files. An axum HTTP server handles frp plugin hooks; per-proxy block lists fall back to a global default. Config is optional JSON.

**Tech Stack:** Rust 2021, axum 0.7, tokio 1, serde_json, ipnet 2, clap 4, tracing, anyhow

---

## Task 1: Initialize Cargo project

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs` (stub)
- Create: `src/ranges/mod.rs` (stub)

- [ ] **Step 1: Write Cargo.toml**

```toml
[package]
name = "frps-defender"
version = "0.1.0"
edition = "2021"

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

[dev-dependencies]
tower = { version = "0.4", features = ["util"] }
http-body-util = "0.1"
```

- [ ] **Step 2: Write stub main.rs**

```rust
fn main() {}
```

- [ ] **Step 3: Create ranges module stub**

`src/ranges/mod.rs`:
```rust
// populated by build.rs codegen
```

- [ ] **Step 4: Create directory structure**

```bash
mkdir -p vendor/caddy-defender scripts
```

- [ ] **Step 5: Verify it compiles**

```bash
cargo build
```

Expected: compiled successfully (no warnings about missing files yet).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs src/ranges/mod.rs
git commit -m "feat: initialize Cargo project"
```

---

## Task 2: Vendor IP range data

**Files:**
- Create: `scripts/fetch-ranges.py`
- Create: `vendor/caddy-defender/*.txt` (15 files, committed)

- [ ] **Step 1: Write fetch-ranges.py**

`scripts/fetch-ranges.py`:
```python
#!/usr/bin/env python3
"""Fetch IP ranges from cloud providers → vendor/caddy-defender/<name>.txt"""

import csv
import io
import json
import os
import sys
import urllib.request

VENDOR_DIR = os.path.join(os.path.dirname(__file__), "..", "vendor", "caddy-defender")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "frps-defender/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8")


def save(name, ranges):
    os.makedirs(VENDOR_DIR, exist_ok=True)
    path = os.path.join(VENDOR_DIR, f"{name}.txt")
    unique = sorted(set(r.strip() for r in ranges if r.strip()))
    with open(path, "w") as f:
        f.write("\n".join(unique) + ("\n" if unique else ""))
    print(f"  {name}: {len(unique)} ranges")


def fetch_aws():
    data = json.loads(fetch("https://ip-ranges.amazonaws.com/ip-ranges.json"))
    ranges = [p["ip_prefix"] for p in data["prefixes"]]
    ranges += [p["ipv6_prefix"] for p in data["ipv6_prefixes"]]
    save("aws", ranges)


def fetch_cloudflare():
    data = json.loads(fetch("https://api.cloudflare.com/client/v4/ips"))
    ranges = data["result"]["ipv4_cidrs"] + data["result"]["ipv6_cidrs"]
    save("cloudflare", ranges)


def fetch_gcloud():
    data = json.loads(fetch("https://www.gstatic.com/ipranges/cloud.json"))
    ranges = []
    for p in data["prefixes"]:
        if "ipv4Prefix" in p:
            ranges.append(p["ipv4Prefix"])
        if "ipv6Prefix" in p:
            ranges.append(p["ipv6Prefix"])
    save("gcloud", ranges)


def fetch_azure():
    # Azure scraping is complex and URL changes periodically; empty for stage 1.
    save("azure", [])


def fetch_github_copilot():
    data = json.loads(fetch("https://api.github.com/meta"))
    save("github-copilot", data.get("copilot", []))


def fetch_openai():
    ranges = []
    for url in [
        "https://openai.com/searchbot.json",
        "https://openai.com/chatgpt-user.json",
        "https://openai.com/gptbot.json",
    ]:
        try:
            data = json.loads(fetch(url))
            ranges += [p["ipv4Prefix"] for p in data.get("prefixes", [])]
        except Exception as e:
            print(f"  Warning: {url}: {e}")
    save("openai", ranges)


def fetch_mistral():
    data = json.loads(fetch("https://mistral.ai/mistralai-user-ips.json"))
    save("mistral", [p["ipv4Prefix"] for p in data.get("prefixes", [])])


def fetch_deepseek():
    save("deepseek", ["34.170.163.122/32", "34.66.5.13/32", "34.172.162.205/32"])


def fetch_digitalocean():
    content = fetch("https://digitalocean.com/geo/google.csv")
    reader = csv.reader(io.StringIO(content))
    save("digitalocean", [row[0] for row in reader if row and not row[0].startswith("#")])


def fetch_linode():
    content = fetch("https://geoip.linode.com/")
    ranges = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ranges.append(line.split(",")[0].strip())
    save("linode", ranges)


def fetch_vultr():
    data = json.loads(fetch("https://geofeed.constant.com/?json"))
    save("vultr", [s["ip_prefix"] for s in data.get("subnets", [])])


def fetch_oci():
    data = json.loads(fetch("https://docs.oracle.com/iaas/tools/public_ip_ranges.json"))
    ranges = []
    for region in data.get("regions", []):
        for cidr in region.get("cidrs", []):
            ranges.append(cidr["cidr"])
    save("oci", ranges)


def fetch_aliyun():
    content = fetch(
        "https://cdn.jsdelivr.net/gh/sakib-m/IP-Prefix-List@main/ALIBABA/only_ip_blocks.txt"
    )
    ranges = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ranges.append(line.split(",")[0].strip())
    save("aliyun", ranges)


def fetch_vpn():
    content = fetch(
        "https://cdn.jsdelivr.net/gh/X4BNet/lists_vpn@main/output/vpn/ipv4.txt"
    )
    save("vpn", [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")])


def fetch_private():
    save("private", [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ])


FETCHERS = {
    "aws": fetch_aws,
    "cloudflare": fetch_cloudflare,
    "gcloud": fetch_gcloud,
    "azure": fetch_azure,
    "github-copilot": fetch_github_copilot,
    "openai": fetch_openai,
    "mistral": fetch_mistral,
    "deepseek": fetch_deepseek,
    "digitalocean": fetch_digitalocean,
    "linode": fetch_linode,
    "vultr": fetch_vultr,
    "oci": fetch_oci,
    "aliyun": fetch_aliyun,
    "vpn": fetch_vpn,
    "private": fetch_private,
}

if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else list(FETCHERS)
    for name in targets:
        if name not in FETCHERS:
            print(f"Unknown provider: {name}", file=sys.stderr)
            continue
        print(f"Fetching {name}...")
        try:
            FETCHERS[name]()
        except Exception as e:
            print(f"  Error: {e}")
```

- [ ] **Step 2: Run the script**

```bash
python3 scripts/fetch-ranges.py
```

Expected: 15 lines like `Fetching aws... aws: 7523 ranges`. Some providers may warn — that's OK as long as the files are created.

- [ ] **Step 3: Verify files exist**

```bash
ls vendor/caddy-defender/
```

Expected: 15 `.txt` files (aws.txt, cloudflare.txt, etc.). Each should have at least a few lines (except azure.txt which will be empty).

- [ ] **Step 4: Commit**

```bash
git add scripts/fetch-ranges.py vendor/caddy-defender/
git commit -m "feat: add IP range fetch script and vendor data"
```

---

## Task 3: Build script codegen

**Files:**
- Create: `build.rs`
- Modify: `src/ranges/mod.rs`

- [ ] **Step 1: Write build.rs**

```rust
use std::{env, fs, io::Write, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=vendor/caddy-defender/");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("ranges.rs");
    let mut out = fs::File::create(&dest).unwrap();

    let providers: &[(&str, &str)] = &[
        ("AWS", "aws"),
        ("CLOUDFLARE", "cloudflare"),
        ("GCLOUD", "gcloud"),
        ("AZURE", "azure"),
        ("GITHUB_COPILOT", "github-copilot"),
        ("OPENAI", "openai"),
        ("MISTRAL", "mistral"),
        ("DEEPSEEK", "deepseek"),
        ("DIGITALOCEAN", "digitalocean"),
        ("LINODE", "linode"),
        ("VULTR", "vultr"),
        ("OCI", "oci"),
        ("ALIYUN", "aliyun"),
        ("VPN", "vpn"),
        ("PRIVATE", "private"),
    ];

    let mut all: Vec<String> = Vec::new();

    for (const_name, file_name) in providers {
        let path = format!("vendor/caddy-defender/{}.txt", file_name);
        let content = fs::read_to_string(&path).unwrap_or_default();
        let ranges: Vec<&str> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        writeln!(
            out,
            "pub static {}: &[&str] = &[{}];",
            const_name,
            ranges
                .iter()
                .map(|r| format!("\"{}\"", r))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();

        all.extend(ranges.iter().map(|r| r.to_string()));
    }

    all.sort();
    all.dedup();

    writeln!(
        out,
        "pub static ALL: &[&str] = &[{}];",
        all.iter()
            .map(|r| format!("\"{}\"", r))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .unwrap();
}
```

- [ ] **Step 2: Update src/ranges/mod.rs**

```rust
include!(concat!(env!("OUT_DIR"), "/ranges.rs"));
```

- [ ] **Step 3: Verify build generates ranges**

```bash
cargo build 2>&1 | head -5
```

Expected: compiles without errors. No output means success.

- [ ] **Step 4: Spot-check generated file**

```bash
grep -c '"' $(cargo metadata --format-version 1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['target_directory'])")/debug/build/frps-defender-*/out/ranges.rs | head -3
```

Or simply: `cargo build` succeeds and you can reference `crate::ranges::AWS` without errors.

- [ ] **Step 5: Commit**

```bash
git add build.rs src/ranges/mod.rs
git commit -m "feat: add build.rs codegen for embedded IP ranges"
```

---

## Task 4: Config module

**Files:**
- Create: `src/config.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/config.rs`:

```rust
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

fn default_listen() -> String {
    "127.0.0.1:7200".into()
}

fn default_block() -> Vec<String> {
    vec!["all".into()]
}

#[derive(Deserialize)]
pub struct ProxyConfig {
    pub block: Vec<String>,
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_block")]
    pub block: Vec<String>,
    #[serde(default)]
    pub proxies: HashMap<String, ProxyConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            block: default_block(),
            proxies: HashMap::new(),
        }
    }
}

impl Config {
    /// Load from path. If path does not exist and `required` is false, returns defaults.
    /// If `required` is true and file is missing, returns an error.
    pub fn load(path: &Path, required: bool) -> anyhow::Result<Self> {
        if !path.exists() {
            if required {
                anyhow::bail!("config file not found: {}", path.display());
            }
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Return the provider block list for a proxy, falling back to global.
    pub fn providers_for(&self, proxy_name: &str) -> &[String] {
        self.proxies
            .get(proxy_name)
            .map(|p| p.block.as_slice())
            .unwrap_or(self.block.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;  // add tempfile to dev-dependencies

    #[test]
    fn defaults_when_file_absent() {
        let path = Path::new("/nonexistent/path/config.json");
        let config = Config::load(path, false).unwrap();
        assert_eq!(config.listen, "127.0.0.1:7200");
        assert_eq!(config.block, vec!["all"]);
        assert!(config.proxies.is_empty());
    }

    #[test]
    fn error_when_required_file_absent() {
        let path = Path::new("/nonexistent/path/config.json");
        assert!(Config::load(path, true).is_err());
    }

    #[test]
    fn loads_from_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"listen":"0.0.0.0:8000","block":["aws","cloudflare"]}}"#).unwrap();
        let config = Config::load(f.path(), true).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8000");
        assert_eq!(config.block, vec!["aws", "cloudflare"]);
    }

    #[test]
    fn per_proxy_fallback() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"block":["aws"],"proxies":{{"ssh":{{"block":["vpn"]}}}}}}"#).unwrap();
        let config = Config::load(f.path(), true).unwrap();
        assert_eq!(config.providers_for("ssh"), &["vpn"]);
        assert_eq!(config.providers_for("other"), &["aws"]);
    }
}
```

- [ ] **Step 2: Add tempfile to dev-dependencies in Cargo.toml**

```toml
[dev-dependencies]
tempfile = "3"
tower = { version = "0.4", features = ["util"] }
http-body-util = "0.1"
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cargo test config
```

Expected: compile error — `config` module not declared in `main.rs`.

- [ ] **Step 4: Add mod declaration to main.rs**

```rust
mod config;
mod ranges;

fn main() {}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test config
```

Expected:
```
test config::tests::defaults_when_file_absent ... ok
test config::tests::error_when_required_file_absent ... ok
test config::tests::loads_from_file ... ok
test config::tests::per_proxy_fallback ... ok
```

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/config.rs src/main.rs
git commit -m "feat: add config module with JSON loading and defaults"
```

---

## Task 5: Matcher module

**Files:**
- Create: `src/matcher.rs`

- [ ] **Step 1: Write the failing test**

`src/matcher.rs`:

```rust
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

fn provider_strs(name: &str) -> Option<&'static [&'static str]> {
    use crate::ranges;
    match name {
        "aws" => Some(ranges::AWS),
        "cloudflare" => Some(ranges::CLOUDFLARE),
        "gcloud" => Some(ranges::GCLOUD),
        "azure" => Some(ranges::AZURE),
        "github-copilot" => Some(ranges::GITHUB_COPILOT),
        "openai" => Some(ranges::OPENAI),
        "mistral" => Some(ranges::MISTRAL),
        "deepseek" => Some(ranges::DEEPSEEK),
        "digitalocean" => Some(ranges::DIGITALOCEAN),
        "linode" => Some(ranges::LINODE),
        "vultr" => Some(ranges::VULTR),
        "oci" => Some(ranges::OCI),
        "aliyun" => Some(ranges::ALIYUN),
        "vpn" => Some(ranges::VPN),
        "private" => Some(ranges::PRIVATE),
        "all" => Some(ranges::ALL),
        _ => None,
    }
}

pub struct Matcher {
    ranges: HashMap<String, Vec<IpNet>>,
}

impl Matcher {
    pub fn build() -> Self {
        let names = [
            "aws", "cloudflare", "gcloud", "azure", "github-copilot",
            "openai", "mistral", "deepseek", "digitalocean", "linode",
            "vultr", "oci", "aliyun", "vpn", "private", "all",
        ];

        let mut ranges: HashMap<String, Vec<IpNet>> = HashMap::new();
        for name in names {
            if let Some(strs) = provider_strs(name) {
                let nets = strs.iter().filter_map(|s| s.parse().ok()).collect();
                ranges.insert(name.to_string(), nets);
            }
        }

        Self { ranges }
    }

    /// Returns the name of the first matching provider, or None if not blocked.
    pub fn is_blocked<'a>(&self, ip: IpAddr, providers: &'a [String]) -> Option<&'a str> {
        for provider in providers {
            if let Some(nets) = self.ranges.get(provider.as_str()) {
                if nets.iter().any(|net| net.contains(ip)) {
                    return Some(provider.as_str());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher() -> Matcher {
        Matcher::build()
    }

    fn providers(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn private_ip_blocked_by_private_provider() {
        let m = matcher();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(m.is_blocked(ip, &providers(&["private"])).is_some());
    }

    #[test]
    fn private_ip_blocked_by_all_provider() {
        let m = matcher();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(m.is_blocked(ip, &providers(&["all"])).is_some());
    }

    #[test]
    fn public_ip_not_blocked_by_private_provider() {
        let m = matcher();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(m.is_blocked(ip, &providers(&["private"])).is_none());
    }

    #[test]
    fn unknown_provider_does_not_block() {
        let m = matcher();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(m.is_blocked(ip, &providers(&["nonexistent"])).is_none());
    }

    #[test]
    fn returns_first_matching_provider_name() {
        let m = matcher();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let result = m.is_blocked(ip, &providers(&["aws", "private"]));
        assert_eq!(result, Some("private"));
    }

    #[test]
    fn empty_providers_never_blocks() {
        let m = matcher();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(m.is_blocked(ip, &[]).is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test matcher
```

Expected: compile error — `matcher` module not declared.

- [ ] **Step 3: Add mod declaration to main.rs**

```rust
mod config;
mod matcher;
mod ranges;

fn main() {}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test matcher
```

Expected:
```
test matcher::tests::private_ip_blocked_by_private_provider ... ok
test matcher::tests::private_ip_blocked_by_all_provider ... ok
test matcher::tests::public_ip_not_blocked_by_private_provider ... ok
test matcher::tests::unknown_provider_does_not_block ... ok
test matcher::tests::returns_first_matching_provider_name ... ok
test matcher::tests::empty_providers_never_blocks ... ok
```

- [ ] **Step 5: Commit**

```bash
git add src/matcher.rs src/main.rs
git commit -m "feat: add matcher module with IP-in-CIDR lookup"
```

---

## Task 6: Handler module

**Files:**
- Create: `src/handler.rs`

- [ ] **Step 1: Write the handler**

`src/handler.rs`:

```rust
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
        Some(provider) => Json(PluginResponse::block(format!("IP blocked: {}", provider))),
        None => Json(PluginResponse::allow()),
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
}
```

- [ ] **Step 2: Add mod declaration to main.rs**

```rust
mod config;
mod handler;
mod matcher;
mod ranges;

fn main() {}
```

- [ ] **Step 3: Run handler tests**

```bash
cargo test handler
```

Expected:
```
test handler::tests::blocks_private_ip ... ok
test handler::tests::allows_public_ip ... ok
test handler::tests::passes_through_non_newuserconn_ops ... ok
test handler::tests::rejects_invalid_remote_addr ... ok
```

- [ ] **Step 4: Commit**

```bash
git add src/handler.rs src/main.rs
git commit -m "feat: add handler module with axum route and response logic"
```

---

## Task 7: Main entry point

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Write main.rs**

```rust
mod config;
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
    let state = Arc::new(AppState { config, matcher });

    let app = Router::new()
        .route("/handler", post(handler::handle))
        .with_state(state);

    tracing::info!("listening on {}", listen);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

- [ ] **Step 2: Build and verify**

```bash
cargo build --release 2>&1
```

Expected: `Finished release [optimized]` with no errors.

- [ ] **Step 3: Verify CLI help works**

```bash
./target/release/frps-defender --help
```

Expected:
```
frp server plugin: block connections by IP range

Usage: frps-defender [OPTIONS]

Options:
      --config <CONFIG>  Path to JSON config file
  -h, --help             Print help
```

- [ ] **Step 4: Run all tests**

```bash
cargo test
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: add main entry point with clap CLI and axum server"
```

---

## Task 8: Systemd service file

**Files:**
- Create: `frps-defender.service`

- [ ] **Step 1: Write the unit file**

`frps-defender.service`:
```ini
[Unit]
Description=frps-defender IP blocking plugin
After=network.target frps.service

[Service]
Type=simple
ExecStart=/usr/local/bin/frps-defender --config /etc/frps-defender/config.json
Restart=on-failure
RestartSec=5s
User=nobody
Group=nobody

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write example config**

`config.example.json`:
```json
{
  "listen": "127.0.0.1:7200",
  "block": ["all"],
  "proxies": {
    "ssh-proxy": {
      "block": ["aws", "cloudflare", "vpn"]
    }
  }
}
```

- [ ] **Step 3: Commit**

```bash
git add frps-defender.service config.example.json
git commit -m "feat: add systemd service unit and example config"
```

---

## Deployment Reference

```bash
# Build
cargo build --release
sudo cp target/release/frps-defender /usr/local/bin/

# Config
sudo mkdir -p /etc/frps-defender
sudo cp config.example.json /etc/frps-defender/config.json

# Service
sudo cp frps-defender.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now frps-defender
```

frp server config (`frps.toml` or `frps.ini`):
```ini
[plugin.defender]
addr = 127.0.0.1:7200
path = /handler
ops = NewUserConn
```
