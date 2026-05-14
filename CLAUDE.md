# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build                     # debug build
cargo build --release           # optimized + stripped binary (see profile.release in Cargo.toml)
cargo test                      # run all tests
cargo test config               # run tests in a specific module
cargo test handler::tests::blocks_private_ip  # run a single test by name

python3 scripts/fetch-ranges.py          # refresh all vendor IP range files
python3 scripts/fetch-ranges.py aws vpn  # refresh specific providers only
```

## Architecture

### Data pipeline (compile-time)

IP ranges are baked into the binary at compile time:

1. `vendor/caddy-defender/*.txt` — one CIDR per line, one file per provider (aws, cloudflare, gcloud, azure, github-copilot, openai, mistral, deepseek, digitalocean, linode, vultr, oci, aliyun, vpn, private)
2. `build.rs` reads these files and emits `$OUT_DIR/ranges.rs` containing `pub static AWS: &[&str]`, etc., plus a deduplicated `ALL` static
3. `src/ranges/mod.rs` exposes them via `include!(concat!(env!("OUT_DIR"), "/ranges.rs"))`

To update IP ranges: run `scripts/fetch-ranges.py` and commit the changed `.txt` files. The next `cargo build` picks them up automatically.

### Request flow

```
frps → POST /handler → handler::handle
         │
         ├─ op != "NewUserConn" → allow (unchange: true)
         ├─ invalid remote_addr → reject ("invalid remote address")
         ├─ 1. matcher::Matcher::is_blocked(ip, providers)   ← static compile-time CIDRs
         │        └─ match → reject ("IP blocked: <provider>")
         ├─ 2. DynBlockStore::is_blocked(ip)                 ← dynamic SQLite-backed CIDRs
         │        └─ match → reject ("IP blocked: dynamic")
         └─ 3. ipdata::IpData::lookup(ip)                    ← threat check (if api key set)
                   ├─ threat=true, asn present → add asn.route to SQLite+memory → reject
                   ├─ threat=true, asn absent  → add /32 to memory only → reject
                   ├─ threat=false → allow (unchange: true)
                   └─ error → warn, allow (unchange: true)
```

`AppState` (in `handler.rs`) holds `Config`, `Matcher`, `Arc<DynBlockStore>`, and `Option<Arc<ipdata::IpData>>` shared across all requests.

### Config resolution

`Config::providers_for(proxy_name)` returns the per-proxy block list if configured, otherwise the global `block` list. Default: `["all"]` (blocks every embedded provider).

Config file is optional; missing default path (`/etc/frps-defender/config.json`) → use defaults. Missing explicit `--config` path → error.

### Config example

```json
{
  "listen": "0.0.0.0:7200",
  "block": ["all"],
  "ipdata_api_key": "your-key-here",
  "db_path": "/var/tmp/frps-defender/blocks.db",
  "proxies": {
    "ssh-proxy": {
      "block": ["private"]
    }
  }
}
```

`ipdata_api_key` — optional; omit to disable threat detection. `db_path` — defaults to `/var/tmp/frps-defender/blocks.db` (writable by `nobody`).

### Provider names

Valid values for `block` arrays: `all`, `aws`, `cloudflare`, `gcloud`, `azure`, `github-copilot`, `openai`, `mistral`, `deepseek`, `digitalocean`, `linode`, `vultr`, `oci`, `aliyun`, `vpn`, `private`. `all` is the deduplicated union of all others.

### frps configuration

```ini
[plugin.defender]
addr = 127.0.0.1:7200
path = /handler
ops = NewUserConn
```
