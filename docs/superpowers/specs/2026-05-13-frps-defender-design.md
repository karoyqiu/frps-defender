# frps-defender Design Spec

**Date:** 2026-05-13  
**Status:** Approved

## Overview

`frps-defender` is a Rust binary that acts as an frp server plugin. It intercepts `NewUserConn` hooks from frps and rejects connections whose source IP matches a configured set of provider IP ranges. IP ranges are embedded at compile time from caddy-defender's pre-generated data.

## Architecture

```
frps  →  POST /handler  →  frps-defender (axum HTTP server)
                                │
                         load config.json (optional)
                                │
                         match proxy_name → block list
                                │
                         check remote_addr against
                         embedded CIDR sets
                                │
                         { reject: true/false }  →  frps
```

### Components

| File | Responsibility |
|---|---|
| `src/main.rs` | Startup: load config, build IP sets, start axum server |
| `src/config.rs` | JSON config structs with defaults |
| `src/handler.rs` | Axum route: parse frp request, resolve block list, return verdict |
| `src/matcher.rs` | IP-in-CIDR lookup using `ipnet::IpNet` |
| `src/ranges/mod.rs` | Generated static CIDR arrays, one per provider |
| `build.rs` | Codegen: converts vendored caddy-defender data into Rust source |

### Key Crates

- `axum` + `tokio` — async HTTP server
- `serde` + `serde_json` — JSON ser/de
- `ipnet` — CIDR parsing and matching
- `tracing` — structured logging

## Config Schema

Config file is optional. If absent, all defaults apply. All fields are optional.

```json
{
  "listen": "127.0.0.1:7200",
  "block": ["all"],
  "proxies": {
    "ssh-proxy": {
      "block": ["aws", "cloudflare"]
    },
    "web-proxy": {
      "block": ["openai", "mistral", "vpn"]
    }
  }
}
```

### Fields

| Field | Default | Description |
|---|---|---|
| `listen` | `"127.0.0.1:7200"` | Address frps-defender binds to |
| `block` | `["all"]` | Global fallback provider list |
| `proxies` | `{}` | Per-proxy overrides; if proxy name absent, global applies |

### Provider Keys

`all`, `aws`, `azure`, `cloudflare`, `gcloud`, `github-copilot`, `openai`, `mistral`, `deepseek`, `digitalocean`, `linode`, `vultr`, `oci`, `aliyun`, `vpn`, `private`

`"all"` = union of all embedded provider sets.

## Data Pipeline

### Build-time Codegen (`build.rs`)

caddy-defender pre-generated IP range data is vendored into `vendor/caddy-defender/` (committed to repo). `build.rs` reads these files and emits Rust source:

```rust
// generated, do not edit
pub static AWS: &[&str] = &["3.2.34.0/26", "3.5.140.0/22", ...];
pub static CLOUDFLARE: &[&str] = &["103.21.244.0/22", ...];
pub static ALL: &[&str] = &[/* union of all */];
```

### Runtime Startup

At startup, `matcher.rs` parses the `&str` slices into `Vec<IpNet>` once and stores in `Arc<HashMap<Provider, Vec<IpNet>>>` shared across handler threads.

### Lookup Path (per request)

1. Parse `remote_addr` from frp JSON → `IpAddr` (strip port)
2. Resolve proxy name → provider list (per-proxy config or global fallback)
3. For each provider, check IP against `Vec<IpNet>` (linear scan)
4. Any match → reject

## HTTP Handler

frp sends `NewUserConn` to `POST /handler`:

```json
{
  "version": "0.1.0",
  "op": "NewUserConn",
  "content": {
    "user": { "user": "...", "metas": {}, "run_id": "..." },
    "proxy_name": "ssh-proxy",
    "proxy_type": "tcp",
    "remote_addr": "1.2.3.4:12345"
  }
}
```

### Response Logic

| Condition | Response |
|---|---|
| IP matches blocked provider | `{ "reject": true, "reject_reason": "IP blocked: <provider>" }` |
| IP not blocked | `{ "reject": false, "unchange": true }` |
| Non-`NewUserConn` op | `{ "reject": false, "unchange": true }` |
| Unparseable `remote_addr` | `{ "reject": true, "reject_reason": "invalid remote address" }` |

## frps Configuration Example

```ini
[plugin.defender]
addr = 127.0.0.1:7200
path = /handler
ops = NewUserConn
```

## Out of Scope (Stage 1)

- Auth token validation
- Live IP range fetching from provider APIs
- Hot config reload
- Per-proxy reject reasons distinct from global
