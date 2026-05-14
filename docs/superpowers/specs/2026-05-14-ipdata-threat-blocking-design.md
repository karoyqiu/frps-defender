# ipdata Threat-Based Dynamic ASN Blocking

**Date:** 2026-05-14
**Status:** Approved

## Overview

Add a second IP-checking layer using the `ipdata` crate. When any threat flag is true for an incoming IP, add the ASN route (CIDR) to a persistent dynamic block list backed by SQLite. Future connections from that entire route are blocked without hitting the ipdata API again. If ipdata is unavailable, fall back to existing static CIDR behavior.

## Dependencies

```toml
ipdata = "0.1.1"
rusqlite = { version = "0.32", features = ["bundled"] }
```

## New Files

- `src/dynblock.rs` — SQLite-backed dynamic block store

## Modified Files

- `src/config.rs` — add `ipdata_api_key`, `db_path`
- `src/handler.rs` — 3-step pipeline, ipdata client in AppState
- `src/main.rs` — init DynBlockStore and IpData client

## Configuration

New optional fields in `config.json`:

```json
{
  "ipdata_api_key": "your-key-here",
  "db_path": "/var/tmp/frps-defender/blocks.db"
}
```

- `ipdata_api_key`: if absent, ipdata check is skipped entirely
- `db_path`: defaults to `/var/tmp/frps-defender/blocks.db`

## Data Model

### SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS blocked_routes (
    cidr      TEXT PRIMARY KEY,
    asn       TEXT NOT NULL,
    asn_name  TEXT NOT NULL,
    reason    TEXT NOT NULL,
    added_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### DynBlockStore

```rust
pub struct DynBlockStore {
    conn: Mutex<rusqlite::Connection>,  // writes only
    nets: RwLock<Vec<IpNet>>,           // in-memory reads, no DB hit per request
}
```

**Startup:** open/create DB, create table if not exists, load all `cidr` rows into `nets`.

**`is_blocked(ip)`:** read-locks `nets`, iterates `IpNet::contains(ip)`. Pure memory.

**`add(cidr, asn, asn_name, reason)`:** inserts into SQLite (via `spawn_blocking`) then pushes parsed `IpNet` to `nets`.

**`add_ephemeral(ip)`:** synthesizes `/32` or `/128` from IP, pushes to `nets` only — no DB write.

## AppState

```rust
pub struct AppState {
    pub config: Arc<Config>,
    pub matcher: Matcher,
    pub dynblock: Arc<DynBlockStore>,
    pub ipdata: Option<Arc<ipdata::IpData>>,
}
```

## Request Flow

```
POST /handler
  │
  ├─ op != "NewUserConn"           → allow
  ├─ invalid remote_addr           → reject("invalid remote address")
  │
  ├─ 1. matcher.is_blocked()       ← static compile-time CIDRs (existing)
  │      └─ match → reject("IP blocked: <provider>")
  │
  ├─ 2. dynblock.is_blocked()      ← dynamic SQLite-backed CIDRs (new)
  │      └─ match → reject("IP blocked: dynamic")
  │
  └─ 3. ipdata configured?
         ipdata.lookup(ip.to_string()).await
           ├─ Ok(info), threat=true, asn present
           │    dynblock.add(asn.route, asn.asn, asn.name, reason) → reject("IP blocked: threat detected")
           ├─ Ok(info), threat=true, asn absent
           │    dynblock.add_ephemeral(ip)                          → reject("IP blocked: threat detected")
           ├─ Ok(info), threat=false → allow
           └─ Err(_) → warn log, allow (fallback to static result)
```

## Threat Detection

Threat is true if any of the following flags are set on `ipdata::Threat`:

```rust
info.threat.is_tor
  || info.threat.is_proxy
  || info.threat.is_known_attacker
  || info.threat.is_known_abuser
  || info.threat.is_threat
  || info.threat.is_bogon
```

## Error Handling

| Scenario | Behavior |
|---|---|
| `ipdata_api_key` not configured | Skip ipdata check, allow if static checks pass |
| ipdata API error / timeout | Log warn, allow (static result stands) |
| `asn` field absent in response | Block IP, add /32 to memory only (not DB) |
| SQLite write fails | Log error, IP still blocked in-memory for session |
| DB path not writable | Fail fast at startup with clear error |

## Testing

- Unit test `DynBlockStore`: add route, verify `is_blocked`, verify SQLite row exists
- Unit test `add_ephemeral`: verify /32 in memory, not in DB
- Integration test handler: mock ipdata response with threat=true, verify reject + route added
- Integration test fallback: simulate ipdata error, verify allow returned
