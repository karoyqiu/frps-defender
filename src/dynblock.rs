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
            let collected: Vec<IpNet> = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .filter_map(|cidr| cidr.parse().ok())
                .collect();
            collected
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
        let changed = self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO blocked_routes (cidr, asn, asn_name, reason) \
             VALUES (?1, ?2, ?3, ?4)",
            params![cidr, asn, asn_name, reason],
        )?;
        if changed > 0 {
            self.nets.write().unwrap().push(net);
        }
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
