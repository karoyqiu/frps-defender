use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

fn default_listen() -> String {
    "127.0.0.1:7200".into()
}

fn default_block() -> Vec<String> {
    vec!["all".into()]
}

fn default_db_path() -> String {
    "/var/tmp/frps-defender/blocks.db".to_string()
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
    #[serde(default)]
    pub ipdata_api_key: Option<String>,
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

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
    use tempfile::NamedTempFile;

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
}
