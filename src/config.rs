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
}
