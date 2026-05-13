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
                let nets = strs
                    .iter()
                    .filter_map(|s| match s.parse() {
                        Ok(net) => Some(net),
                        Err(_) => {
                            tracing::warn!("skipping unparseable CIDR: {}", s);
                            None
                        }
                    })
                    .collect();
                ranges.insert(name.to_string(), nets);
            }
        }

        Self { ranges }
    }

    /// Returns the name of the first matching provider, or None if not blocked.
    pub fn is_blocked<'a>(&self, ip: IpAddr, providers: &'a [String]) -> Option<&'a str> {
        for provider in providers {
            if let Some(nets) = self.ranges.get(provider.as_str()) {
                if nets.iter().any(|net| net.contains(&ip)) {
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
        let binding = providers(&["aws", "private"]);
        let result = m.is_blocked(ip, &binding);
        assert_eq!(result, Some("private"));
    }

    #[test]
    fn empty_providers_never_blocks() {
        let m = matcher();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(m.is_blocked(ip, &[]).is_none());
    }
}
