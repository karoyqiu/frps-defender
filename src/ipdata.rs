use anyhow::Result;
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Deserialize)]
pub struct IpInfo {
    pub asn: Option<Asn>,
    pub threat: Option<Threat>,
}

#[derive(Deserialize)]
pub struct Asn {
    pub asn: String,
    pub name: String,
    pub route: String,
}

#[derive(Deserialize, Default)]
pub struct Threat {
    #[serde(default)]
    pub is_tor: bool,
    #[serde(default)]
    pub is_proxy: bool,
    #[serde(default)]
    pub is_known_attacker: bool,
    #[serde(default)]
    pub is_known_abuser: bool,
    #[serde(default)]
    pub is_threat: bool,
    #[serde(default)]
    pub is_bogon: bool,
}

pub struct IpDataClient {
    client: reqwest::Client,
    api_key: String,
}

impl IpDataClient {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self { client: reqwest::Client::new(), api_key: api_key.into() }
    }

    pub async fn lookup(&self, ip: IpAddr) -> Result<IpInfo> {
        let url = format!("https://api.ipdata.co/{}?api-key={}", ip, self.api_key);
        let info = self.client.get(&url).send().await?.json::<IpInfo>().await?;
        Ok(info)
    }
}
