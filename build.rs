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
