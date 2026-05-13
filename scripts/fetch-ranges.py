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
