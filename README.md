# OSINT MCP

![A large black and white eye, the OSINT MCP project banner](docs/eye-banner.png)

**72 tools for open-source intelligence and authorized reconnaissance, exposed through the Model Context Protocol (MCP).** Investigate domains, IPs, websites, public accounts, breach metadata, threat feeds, and images from one stdio server.

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-111111?logo=python&logoColor=white) ![72 tools](https://img.shields.io/badge/Tools-72-111111) ![License MIT](https://img.shields.io/badge/License-MIT-111111)

Most tools work without an API key. Optional keys add coverage from services such as HIBP, VirusTotal, and OTX. Browser tools use Playwright; the rest can run without a browser.

## Start here

**Requirements:** Python 3.10 or newer. Chromium is needed only for browser and deep research tools; Tesseract is optional for OCR.

```bash
git clone https://github.com/n5za/osint-mcp.git
cd osint-mcp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Install Chromium if you plan to use `browser_*`, `browser_search`, `browser_crawl`, or `deep_osint`:

```bash
playwright install chromium
```

The server speaks **MCP over stdio**. Connect it to a client; running `python server.py` directly waits for MCP messages on stdin.

### Connect an MCP client

Use the absolute path to the virtual environment's Python binary. This lets the client start the server without shell activation.

<details>
<summary>Claude Desktop / Cursor</summary>

Put this in Claude Desktop's `claude_desktop_config.json` or Cursor's `.cursor/mcp.json`, changing the two absolute paths:

```json
{
  "mcpServers": {
    "osint": {
      "command": "/absolute/path/to/osint-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/osint-mcp/server.py"]
    }
  }
}
```

Restart the client after saving.
</details>

<details>
<summary>OpenCode</summary>

Add this to `opencode.jsonc` (or `~/.config/opencode/opencode.jsonc`):

```jsonc
{
  "mcp": {
    "osint": {
      "type": "local",
      "command": [
        "/absolute/path/to/osint-mcp/.venv/bin/python",
        "/absolute/path/to/osint-mcp/server.py"
      ],
      "enabled": true
    }
  }
}
```

Reload OpenCode, then run `opencode mcp list`.
</details>

<details>
<summary>VS Code / Copilot</summary>

Put this in `.vscode/mcp.json`:

```json
{
  "servers": {
    "osint": {
      "type": "stdio",
      "command": "/absolute/path/to/osint-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/osint-mcp/server.py"]
    }
  }
}
```
</details>

<details>
<summary>Claude Code</summary>

```bash
claude mcp add osint -- /absolute/path/to/osint-mcp/.venv/bin/python /absolute/path/to/osint-mcp/server.py
```
</details>

### Check the installation

```bash
python - <<'PY'
import asyncio
from osint_mcp.app import mcp
print(len(asyncio.run(mcp.list_tools())))
PY
```

Expected output: `72`. To try a keyless tool without an MCP client:

```bash
python - <<'PY'
import asyncio
from osint_mcp.dns_tools import dns_lookup
print(asyncio.run(dns_lookup("example.com", "A")))
PY
```

## Choose a workflow

| Goal | Start with | Continue with |
|---|---|---|
| Domain overview | `recon_domain` | `recon_deep`, `dns_lookup`, `domain_whois` |
| DNS posture | `dnssec_status` | `dns_resolver_compare`, `email_security` |
| IP context | `recon_ip` | `ip_intel`, `asn_lookup`, `ip_whois` |
| Public web surface | `http_headers_audit` | `tech_fingerprint`, `wayback_urls`, `js_recon` |
| Threat triage | `threat_reputation` | `virustotal_report`, `otx_domain`, `cve_intel` |
| Rendered or dynamic page | `browser_open` | `browser_extract`, `browser_screenshot` |
| Multi-source research | `deep_osint` | `source_crosscheck`, `image_analyze` |

`recon_ip` includes a TCP port check. Other tools that actively contact target systems include `port_scan`, `subdomain_enum`, `api_discovery`, `dns_zone_transfer`, and browser tools. Use them only on targets you are authorized to assess.

## Tool catalog

The names below are the registered MCP tool names. Arguments and result schemas are available through MCP tool discovery.

### Overview and DNS

| Tools | Purpose |
|---|---|
| `recon_domain`, `recon_ip`, `recon_deep` | Parallel overviews for a domain or IP. |
| `dns_lookup`, `reverse_dns` | DNS records and reverse PTR lookups. |
| `dnssec_status` | Check DS and DNSKEY publication. This does **not** validate signatures. |
| `dns_resolver_compare` | Compare Cloudflare and Google DNS-over-HTTPS answers. Differences can be normal for geo DNS or load balancing. |
| `crtsh_subdomains`, `passive_subdomains` | Find names from public certificate and passive sources. |
| `subdomain_enum`, `dns_zone_transfer` | Active subdomain guessing and AXFR checks. |

### Domains, IPs, and websites

| Tools | Purpose |
|---|---|
| `domain_whois`, `ssl_certificate` | RDAP registration and live TLS certificate details. |
| `robots_txt`, `security_txt`, `sitemap_urls`, `wayback_urls` | Site policy files, sitemaps, and archived URLs. |
| `ip_intel`, `asn_lookup`, `reverse_ip`, `ip_whois` | Address, network, ASN, and registration context. |
| `port_scan` | Active TCP connection scan with configurable ports. |
| `http_fetch`, `http_headers_audit`, `tech_fingerprint` | HTTP response, security headers, and technology clues. |
| `extract_links`, `page_metadata` | Links, forms, metadata, and page structure. |

### Discovery and search

| Tools | Purpose |
|---|---|
| `web_search`, `google_dorks`, `github_search` | Web search, prepared search queries, and public GitHub search. |
| `urlscan_search`, `commoncrawl_urls` | Public scan and archive indexes. |
| `js_recon`, `api_discovery`, `well_known` | JavaScript clues, API paths, and well-known endpoints. |
| `subdomain_takeover_check`, `favicon_hash`, `cloud_bucket_check` | Dangling DNS signals, favicon pivot, and public bucket checks. |
| `hackernews_search`, `grep_app_search`, `bluesky_profile`, `npm_search` | Public discussion, code, profile, and package sources. |

### Identity, exposure, and threat intelligence

| Tools | Purpose |
|---|---|
| `username_search`, `email_intel` | Public handle and email context. |
| `breach_check`, `stealer_log_check`, `domain_breach_exposure` | Exposure **metadata only**; personal lookups require `authorized=True`. |
| `breach_catalog`, `breach_providers` | Public breach catalog and provider availability. |
| `email_security` | SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT, and CAA posture. |
| `otx_domain`, `virustotal_report`, `cve_intel`, `threat_reputation` | Threat feeds, detections, vulnerability details, and combined signals. |
| `dnsbl_check`, `tor_exit_check`, `greynoise_ip` | DNS blocklists, Tor exit list, and GreyNoise context. |
| `urlhaus_lookup`, `peeringdb_network`, `openphish_check` | Malware URL, network, and phishing feeds. |

### Browser, deep research, and local utilities

| Tools | Purpose |
|---|---|
| `browser_open`, `browser_extract`, `browser_screenshot`, `browser_eval` | Render a page, extract content, capture a PNG, or evaluate JavaScript. |
| `deep_osint`, `browser_search`, `browser_crawl`, `source_crosscheck` | Bounded browser research and source comparison. |
| `image_analyze`, `image_exif` | Image hashes, metadata, optional OCR/QR, and EXIF. |
| `jwt_decode`, `hash_text` | Decode JWT fields and calculate text hashes locally. |

`browser_screenshot` returns image content; most other tools return structured data. A source error or missing key is reported in the result, so a failed lookup is not treated as a negative finding.

## Optional API keys

No key is required to start. Set environment variables for extra provider coverage, or copy [`keys.example.json`](keys.example.json) to `~/.config/osint-mcp/keys.json` and set file permissions to `600`.

| Environment variable | Used for |
|---|---|
| `GITHUB_TOKEN` | GitHub code search and higher API limits. |
| `HIBP_API_KEY` | Have I Been Pwned account, domain, and stealer endpoints. |
| `OTX_API_KEY` | AlienVault OTX coverage. |
| `VIRUSTOTAL_API_KEY` | VirusTotal reports. |
| `GREYNOISE_API_KEY` | Optional GreyNoise access. |
| `URLHAUS_API_KEY` | URLhaus API access. |

```bash
mkdir -p ~/.config/osint-mcp
chmod 700 ~/.config/osint-mcp
cp keys.example.json ~/.config/osint-mcp/keys.json
chmod 600 ~/.config/osint-mcp/keys.json
```

Never commit real keys. See the provider's own documentation for access requirements and quotas.

## Configuration and limits

| Setting | Default | Effect |
|---|---|---|
| `OSINT_BROWSER_PATH` | auto-detected | Override the Chrome/Chromium executable. |
| `OSINT_HEADLESS` | `1` | Set `0` to show a browser window. |
| `OSINT_SHOTS_DIR` | `./shots` | Screenshot output directory. |
| `OSINT_KEYS_FILE` | `~/.config/osint-mcp/keys.json` | Alternate local key file. |

Public sources can rate-limit, block, or return incomplete data. A DNS resolver mismatch is not automatically a misconfiguration. Breach results may be stale or contain false positives. Browser crawling and some composite tools make multiple requests, so set their limits to fit your scope. `image_analyze` processes images locally for hashes, EXIF, OCR, and QR; reverse-image search links are generated for remote URLs.

## Project structure

```text
osint_mcp/
├── app.py              # MCP registration and tool instructions
├── common.py           # HTTP, cache, keys, and shared helpers
├── composite.py        # overview workflows
├── dns_tools.py        # DNS, CT, AXFR, subdomain enumeration
├── dns_audit_tools.py  # DNSSEC and resolver comparison
├── domain_tools.py     # RDAP, TLS, site policy files, archives
├── ip_tools.py         # IP and port tools
├── web_tools.py        # HTTP and page analysis
├── discovery_tools.py  # API, JS, archive, and takeover discovery
├── intel_tools.py      # threat intelligence
├── breach_tools.py     # exposure metadata
├── mail_tools.py       # email security
├── search_tools.py     # web and GitHub search
├── social_tools.py     # social, code, and package search
├── identity_tools.py   # username and email context
├── browser_tools.py    # Playwright browser tools
├── deep_tools.py       # deep research and image analysis
└── util_tools.py       # local utilities
```

## Responsible use

Use this project only for your own assets, authorized engagements, bug bounty scopes, or labs. Breach tools return aggregate metadata and do not expose passwords, hashes, cookies, or raw leaked records. Confirm findings with primary evidence before reporting them.

MIT licensed. See [LICENSE](LICENSE).
