# OSINT Recon MCP

**72 OSINT & reconnaissance tools for any MCP client** — DNS, WHOIS, TLS, IP intelligence, subdomain discovery, breach metadata, threat intel, JavaScript recon, and a real headless browser for deep research.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![MCP](https://img.shields.io/badge/MCP-1.x-6f42c1)
![Tools](https://img.shields.io/badge/tools-72-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

The model picks the narrowest tool it needs from the tool descriptions; every tool returns
structured JSON (except `browser_screenshot`, which returns a real PNG). Most sources are
**keyless** — API keys only unlock extra coverage (VirusTotal, OTX, HIBP, URLhaus, GitHub code search).

- **One-shot overviews** — `recon_domain`, `recon_ip`, `recon_deep` fan out many sources in parallel.
- **Passive by default** — certificates, archives, RDAP, DNS, public feeds.
- **Real browser** — rendered text, screenshots, JS evaluation, bounded crawling, OCR/EXIF.
- **Honest results** — tools report `blocked`, `needs_key`, or source failures instead of pretending "not found".
- **Metadata-only breach tools** — no passwords, hashes, cookies, or raw leaked records, ever.

---

## Table of contents

- [Quick start](#quick-start)
- [OpenCode integration](#opencode-integration)
- [Other MCP clients](#other-mcp-clients)
- [Tool catalog](#tool-catalog)
  - [One-shot overview](#one-shot-overview)
  - [DNS / infrastructure](#dns--infrastructure)
  - [Domain / TLS / historical web](#domain--tls--historical-web)
  - [IP addresses](#ip-addresses)
  - [Web recon](#web-recon)
  - [Search](#search)
  - [Identity](#identity)
  - [Breach / leaked-data exposure](#breach--leaked-data-exposure)
  - [Threat intelligence](#threat-intelligence)
  - [Discovery / deep search](#discovery--deep-search)
  - [Social / code / package search](#social--code--package-search)
  - [Email security](#email-security)
  - [Real browser](#real-browser)
  - [Browser-driven deep OSINT](#browser-driven-deep-osint)
  - [Utilities](#utilities)
- [Example sessions](#example-sessions)
- [Configuration](#configuration)
- [API keys](#api-keys)
- [Project layout](#project-layout)
- [How it works](#how-it-works)
- [Safety, ethics, legal](#safety-ethics-legal)
- [Rate limits & caveats](#rate-limits--caveats)
- [License](#license)

---

## Quick start

### Requirements

| Dependency | Notes |
|---|---|
| Python 3.10+ | Tested on 3.10 – 3.14 |
| Google Chrome or Chromium | Only for the `browser_*` and `deep_*` tools |
| Tesseract OCR + `eng` data | Only for `image_analyze(ocr=True)` |

### Install

```bash
git clone https://github.com/n5za/osint-mcp.git
cd osint-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Browser tools need a Chromium build:
playwright install chromium
```

Optional system packages:

```bash
# Debian / Ubuntu / Kali
sudo apt install tesseract-ocr tesseract-ocr-eng

# Arch
sudo pacman -S tesseract tesseract-data-eng
```

The server uses the system browser by default. To force a specific binary:

```bash
export OSINT_BROWSER_PATH=/usr/bin/google-chrome-stable
```

### Smoke test

The server speaks MCP over stdio, so it is not meant to run interactively.
Test the Python layer directly:

```bash
python3 - <<'PY'
import asyncio, json
from osint_mcp.composite import recon_domain
result = asyncio.run(recon_domain("example.com"))
print(json.dumps(result["summary"], indent=2))
PY
```

Or list every registered tool:

```bash
python3 - <<'PY'
import asyncio
from osint_mcp.app import mcp
print(len(asyncio.run(mcp.list_tools())), "tools")
PY
```

---

## OpenCode integration

OpenCode reads MCP servers from `opencode.json` / `opencode.jsonc` — either the global file at
`~/.config/opencode/opencode.jsonc` or a project-level `.opencode/opencode.jsonc`.

### 1. Add the server

Edit your config and add the `osint` entry under `mcp`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "osint": {
      "type": "local",
      "command": ["python3", "/absolute/path/to/osint-mcp/server.py"],
      "enabled": true,
      "environment": {
        "OSINT_SHOTS_DIR": "/absolute/path/to/osint-mcp/shots"
      }
    }
  }
}
```

Notes:

- `command` must be an **absolute path** to the entrypoint (or a command on `PATH`).
- Use your venv interpreter if you installed dependencies there, for example
  `["/absolute/path/to/osint-mcp/.venv/bin/python", ".../server.py"]`.
- `OSINT_SHOTS_DIR` is where screenshots are written. It defaults to `./shots` next to `server.py`.
- Add API keys under `environment` (see [API keys](#api-keys)) or in the JSON key store — never in the repo.

If you installed the package with `pip install -e .`, you can use the console script instead:

```jsonc
"command": ["osint-mcp"]
```

### 2. Reload OpenCode

Restart OpenCode, or reload the session. MCP servers are spawned at session start.

### 3. Verify

```bash
opencode mcp list
```

You should see `osint` with 72 tools. Inside a session, ask the model to call
`recon_domain` for a domain you are authorized to test — the tool names appear in the
model's tool list, prefixed by the server name (`osint_recon_domain`, etc., depending on client).

### 4. Prompt the model well

The server ships an MCP `instructions` block with workflow hints, so a plain request works:

> Use the osint tools to profile `example.com`: DNS, WHOIS, TLS certificate, security headers, and any passive subdomains. Summarize the risk-relevant findings.

For deeper runs, name the tool explicitly:

> Call `recon_deep` on `example.com` with `limit=100`, then `subdomain_takeover_check`, and give me a table of dangling CNAMEs.

### Troubleshooting

| Symptom | Fix |
|---|---|
| Server shows `failed` in `opencode mcp list` | Run the exact `command` manually; a traceback means a missing dependency |
| `ModuleNotFoundError: mcp` | You pointed at the system Python instead of your venv |
| Browser tools time out | `playwright install chromium`, or set `OSINT_BROWSER_PATH` |
| `needs_key` in results | Optional — add the key for that source |
| Screenshots not found | Check `OSINT_SHOTS_DIR` exists and is writable |
| Tools missing after config edit | Restart the session; config is read at startup |

---

## Other MCP clients

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add osint -- python3 /absolute/path/to/osint-mcp/server.py
```

With env vars:

```bash
claude mcp add osint \
  -e OSINT_SHOTS_DIR=/absolute/path/to/osint-mcp/shots \
  -e VIRUSTOTAL_API_KEY=... \
  -- python3 /absolute/path/to/osint-mcp/server.py
```
</details>

<details>
<summary><b>Claude Desktop</b></summary>

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "osint": {
      "command": "python3",
      "args": ["/absolute/path/to/osint-mcp/server.py"],
      "env": {
        "OSINT_SHOTS_DIR": "/absolute/path/to/osint-mcp/shots"
      }
    }
  }
}
```
</details>

<details>
<summary><b>Cursor</b></summary>

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "osint": {
      "command": "python3",
      "args": ["/absolute/path/to/osint-mcp/server.py"]
    }
  }
}
```
</details>

<details>
<summary><b>VS Code / Copilot</b></summary>

`.vscode/mcp.json`:

```json
{
  "servers": {
    "osint": {
      "type": "stdio",
      "command": "python3",
      "args": ["/absolute/path/to/osint-mcp/server.py"]
    }
  }
}
```
</details>

<details>
<summary><b>Any other client (raw stdio)</b></summary>

```bash
python3 /absolute/path/to/osint-mcp/server.py
```

Transport: `stdio`. No ports, no daemon, no network listener.
</details>

---

## Tool catalog

### One-shot overview

| Tool | What it returns |
|---|---|
| `recon_domain(domain)` | DNS + RDAP whois + TLS + crt.sh + security headers + tech fingerprint + robots/security.txt, fanned out in parallel |
| `recon_ip(ip)` | Geo/ASN + Shodan InternetDB + PTR + reverse-IP + top-20 port scan, in parallel |
| `recon_deep(domain, limit=100)` | Passive subdomains + urlscan + Common Crawl + API discovery + well-known + email security + threat intel + favicon, in parallel |

### DNS / infrastructure

| Tool | What it returns |
|---|---|
| `dns_lookup(domain, record_type="A")` | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/SRV/ANY, structured |
| `dnssec_status(domain)` | DS and DNSKEY publication; signed, unsigned, or incomplete. Does not validate signatures. |
| `dns_resolver_compare(domain, record_type="A")` | Compare Cloudflare and Google DNS-over-HTTPS answers for A/AAAA/MX/NS/TXT/CAA/CNAME. |
| `reverse_dns(ip)` | PTR records |
| `crtsh_subdomains(domain, limit=200)` | Passive subdomains from certificate transparency (crt.sh, Cert Spotter fallback) |
| `subdomain_enum(domain, wordlist=None, concurrency=50)` | Active brute force with a built-in ~320-word list, wildcard detection |
| `dns_zone_transfer(domain)` | AXFR attempt against every authoritative nameserver |

`dnssec_status` checks whether DS and DNSKEY records are published; it does not verify cryptographic signatures. `dns_resolver_compare` reports the public resolvers' answers at query time. Different answers can be expected for geo DNS, load balancing, or resolver policies.

### Domain / TLS / historical web

| Tool | What it returns |
|---|---|
| `domain_whois(domain)` | RDAP registration: registrar, dates, status, nameservers, DNSSEC |
| `ssl_certificate(host, port=443)` | Live certificate: subject/issuer/SAN/expiry/days left, key and cipher |
| `robots_txt(domain)` | Parsed robots.txt, sitemaps, sensitive path hits |
| `security_txt(domain)` | RFC 9116 security.txt fields + expiry check |
| `sitemap_urls(domain, limit=200)` | sitemap.xml / sitemap index discovery |
| `wayback_urls(domain, limit=500, include_subdomains=True, only_ok=True)` | Wayback CDX historical URLs: forgotten endpoints, backups, parameters |

### IP addresses

| Tool | What it returns |
|---|---|
| `ip_intel(ip)` | Geolocation/ASN/org + Shodan InternetDB ports, hostnames, CVEs |
| `asn_lookup(target)` | ASN holder and announced prefixes (RIPEstat), or IP/domain → ASN |
| `reverse_ip(ip)` | Other domains hosted on the same IP |
| `port_scan(host, ports="top100", timeout=1.0, concurrency=200)` | Async TCP connect scan — presets `top20` / `top100` / `web` / `db` / `common`, banner grabbing |

> `port_scan` is **active**. Only use it on systems you are authorized to test.

### Web recon

| Tool | What it returns |
|---|---|
| `http_fetch(url, method="GET", headers=None, body=None, verify_ssl=True, ...)` | Custom request with TLS-verify toggle, redirects, body and headers |
| `http_headers_audit(url)` | Security-header score + grade, cookie flags, information leaks |
| `tech_fingerprint(url)` | Server/CDN/WAF/framework/CMS/analytics detection with evidence |
| `extract_links(url, external_only=False, limit=500)` | Internal/external links, emails, scripts, forms, query-parameter inventory |
| `page_metadata(url)` | Title, meta/OG/Twitter tags, headings, analytics IDs, iframes, forms |

### Search

| Tool | What it returns |
|---|---|
| `web_search(query, max_results=10)` | DuckDuckGo HTML results (keyless) |
| `google_dorks(target, category=None)` | 44 ready-made dorks × Google/Bing/DDG links, 11 categories |
| `github_search(query, kind="repositories", max_results=20)` | Repos/users/issues/commits/code (code search needs `GITHUB_TOKEN`) |

### Identity

| Tool | What it returns |
|---|---|
| `username_search(username, sites=None, timeout=10)` | ~26 platforms, separated into found / not-found / blocked |
| `email_intel(email)` | MX/SPF/DMARC, disposable/role detection, Gravatar, HIBP (optional key) |

### Breach / leaked-data exposure

Metadata only. Personal lookups require `authorized=True`.

| Tool | What it returns |
|---|---|
| `breach_check(identifier, kind="email", authorized=False)` | LeakCheck aggregate metadata + HIBP account breaches (key) + Hudson Rock stealer infections + HIBP catalogue matches; exposure score, signals, recommendations |
| `breach_catalog(query, limit=20, domain_only=False)` | Public HIBP breach catalogue search: dates, record counts, data classes, descriptions |
| `stealer_log_check(identifier, kind="email", authorized=False)` | Focused infostealer check: Hudson Rock + HIBP stealer logs (key); dates, OS, sanitized malware path, website domains, counts |
| `domain_breach_exposure(domain, authorized=False)` | Whole-domain aggregate from LeakCheck + HIBP catalogue + verified HIBP domain/stealer aggregates; no employee aliases returned |
| `breach_providers()` | Which providers/keys are available, without exposing key material |

These tools return **no passwords, hashes, cookies, raw leaked records, or employee email
aliases**. HIBP account/domain/stealer endpoints need a paid key; LeakCheck public metadata,
Hudson Rock, and the HIBP catalogue are keyless.

### Threat intelligence

| Tool | What it returns |
|---|---|
| `otx_domain(domain, limit=50)` | AlienVault OTX pulses, malware families, URL list, validation (OTX key) |
| `virustotal_report(target, kind="domain")` | VirusTotal report: engine detections, DNS, certificate (VT key) |
| `cve_intel(cve_id)` | CVE details from CIRCL + NVD: CVSS, CWE, EPSS, CISA KEV, affected products |
| `threat_reputation(target)` | One-shot verdict aggregating VT, OTX, GreyNoise, Tor, DNSBL, InternetDB, OpenPhish |
| `dnsbl_check(target, include_errors=False)` | Spamhaus/Barracuda/SORBS etc. via authoritative nameservers (bypasses open-resolver blocks) |
| `tor_exit_check(target)` | Check an IP against the Tor bulk exit list |
| `greynoise_ip(ip)` | GreyNoise community: noise, RIOT, classification, last seen |
| `ip_whois(ip)` | RDAP IP registration: network, ASN, org, country, contacts, remarks |
| `urlhaus_lookup(target)` | abuse.ch URLhaus host/URL lookup (optional Auth-Key) |
| `peeringdb_network(query)` | PeeringDB network by ASN or name: IX, peering policy, traffic |
| `openphish_check(url)` | Check a URL/host against the OpenPhish live phishing feed |

### Discovery / deep search

| Tool | What it returns |
|---|---|
| `urlscan_search(query, limit=50)` | urlscan.io scan search by domain/IP/URL/filename, with screenshots and result links |
| `commoncrawl_urls(domain, limit=500, index="CC-MAIN-2024-10")` | Archived URLs from the Common Crawl index |
| `passive_subdomains(domain, limit=500, deep=False)` | crt.sh + HackerTarget + RapidDNS + OTX aggregation with per-source counts |
| `js_recon(url, max_scripts=30, max_bytes=2000000)` | Page JS bundles: API endpoints, source maps, masked secret candidates |
| `api_discovery(domain, limit=100)` | Probe OpenAPI/Swagger, GraphQL, OIDC, JWKS, actuator, `.env`, `.git`, debug paths |
| `well_known(domain)` | `/.well-known/*`: OIDC, JWKS, security.txt, app links, MTA-STS |
| `subdomain_takeover_check(domain, limit=500, deep=False)` | Dangling CNAMEs to GitHub/S3/Azure/Heroku/Netlify/Vercel/etc. with provider fingerprints |
| `favicon_hash(url)` | Shodan-compatible mmh3 favicon hash + MD5/SHA256 + ready Shodan query |
| `cloud_bucket_check(bucket, provider="auto")` | S3/GCS/Azure bucket existence and public object listing (read-only) |

### Social / code / package search

| Tool | What it returns |
|---|---|
| `hackernews_search(query, limit=20, sort="relevance", tags=None)` | HN stories/comments via Algolia |
| `grep_app_search(query, limit=20, language=None, repo=None)` | Public code search with repo/path/line snippets (browser fallback for bot checks) |
| `bluesky_profile(actor, posts=10)` | Public Bluesky profile, counts, labels, recent posts + engagement |
| `npm_search(query, limit=20)` | npm package search: version, publisher, links, quality/popularity scores |

### Email security

| Tool | What it returns |
|---|---|
| `email_security(domain)` | SPF, DMARC, DKIM (common selectors + RSA bits), BIMI, MTA-STS, TLS-RPT, CAA, score/grade/issues |

### Real browser

| Tool | What it returns |
|---|---|
| `browser_open(url, wait_ms=1500, screenshot=True)` | Headless Chrome tab: title, text, counts, console messages, screenshot path |
| `browser_extract(url, selector=None, wait_ms=1500)` | Rendered text + links + images, optional CSS selector |
| `browser_screenshot(url, full_page=True, wait_ms=1500)` | Returns the PNG inline as image content |
| `browser_eval(url, expression, wait_ms=1500)` | Evaluate JavaScript in the page and return the JSON result |

### Browser-driven deep OSINT

| Tool | What it returns |
|---|---|
| `deep_osint(query, max_results=6, max_pages=8, max_depth=2, analyze_images=True, ocr_images=False, screenshots=False)` | Search in a real browser → crawl top sources → extract entities → cross-check → analyze images → follow-up leads |
| `browser_search(query, engine="duckduckgo", limit=10)` | Search DuckDuckGo/Bing/Brave in Chromium, decode redirects, filter ads |
| `browser_crawl(start_url, query=None, max_pages=6, max_depth=1, screenshots=False)` | Open seeds, follow relevant links with caps, extract text/meta/links/images/entities |
| `source_crosscheck(sources, query=None)` | Fetch several URLs and split entities into `corroborated` (2+ sources) vs `single_source` |
| `image_analyze(target, ocr=True, qr=True, reverse_search=True)` | Dimensions, EXIF/GPS, MD5/SHA256/dHash/aHash, dominant colors, Tesseract OCR, OpenCV QR, reverse-image links |

`deep_osint` is the main entry point. Crawls are bounded by `max_results`, `max_pages`,
`max_depth`, and per-page timeouts — it is a bounded crawler, not an open-ended scraper.

### Utilities

| Tool | What it returns |
|---|---|
| `jwt_decode(token)` | Header/payload, exp/iat/nbf, `alg=none` warning |
| `hash_text(text, algorithms=None)` | md5/sha1/sha256/sha512 and friends |
| `image_exif(source)` | EXIF + GPS from a local path or URL |

---

## Example sessions

**Domain triage**

> Profile `example.com` with the osint tools: DNS, WHOIS, certificate, security headers, subdomains, and takeover risk.

**Attack-surface inventory**

> Run `recon_deep` on `example.com`, then `js_recon` on the three most interesting hosts, and list every API endpoint you find grouped by host.

**Phishing check**

> Check `http://suspicious-login.example` with `threat_reputation`, `openphish_check`, and `urlhaus_lookup`, then screenshot it with `browser_screenshot`.

**Person investigation (authorized)**

> Use `username_search` for handle `sampleuser`, then `email_intel` for the address they publish, and summarize only public professional information.

**CVE brief**

> Get `cve_intel` for `CVE-2024-3400` and tell me EPSS, KEV status, and which products are affected.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OSINT_SHOTS_DIR` | `./shots` next to `server.py` | Screenshot output directory |
| `OSINT_BROWSER_PATH` | auto-detect Chrome/Chromium | Browser executable |
| `OSINT_HEADLESS` | `1` | Set to `0` for a visible browser window |
| `OSINT_KEYS_FILE` | `~/.config/osint-mcp/keys.json` | Local JSON key store |
| `GITHUB_TOKEN` / `GH_TOKEN` | — | GitHub code search + higher rate limit |
| `HIBP_API_KEY` | key store `hibp` / `haveibeenpwned` | HIBP account, verified-domain, stealer lookups |
| `OTX_API_KEY` | key store `otx` | AlienVault OTX pulses and URL data |
| `VIRUSTOTAL_API_KEY` | key store `virustotal` / `vt` | VirusTotal reports (free tier ≈ 4 req/min) |
| `GREYNOISE_API_KEY` | — | Optional; the community endpoint works keyless |
| `URLHAUS_API_KEY` / `URLHAUS_AUTH_KEY` | key store `urlhaus` | abuse.ch URLhaus Auth-Key |

## API keys

Keys can come from environment variables (above) or from a local JSON file:

```bash
mkdir -p ~/.config/osint-mcp
chmod 700 ~/.config/osint-mcp
cp keys.example.json ~/.config/osint-mcp/keys.json
$EDITOR ~/.config/osint-mcp/keys.json
chmod 600 ~/.config/osint-mcp/keys.json
```

```json
{
  "github": "ghp_...",
  "hibp": "...",
  "otx": "...",
  "virustotal": "...",
  "urlhaus": "..."
}
```

Tools never print full keys — only booleans such as `key_used`, or masked values.

Where to get them:

| Key | Source |
|---|---|
| GitHub token | <https://github.com/settings/tokens> (no scopes needed for public code search) |
| HIBP | <https://haveibeenpwned.com/API/Key> (paid) |
| OTX | <https://otx.alienvault.com/api> |
| VirusTotal | <https://www.virustotal.com/gui/my-apikey> (free tier) |
| URLhaus | <https://auth.abuse.ch/> (free) |

---

## Project layout

```
osint-mcp/
├── server.py               # stdio entrypoint
├── run.sh                  # convenience launcher
├── osint_mcp/
│   ├── app.py              # FastMCP instance + tool registration + instructions
│   ├── common.py           # HTTP client, cache, key store, shared helpers
│   ├── composite.py        # recon_domain / recon_ip / recon_deep
│   ├── dns_tools.py        # DNS, CT, brute force, AXFR
│   ├── dns_audit_tools.py  # DNSSEC publication and resolver comparison
│   ├── domain_tools.py     # RDAP, TLS, robots, security.txt, sitemaps, Wayback
│   ├── ip_tools.py         # IP intel, ASN, reverse IP, port scan
│   ├── web_tools.py        # HTTP fetch, header audit, fingerprint, links, metadata
│   ├── search_tools.py     # web search, dorks, GitHub
│   ├── identity_tools.py   # username, email
│   ├── breach_tools.py     # breach metadata (no raw records)
│   ├── intel_tools.py      # OTX, VT, CVE, DNSBL, GreyNoise, PeeringDB, ...
│   ├── discovery_tools.py  # urlscan, Common Crawl, subdomains, JS, API, takeover
│   ├── social_tools.py     # HN, grep.app, Bluesky, npm
│   ├── mail_tools.py       # SPF/DMARC/DKIM/BIMI/MTA-STS
│   ├── browser_tools.py    # Playwright session helpers
│   ├── deep_tools.py       # browser_search/crawl, deep_osint, image analysis
│   ├── util_tools.py       # JWT, hashes, EXIF
│   └── data/subdomains.txt # ~320-entry brute-force wordlist
├── keys.example.json
├── requirements.txt
└── pyproject.toml
```

## How it works

- **FastMCP over stdio.** `server.py` builds the app, registers 72 tools, and speaks JSON-RPC on
  stdin/stdout. No HTTP listener, no persistence, no background daemon.
- **Bounded concurrency.** Composite tools fan out with `asyncio.gather`; every network call has a
  timeout and a cache entry (5 min default) to stay friendly to upstream APIs.
- **Graceful degradation.** Missing keys → `needs_key`; blocked upstream → `blocked`; upstream
  errors → structured `{ok: false, error}` instead of a crashed tool call.
- **Evidence-first output.** Fingerprinting and takeover checks report the matched fingerprint or
  header that produced the verdict, so the model can explain *why*.
- **Privacy guardrails.** Breach tools return aggregate metadata only and require
  `authorized=True` for anything tied to a person.

## Safety, ethics, legal

This is a reconnaissance toolkit. Use it only where you have permission.

- **Authorized targets only.** Bug bounty scopes, your own assets, signed engagements, or CTF/lab
  environments.
- **Passive by default, active when asked.** `port_scan`, `subdomain_enum`, and `browser_*` touch
  the target; everything else leans on public data.
- **No credential harvesting.** Breach tools are metadata-only by design and will not return
  passwords, hashes, cookies, or raw records.
- **Respect rate limits and the law.** Upstream APIs have terms of service; unauthorized scanning
  is illegal in many jurisdictions (CFAA, Computer Misuse Act, etc.).
- **The author accepts no liability** for misuse. See [LICENSE](LICENSE).

## Rate limits & caveats

- Most sources are keyless. OTX and VirusTotal are strongly recommended; URLhaus needs a free key.
- Upstreams rate-limit or fail: HackerTarget (~50/day), crt.sh (502s), Common Crawl (504s on large
  domains), Wayback CDX (slow), Reddit/HackerOne (Cloudflare 403), VirusTotal free (~4 req/min).
  Tools report `blocked` / `needs_key` or fall back instead of returning a false negative.
- `grep_app_search` tries the JSON API first, then renders in Chromium if a bot challenge appears.
- `browser_search` tries DuckDuckGo HTML, then Bing and Brave; Bing redirect URLs are decoded.
- `deep_osint` / `browser_crawl` cap at 20 pages and depth 2 by default. Raise the caps deliberately.
- `image_analyze` is fully local for hashes/EXIF/OCR/QR; reverse-image links are only generated for
  remote URLs and nothing is uploaded.
- `subdomain_takeover_check` marks `high` only when a provider-specific unclaimed fingerprint matches;
  a matching CNAME alone is `potential`.
- Aggregate breach matches can be stale or false-positive, especially for shared or test addresses.

## License

MIT — see [LICENSE](LICENSE).
