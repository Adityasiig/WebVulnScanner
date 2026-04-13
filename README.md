# WebVulnScanner

A Python-based web vulnerability scanner with automated recon, WAF detection, subdomain enumeration, and a clean HTML report dashboard.

Built by [Aditya Singh](https://adityasiig.github.io/Portfolio/) — [GitHub](https://github.com/Adityasiig) · [Portfolio](https://adityasiig.github.io/Portfolio/) · [Terminal Portfolio](https://adityasiig.github.io/terminal-portfolio/)

> **For authorized security testing only. Always get written permission before scanning any target.**

---

## Features

| Module | What it detects |
|---|---|
| **SQLi** | Error-based, time-based blind, boolean-based blind SQL injection |
| **XSS** | Reflected XSS in URL parameters and form fields |
| **Headers** | Missing security headers, cookie flags, server info disclosure |
| **Sensitive** | Exposed files — `.env`, `.git`, backups, admin panels, API docs |
| **Traversal** | Directory/path traversal (LFI) with encoding bypass payloads |
| **Redirect** | Open redirect via URL parameters and common redirect params |
| **SSL** | Certificate expiry, weak protocols, weak ciphers, self-signed certs |

### Engine features
- **Recon phase** — auto-parses `robots.txt`, sitemaps, discovers URLs before crawling
- **Subdomain enumeration** — queries crt.sh certificate transparency logs
- **WAF detection** — detects Cloudflare/bot challenges, avoids false positives
- **WAF evasion** — realistic browser headers, human-like request delays, User-Agent rotation
- **Severity filter** — only shows MEDIUM/HIGH/CRITICAL by default, no noise
- **HTML reports** — minimalist dashboard with charts, exploitation guides, fix recommendations
- **JSON reports** — machine-readable output for automation

---

## Installation

```bash
git clone https://github.com/Adityasiig/WebVulnScanner.git
cd WebVulnScanner
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic scan
python scanner.py -u https://example.com

# Recon + scan (recommended)
python scanner.py -u https://example.com --recon

# Full recon with subdomain enumeration
python scanner.py -u https://example.com --recon --subdomains

# Specific modules only
python scanner.py -u https://example.com --modules sqli,xss,headers

# Skip crawling, test URL directly
python scanner.py -u https://example.com --no-crawl

# Deep scan
python scanner.py -u https://example.com --full --depth 5

# Show only HIGH and CRITICAL
python scanner.py -u https://example.com --min-severity HIGH
```

### All flags

| Flag | Description |
|---|---|
| `-u, --url` | Target URL (required) |
| `-m, --modules` | Comma-separated modules to run (default: all) |
| `--recon` | Run recon phase before crawling (robots.txt + sitemap) |
| `--subdomains` | Enumerate subdomains via crt.sh |
| `--full` | Deep crawl — depth 5, max 100 pages, recon enabled |
| `--depth` | Crawl depth (default: 2) |
| `--max-pages` | Max pages to crawl (default: 30) |
| `--no-crawl` | Skip crawling, scan target URL only |
| `--min-severity` | Minimum severity to report: CRITICAL/HIGH/MEDIUM/LOW/INFO (default: MEDIUM) |
| `-o, --output` | Output directory for reports (default: reports/) |
| `-q, --quiet` | Minimal terminal output |

---

## Project Structure

```
WebVulnScanner/
├── scanner.py                  # CLI entry point
├── requirements.txt
├── core/
│   ├── utils.py                # HTTP client, headers, helpers
│   ├── crawler.py              # Web spider with form extraction
│   ├── recon.py                # robots.txt, sitemap, subdomain recon
│   └── reporter.py             # HTML + JSON report generator
└── modules/
    ├── sqli.py                 # SQL injection (error, time, boolean)
    ├── xss.py                  # Cross-site scripting
    ├── headers.py              # Security headers + WAF-aware detection
    ├── sensitive.py            # Sensitive files + WAF baseline detection
    ├── directory_traversal.py  # Path traversal / LFI
    ├── redirect.py             # Open redirect
    └── ssl_check.py            # SSL/TLS analysis
```

---

## Reports

Reports are saved to `reports/` as both HTML and JSON.

The HTML report includes:
- Severity breakdown with chart
- Per-finding exploitation guides (step by step, beginner friendly)
- Tool requirements per finding
- Fix recommendations
- Search and filter by severity

---

## Disclaimer

This tool is for **authorized penetration testing and educational purposes only**.
Scanning systems without explicit written permission is **illegal** in most jurisdictions.
The author is not responsible for any misuse.
