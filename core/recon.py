"""
Recon module — discovers URLs before crawling via:
  - robots.txt parsing (disallowed paths + sitemap links)
  - Sitemap XML parsing (sitemap-index + sitemap)
  - Subdomain enumeration via crt.sh certificate transparency logs
"""

import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin

from core.utils import make_request, print_status, print_info, print_error


# ---------------------------------------------------------------------------
# Robots.txt
# ---------------------------------------------------------------------------

def parse_robots(target_url):
    """
    Fetch robots.txt and return:
      - disallowed_paths : list of disallowed URL paths
      - sitemap_urls     : sitemap URLs found in robots.txt
    """
    robots_url = urljoin(target_url.rstrip("/") + "/", "robots.txt")
    print_status(f"Fetching robots.txt → {robots_url}")

    disallowed = []
    sitemaps = []

    resp = make_request(robots_url)
    if resp is None or resp.status_code != 200:
        print_info("robots.txt not found or blocked")
        return disallowed, sitemaps

    for line in resp.text.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                full_url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
                disallowed.append(full_url)
        elif lower.startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm:
                sitemaps.append(sm)

    print_info(f"robots.txt → {len(disallowed)} disallowed paths, {len(sitemaps)} sitemap(s)")
    return disallowed, sitemaps


# ---------------------------------------------------------------------------
# Sitemap
# ---------------------------------------------------------------------------

def parse_sitemap(sitemap_url, visited=None, depth=0, max_depth=3):
    """
    Recursively parse sitemap / sitemap-index XML.
    Returns a list of page URLs.
    """
    if visited is None:
        visited = set()
    if sitemap_url in visited or depth > max_depth:
        return []
    visited.add(sitemap_url)

    urls = []
    resp = make_request(sitemap_url)
    if resp is None or resp.status_code != 200:
        return urls

    content = resp.text.strip()
    # Strip namespace for simpler parsing
    content_clean = re.sub(r'\sxmlns[^"]*"[^"]*"', "", content)
    content_clean = re.sub(r'<(\w+:)', '<', content_clean)
    content_clean = re.sub(r'</(\w+:)', '</', content_clean)

    try:
        root = ET.fromstring(content_clean)
    except ET.ParseError:
        return urls

    tag = root.tag.lower()

    if "sitemapindex" in tag:
        # Sitemap index — recurse into each child sitemap
        for loc in root.iter("loc"):
            child_url = loc.text.strip() if loc.text else ""
            if child_url:
                urls.extend(parse_sitemap(child_url, visited, depth + 1, max_depth))
    else:
        # Regular sitemap — collect <loc> entries
        for loc in root.iter("loc"):
            page = loc.text.strip() if loc.text else ""
            if page:
                urls.append(page)

    return urls


def discover_sitemap_urls(target_url, extra_sitemap_urls=None):
    """
    Try common sitemap locations + any URLs found in robots.txt.
    Returns deduplicated list of page URLs.
    """
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    candidates = [
        f"{base}/sitemap.xml",
        f"{base}/sitemap-index.xml",
        f"{base}/sitemap_index.xml",
        f"{base}/sitemap/sitemap.xml",
    ]
    if extra_sitemap_urls:
        candidates = list(extra_sitemap_urls) + candidates

    all_urls = []
    tried = set()
    for sm_url in candidates:
        if sm_url in tried:
            continue
        tried.add(sm_url)
        print_status(f"Trying sitemap → {sm_url}")
        found = parse_sitemap(sm_url)
        if found:
            print_info(f"  Found {len(found)} URLs in {sm_url}")
            all_urls.extend(found)

    deduped = list(dict.fromkeys(all_urls))  # preserve order, remove dupes
    print_info(f"Sitemap total: {len(deduped)} unique URLs discovered")
    return deduped


# ---------------------------------------------------------------------------
# Subdomain enumeration via crt.sh
# ---------------------------------------------------------------------------

def enumerate_subdomains(domain):
    """
    Query crt.sh certificate transparency logs to find subdomains.
    Returns list of unique subdomain URLs (https://sub.domain.com).
    """
    print_status(f"Querying crt.sh for subdomains of {domain} ...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    resp = make_request(url, timeout=20)
    if resp is None or resp.status_code != 200:
        print_info("crt.sh query failed — skipping subdomain enumeration")
        return []

    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError:
        print_info("crt.sh returned invalid JSON")
        return []

    subdomains = set()
    for entry in data:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lstrip("*.")
            if sub and domain in sub and " " not in sub:
                subdomains.add(sub)

    print_info(f"crt.sh → {len(subdomains)} subdomains found")

    # Probe each subdomain to see if it's alive
    alive = []
    for sub in sorted(subdomains):
        sub_url = f"https://{sub}"
        resp = make_request(sub_url, timeout=8)
        if resp is not None:
            print_info(f"  [ALIVE] {sub_url} — HTTP {resp.status_code}")
            alive.append(sub_url)
        else:
            # Try HTTP fallback
            sub_url_http = f"http://{sub}"
            resp = make_request(sub_url_http, timeout=8)
            if resp is not None:
                print_info(f"  [ALIVE] {sub_url_http} — HTTP {resp.status_code}")
                alive.append(sub_url_http)

    print_info(f"Alive subdomains: {len(alive)}")
    return alive


# ---------------------------------------------------------------------------
# Main recon runner
# ---------------------------------------------------------------------------

def run_recon(target_url, subdomains=False):
    """
    Run full recon phase. Returns dict with:
      - extra_urls      : all discovered page URLs (robots + sitemap)
      - subdomains      : alive subdomain URLs
      - disallowed_paths: raw disallowed paths from robots.txt
    """
    parsed = urlparse(target_url)
    domain = parsed.netloc

    print_status("Starting recon phase...")

    # 1. robots.txt
    disallowed_paths, sitemap_hints = parse_robots(target_url)

    # 2. Sitemaps
    sitemap_urls = discover_sitemap_urls(target_url, extra_sitemap_urls=sitemap_hints)

    # 3. Filter sitemap URLs to same domain only
    same_domain_urls = [
        u for u in sitemap_urls
        if urlparse(u).netloc == domain
    ]

    # 4. Merge disallowed paths + sitemap URLs
    all_extra = list(dict.fromkeys(disallowed_paths + same_domain_urls))

    # 5. Subdomain enum (optional)
    alive_subs = []
    if subdomains:
        alive_subs = enumerate_subdomains(domain)

    return {
        "extra_urls": all_extra,
        "subdomains": alive_subs,
        "disallowed_paths": disallowed_paths,
    }
