from urllib.parse import urlparse
from core.utils import make_request, inject_payload_in_url, print_finding, print_status

MODULE = "OpenRedirect"

REDIRECT_URLS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F%2F",
    "/\\evil.com",
    "https:evil.com",
    "////evil.com",
    "https://evil.com/.example.com",
    "https://example.com@evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url",
    "next", "return", "returnTo", "return_url",
    "goto", "dest", "destination", "redir",
    "continue", "target", "link", "out",
    "forward", "callback", "ref", "page",
]


def scan(target_url, crawl_data):
    print_status("Testing for Open Redirect vulnerabilities...")
    findings = []

    urls_with_params = [u for u in crawl_data.get("urls", []) if "?" in u]

    for url in urls_with_params:
        findings.extend(_test_url_redirect(url))

    findings.extend(_test_common_params(target_url))

    return findings


def _test_url_redirect(url):
    findings = []
    for payload in REDIRECT_URLS:
        injected_urls = inject_payload_in_url(url, payload)
        for injected_url, param in injected_urls:
            param_lower = param.lower()
            if not any(rp in param_lower for rp in REDIRECT_PARAMS):
                continue

            resp = make_request(injected_url, allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if _is_external_redirect(location):
                    finding = {
                        "severity": "MEDIUM",
                        "module": MODULE,
                        "type": "Open Redirect",
                        "url": injected_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Redirects to: {location}",
                        "description": f"Open redirect via param '{param}'  - can be used for phishing",
                        "exploitation": (
                            f"1. Craft phishing URL: https://trusted-site.com/?{param}=https://evil-login.com\n"
                            f"2. The victim sees the trusted domain and clicks  - gets redirected to attacker's site\n"
                            f"3. Clone the target login page on evil-login.com to harvest credentials\n"
                            f"4. Chain with OAuth: redirect_uri=https://evil.com to steal OAuth tokens\n"
                            f"5. Chain with SSRF: redirect to internal services (http://127.0.0.1:8080)\n"
                            f"6. Use URL encoding to bypass filters: https://evil.com%252F%252Ftrusted.com"
                        ),
                    }
                    findings.append(finding)
                    print_finding("MEDIUM", MODULE,
                                  f"Open redirect in param '{param}'",
                                  url=injected_url,
                                  detail=f"Redirects to: {location}")
                    return findings
    return findings


def _test_common_params(base_url):
    findings = []
    base = base_url.rstrip("/")

    for param_name in REDIRECT_PARAMS:
        for payload in REDIRECT_URLS[:3]:
            test_url = f"{base}/?{param_name}={payload}"
            resp = make_request(test_url, allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if _is_external_redirect(location):
                    finding = {
                        "severity": "MEDIUM",
                        "module": MODULE,
                        "type": "Open Redirect (Common Parameter)",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": f"Redirects to: {location}",
                        "description": f"Open redirect via common param '{param_name}'",
                        "exploitation": (
                            f"1. This common parameter '{param_name}' accepts external URLs\n"
                            f"2. Send phishing link: {base}/?{param_name}=https://attacker-login.com\n"
                            f"3. Victim trusts the domain, clicks, gets redirected to fake login\n"
                            f"4. Harvest credentials on the fake page\n"
                            f"5. Can also be used to bypass URL-based access controls"
                        ),
                    }
                    findings.append(finding)
                    print_finding("MEDIUM", MODULE,
                                  f"Open redirect via '{param_name}'",
                                  url=test_url,
                                  detail=f"Redirects to: {location}")
                    break
    return findings


def _is_external_redirect(location):
    if not location:
        return False
    try:
        parsed = urlparse(location)
        if parsed.netloc and "evil.com" in parsed.netloc:
            return True
        if location.startswith("//evil.com"):
            return True
    except Exception:
        pass
    return False
