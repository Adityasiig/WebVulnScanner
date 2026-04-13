import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from core.utils import print_finding, print_status, print_info

MODULE = "SSL/TLS"

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
]


def scan(target_url, crawl_data):
    print_status("Analyzing SSL/TLS configuration...")
    findings = []

    parsed = urlparse(target_url)
    hostname = parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        finding = {
            "severity": "HIGH",
            "module": MODULE,
            "type": "No HTTPS",
            "url": target_url,
            "parameter": "",
            "payload": "",
            "evidence": f"Site uses {parsed.scheme}://",
            "description": "Site does not use HTTPS  - all traffic is unencrypted",
            "exploitation": (
                "1. Any user on the same network can sniff all traffic in plaintext\n"
                "2. Wireshark: capture on interface, filter 'http'  - see all requests, cookies, passwords\n"
                "3. MITM with Bettercap: bettercap -iface eth0 -eval 'net.sniff on; arp.spoof on'\n"
                "4. Capture login credentials directly from POST requests\n"
                "5. Inject malicious content into any HTTP response (e.g., JavaScript payloads)\n"
                "6. Session hijacking: capture session cookies and replay them"
            ),
        }
        findings.append(finding)
        print_finding("HIGH", MODULE, "Site does not use HTTPS", url=target_url,
                       detail="All traffic transmitted in plaintext")
        return findings

    conn = None
    try:
        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        conn = context.wrap_socket(sock, server_hostname=hostname)
        conn.connect((hostname, port))

        cert = conn.getpeercert()
        cipher = conn.cipher()
        protocol = conn.version()

        print_info(f"Protocol: {protocol} | Cipher: {cipher[0]}")

        if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            finding = {
                "severity": "HIGH",
                "module": MODULE,
                "type": f"Weak Protocol: {protocol}",
                "url": target_url,
                "parameter": "",
                "payload": "",
                "evidence": f"Server supports {protocol}",
                "description": f"{protocol} is deprecated and vulnerable to known attacks",
                "exploitation": (
                    f"1. {protocol} is vulnerable to POODLE, BEAST, or CRIME attacks\n"
                    f"2. Use testssl.sh to enumerate all supported protocols: ./testssl.sh {target_url}\n"
                    f"3. POODLE attack: force downgrade to SSLv3, then decrypt traffic block-by-block\n"
                    f"4. Tool: nmap --script ssl-poodle -p 443 {hostname}\n"
                    f"5. BEAST attack: decrypt TLS 1.0 traffic using chosen-plaintext attack"
                ),
            }
            findings.append(finding)
            print_finding("HIGH", MODULE, f"Weak protocol: {protocol}", url=target_url)

        cipher_name = cipher[0] if cipher else ""
        for weak in WEAK_CIPHERS:
            if weak.lower() in cipher_name.lower():
                finding = {
                    "severity": "HIGH",
                    "module": MODULE,
                    "type": f"Weak Cipher: {cipher_name}",
                    "url": target_url,
                    "parameter": "",
                    "payload": "",
                    "evidence": f"Cipher suite: {cipher_name}",
                    "description": f"Weak cipher '{weak}' detected in use",
                    "exploitation": (
                        f"1. Weak cipher {cipher_name} can be broken with known attacks\n"
                        f"2. RC4: statistical biases allow plaintext recovery (RC4 NOMORE attack)\n"
                        f"3. DES/3DES: Sweet32 birthday attack on 64-bit block ciphers\n"
                        f"4. NULL/EXPORT: no encryption or intentionally weakened encryption\n"
                        f"5. Scan all ciphers: nmap --script ssl-enum-ciphers -p 443 {hostname}"
                    ),
                }
                findings.append(finding)
                print_finding("HIGH", MODULE, f"Weak cipher: {cipher_name}", url=target_url)
                break

        if cert:
            try:
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y")
            days_left = (not_after - datetime.utcnow()).days

            if days_left < 0:
                finding = {
                    "severity": "CRITICAL",
                    "module": MODULE,
                    "type": "Expired SSL Certificate",
                    "url": target_url,
                    "evidence": f"Expired on {not_after.strftime('%Y-%m-%d')}",
                    "description": "SSL certificate has expired  - browsers will show warnings",
                    "exploitation": (
                        "1. Users will see browser warnings and may click through them\n"
                        "2. MITM attack: present your own certificate  - users already trained to ignore warnings\n"
                        "3. Phishing: clone the site with a valid cert, redirect users from the expired domain\n"
                        "4. If the cert is for a wildcard domain, other subdomains are also affected"
                    ),
                }
                findings.append(finding)
                print_finding("CRITICAL", MODULE, "SSL certificate EXPIRED", url=target_url,
                               detail=f"Expired: {not_after.strftime('%Y-%m-%d')}")
            elif days_left < 30:
                finding = {
                    "severity": "MEDIUM",
                    "module": MODULE,
                    "type": "SSL Certificate Expiring Soon",
                    "url": target_url,
                    "parameter": "",
                    "payload": "",
                    "evidence": f"Expires in {days_left} days ({not_after.strftime('%Y-%m-%d')})",
                    "description": f"Certificate expires in {days_left} days",
                    "exploitation": (
                        f"1. Certificate expires in {days_left} days - once expired, browsers show 'not secure' warnings\n"
                        "2. Users trained to click through warnings can become MITM targets\n"
                        "3. An attacker can present their own cert and intercept traffic after expiry\n"
                        "4. Monitor: echo | openssl s_client -connect {hostname}:443 2>/dev/null | openssl x509 -noout -dates\n"
                        "5. Renew immediately using Let's Encrypt: certbot renew"
                    ).replace("{hostname}", hostname),
                }
                findings.append(finding)
                print_finding("MEDIUM", MODULE,
                              f"Certificate expires in {days_left} days", url=target_url)
            else:
                print_info(f"Certificate valid for {days_left} more days")

            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            cn = subject.get("commonName", "N/A")
            issuer_cn = issuer.get("commonName", "N/A")
            print_info(f"Subject: {cn} | Issuer: {issuer_cn}")

            if cn == issuer_cn:
                finding = {
                    "severity": "MEDIUM",
                    "module": MODULE,
                    "type": "Self-Signed Certificate",
                    "url": target_url,
                    "evidence": f"Subject and Issuer both: {cn}",
                    "description": "Self-signed certificate  - not trusted by browsers",
                    "exploitation": (
                        "1. Self-signed certs are not validated by any CA  - MITM is trivial\n"
                        "2. Generate your own self-signed cert and intercept traffic\n"
                        "3. Users must manually trust the cert  - social engineering opportunity\n"
                        "4. Tool: mitmproxy with custom CA cert to intercept all HTTPS traffic"
                    ),
                }
                findings.append(finding)
                print_finding("MEDIUM", MODULE, "Self-signed certificate detected", url=target_url)

    except ssl.SSLError as e:
        finding = {
            "severity": "HIGH",
            "module": MODULE,
            "type": "SSL Error",
            "url": target_url,
            "parameter": "",
            "payload": "",
            "evidence": str(e),
            "description": f"SSL connection error: {e}",
            "exploitation": (
                "1. SSL handshake failure may indicate misconfigured or insecure TLS settings\n"
                "2. Test with: openssl s_client -connect {host}:443\n"
                "3. Scan all ciphers/protocols: nmap --script ssl-enum-ciphers -p 443 {host}\n"
                "4. Full TLS audit: testssl.sh {target}"
            ).replace("{host}", hostname).replace("{target}", target_url),
        }
        findings.append(finding)
        print_finding("HIGH", MODULE, f"SSL error: {e}", url=target_url)
    except socket.timeout:
        print_info("SSL connection timed out")
    except Exception as e:
        print_info(f"SSL check skipped: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return findings
