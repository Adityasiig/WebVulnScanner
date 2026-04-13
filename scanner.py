#!/usr/bin/env python3
"""
WebVulnScan  - Web Vulnerability Scanner
Built for educational purposes on Kali Linux.

Usage:
    python3 scanner.py -u <target_url>
    python3 scanner.py -u <target_url> --modules sqli,xss,headers
    python3 scanner.py -u <target_url> --full --depth 3
"""

import sys
import os
import argparse
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init as colorama_init, Fore, Style
from core.utils import normalize_url, print_banner, print_section, print_status, print_error, print_info
from core.crawler import Crawler
from core.reporter import generate_report
from core.recon import run_recon

from modules import sqli, xss, headers, sensitive, directory_traversal, redirect, ssl_check

colorama_init(autoreset=True)

AVAILABLE_MODULES = {
    "sqli": ("SQL Injection", sqli),
    "xss": ("Cross-Site Scripting", xss),
    "headers": ("Security Headers", headers),
    "sensitive": ("Sensitive Files", sensitive),
    "traversal": ("Directory Traversal", directory_traversal),
    "redirect": ("Open Redirect", redirect),
    "ssl": ("SSL/TLS Analysis", ssl_check),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScan  - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -u https://example.com
  python3 scanner.py -u https://example.com --modules sqli,xss
  python3 scanner.py -u https://example.com --full --depth 5 --max-pages 100
  python3 scanner.py -u https://example.com --no-crawl --modules headers,sensitive,ssl

Available modules: sqli, xss, headers, sensitive, traversal, redirect, ssl
        """,
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-m", "--modules", default=None,
                        help="Comma-separated list of modules (default: all)")
    parser.add_argument("--full", action="store_true",
                        help="Run all modules with deep crawling")
    parser.add_argument("--depth", type=int, default=2,
                        help="Crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=30,
                        help="Max pages to crawl (default: 30)")
    parser.add_argument("--no-crawl", action="store_true",
                        help="Skip crawling, only test the target URL")
    parser.add_argument("--recon", action="store_true",
                        help="Run recon phase (robots.txt + sitemap discovery) before crawling")
    parser.add_argument("--subdomains", action="store_true",
                        help="Enumerate subdomains via crt.sh (use with --recon)")
    parser.add_argument("-o", "--output", default="reports",
                        help="Output directory for reports (default: reports)")
    parser.add_argument("--min-severity", default="MEDIUM",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report (default: MEDIUM)")
    parser.add_argument("--json-only", action="store_true",
                        help="Only generate JSON report (no HTML)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Minimal output")

    return parser.parse_args()


def select_modules(module_str):
    if not module_str:
        return AVAILABLE_MODULES

    selected = {}
    for name in module_str.split(","):
        name = name.strip().lower()
        if name in AVAILABLE_MODULES:
            selected[name] = AVAILABLE_MODULES[name]
        else:
            print_error(f"Unknown module: '{name}'")
            print_info(f"Available: {', '.join(AVAILABLE_MODULES.keys())}")
            sys.exit(1)
    return selected


def main():
    args = parse_args()

    if not args.quiet:
        print_banner()

    target = normalize_url(args.url)

    if args.full:
        args.depth = 5
        args.max_pages = 100
        args.recon = True

    modules = select_modules(args.modules)

    print_section("TARGET INFORMATION")
    print_status(f"Target: {target}")
    print_status(f"Modules: {', '.join(name for name, _ in modules.values())}")
    print_status(f"Crawl Depth: {args.depth} | Max Pages: {args.max_pages}")

    from core.utils import make_request
    print_status("Testing connectivity...")
    test_resp = make_request(target)
    if test_resp is None:
        print_error(f"Cannot connect to {target}")
        print_error("Check the URL and your network connection.")
        sys.exit(1)
    print_info(f"Connected! HTTP {test_resp.status_code} | Server: {test_resp.headers.get('Server', 'N/A')}")

    start_time = time.time()

    # --- Recon phase ---
    recon_data = {"extra_urls": [], "subdomains": [], "disallowed_paths": []}
    if getattr(args, "recon", False) and not args.no_crawl:
        print_section("RECON")
        recon_data = run_recon(target, subdomains=getattr(args, "subdomains", False))
        if recon_data["subdomains"]:
            print_info(f"Alive subdomains: {', '.join(recon_data['subdomains'])}")
        if recon_data["extra_urls"]:
            print_info(f"Total URLs to scan from recon: {len(recon_data['extra_urls'])}")

    print_section("CRAWLING")
    if args.no_crawl:
        print_info("Crawling disabled - scanning target URL only")
        all_urls = [target] + recon_data["extra_urls"]
        crawl_data = {"urls": list(dict.fromkeys(all_urls)), "forms": [], "js_files": [], "emails": []}
    else:
        crawler = Crawler(
            target,
            max_depth=args.depth,
            max_pages=args.max_pages,
            seed_urls=recon_data["extra_urls"],
        )
        crawl_data = crawler.crawl()

    if crawl_data.get("emails"):
        print_info(f"Emails found: {', '.join(crawl_data['emails'][:10])}")

    all_findings = []

    for _key, (module_name, module_obj) in modules.items():
        print_section(f"MODULE: {module_name.upper()}")
        try:
            findings = module_obj.scan(target, crawl_data)
            all_findings.extend(findings)
            if not findings:
                print_info("No issues found")
        except KeyboardInterrupt:
            print_error("Scan interrupted by user")
            break
        except Exception as e:
            print_error(f"Module error: {e}")

    # --- Scan alive subdomains ---
    if recon_data["subdomains"]:
        for sub_url in recon_data["subdomains"]:
            print_section(f"SCANNING SUBDOMAIN: {sub_url}")
            sub_crawl = {"urls": [sub_url], "forms": [], "js_files": [], "emails": []}
            for _key, (module_name, module_obj) in modules.items():
                try:
                    findings = module_obj.scan(sub_url, sub_crawl)
                    all_findings.extend(findings)
                except Exception as e:
                    print_error(f"Subdomain module error ({sub_url}): {e}")

    duration = time.time() - start_time

    # --- Severity filter ---
    SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_rank = SEVERITY_RANK.get(args.min_severity, 2)
    filtered_findings = [
        f for f in all_findings
        if SEVERITY_RANK.get(f.get("severity", "INFO"), 0) >= min_rank
    ]
    dropped = len(all_findings) - len(filtered_findings)
    if dropped > 0:
        print_info(f"Filtered out {dropped} LOW/INFO findings (use --min-severity LOW to see all)")

    all_findings = filtered_findings

    print_section("SCAN SUMMARY")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1

    total = len(all_findings)
    print_status(f"Scan completed in {duration:.1f} seconds")
    print_status(f"Total findings: {total}")
    print()

    severity_display = [
        ("CRITICAL", Fore.RED + Style.BRIGHT),
        ("HIGH", Fore.RED),
        ("MEDIUM", Fore.YELLOW),
        ("LOW", Fore.CYAN),
        ("INFO", Fore.BLUE),
    ]
    for sev, color in severity_display:
        count = counts[sev]
        bar = "#" * count + "." * max(0, 20 - count)
        print(f"  {color}{sev:10}{Style.RESET_ALL} {bar} {count}")
    print()

    print_section("GENERATING REPORTS")
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.output)
    json_path, html_path = generate_report(target, all_findings, crawl_data, duration, output_dir)

    print()
    print(f"  {Fore.GREEN}{Style.BRIGHT}Scan complete!{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}HTML Report: {Fore.CYAN}{html_path}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}JSON Report: {Fore.CYAN}{json_path}{Style.RESET_ALL}")
    print()

    if counts["CRITICAL"] > 0:
        print(f"  {Fore.RED}{Style.BRIGHT}[!] {counts['CRITICAL']} CRITICAL vulnerabilities found!{Style.RESET_ALL}")
    elif counts["HIGH"] > 0:
        print(f"  {Fore.RED}[!] {counts['HIGH']} HIGH severity issues found.{Style.RESET_ALL}")
    elif total == 0:
        print(f"  {Fore.GREEN}[+] No vulnerabilities detected. Target appears secure.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}[!] {total} issues found. Review the report.{Style.RESET_ALL}")
    print()


if __name__ == "__main__":
    main()
