import random
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

requests.packages.urllib3.disable_warnings()

USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.60 Mobile Safari/537.36",
]

# Realistic Accept headers per browser type
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
]

# Human-like delay range (seconds) between requests
REQUEST_DELAY = (0.5, 2.0)
_last_request_time = 0

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.BLUE,
}


def get_random_ua():
    return random.choice(USER_AGENTS)


def _human_delay():
    """Throttle requests to mimic human browsing speed."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    delay = random.uniform(*REQUEST_DELAY)
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _last_request_time = time.time()


def make_request(url, method="GET", data=None, headers=None, timeout=15, allow_redirects=True):
    _human_delay()

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    default_headers = {
        "User-Agent": get_random_ua(),
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "Referer": origin,
    }
    if headers:
        default_headers.update(headers)

    try:
        if method.upper() == "GET":
            resp = requests.get(url, headers=default_headers, timeout=timeout,
                                verify=False, allow_redirects=allow_redirects)
        elif method.upper() == "POST":
            resp = requests.post(url, data=data, headers=default_headers,
                                 timeout=timeout, verify=False, allow_redirects=allow_redirects)
        else:
            return None
        return resp
    except requests.exceptions.RequestException:
        return None


def inject_payload_in_url(url, payload):
    """Inject payload into each query parameter of the URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    results = []

    for param in params:
        modified = params.copy()
        modified[param] = [payload]
        new_query = urlencode(modified, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        results.append((new_url, param))

    return results


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def is_same_domain(url, target_domain):
    try:
        return urlparse(url).netloc == target_domain
    except Exception:
        return False


def print_banner():
    banner = (
        f"\n{Fore.CYAN}{Style.BRIGHT}"
        f"  __        __   _    __     __    _         ____\n"
        f"  \\ \\      / /__| |__ \\ \\   / /_ _| |_ __  / ___| ___ __ _ _ __\n"
        f"   \\ \\ /\\ / / _ \\ '_ \\ \\ \\ / / _` | | '_ \\ \\___ \\/ __/ _` | '_ \\\n"
        f"    \\ V  V /  __/ |_) | \\ V / (_| | | | | | ___) | (_| (_| | | | |\n"
        f"     \\_/\\_/ \\___|_.__/   \\_/ \\__,_|_|_| |_||____/ \\___\\__,_|_| |_|\n"
        f"{Style.RESET_ALL}\n"
        f" {Fore.WHITE}[ Web Vulnerability Scanner v1.0 ]{Style.RESET_ALL}\n"
        f" {Fore.YELLOW}[ Educational Use Only ]{Style.RESET_ALL}\n"
    )
    print(banner)


def print_finding(severity, module, message, url="", detail=""):
    color = SEVERITY_COLORS.get(severity, Fore.WHITE)
    tag = f"{color}[{severity}]{Style.RESET_ALL}"
    mod = f"{Fore.MAGENTA}[{module}]{Style.RESET_ALL}"
    print(f"  {tag} {mod} {message}")
    if url:
        print(f"         {Fore.WHITE}URL: {url}{Style.RESET_ALL}")
    if detail:
        print(f"         {Fore.WHITE}Detail: {detail}{Style.RESET_ALL}")
    print()


def print_section(title):
    print(f"\n{Fore.CYAN}{'-' * 60}")
    print(f"  {Style.BRIGHT}{title}")
    print(f"{'-' * 60}{Style.RESET_ALL}\n")


def print_status(message):
    print(f"  {Fore.GREEN}[*]{Style.RESET_ALL} {message}")


def print_error(message):
    print(f"  {Fore.RED}[!]{Style.RESET_ALL} {message}")


def print_info(message):
    print(f"  {Fore.BLUE}[i]{Style.RESET_ALL} {message}")
