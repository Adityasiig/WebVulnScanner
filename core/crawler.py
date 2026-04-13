import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from core.utils import make_request, is_same_domain, print_status, print_info


class Crawler:
    def __init__(self, target_url, max_depth=3, max_pages=50, seed_urls=None):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.urls = set()
        self.forms = []
        self.js_files = set()
        self.emails = set()
        # Pre-seed with recon-discovered URLs (robots.txt, sitemap, etc.)
        self.seed_urls = seed_urls or []

    def crawl(self):
        print_status(f"Crawling {self.target_url} (depth={self.max_depth}, max={self.max_pages})")

        # Add recon-discovered URLs to the queue first
        if self.seed_urls:
            print_info(f"Pre-seeding crawler with {len(self.seed_urls)} recon URLs")
            for url in self.seed_urls:
                if len(self.visited) < self.max_pages:
                    self._crawl_recursive(url, depth=1)

        # Then crawl from the target root
        self._crawl_recursive(self.target_url, depth=0)
        print_info(f"Found {len(self.urls)} URLs, {len(self.forms)} forms, {len(self.js_files)} JS files")
        return {
            "urls": list(self.urls),
            "forms": self.forms,
            "js_files": list(self.js_files),
            "emails": list(self.emails),
        }

    def _crawl_recursive(self, url, depth):
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        if not is_same_domain(url, self.domain):
            return

        self.visited.add(url)
        self.urls.add(url)

        try:
            resp = make_request(url)
            if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
                return

            soup = BeautifulSoup(resp.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                link = urljoin(url, tag["href"])
                link = link.split("#")[0].rstrip("/")
                if is_same_domain(link, self.domain) and link not in self.visited:
                    self.urls.add(link)
                    self._crawl_recursive(link, depth + 1)

            for form in soup.find_all("form"):
                form_data = self._extract_form(form, url)
                if form_data:
                    self.forms.append(form_data)

            for script in soup.find_all("script", src=True):
                js_url = urljoin(url, script["src"])
                self.js_files.add(js_url)

            emails_found = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", resp.text))
            self.emails.update(emails_found)
        except Exception as e:
            print_info(f"Skipped {url}: {e}")

    def _extract_form(self, form, page_url):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        action_url = urljoin(page_url, action) if action else page_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_type = inp.get("type", "text")
            input_name = inp.get("name", "")
            input_value = inp.get("value", "")
            if input_name:
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value,
                })

        if not inputs:
            return None

        return {
            "action": action_url,
            "method": method,
            "inputs": inputs,
            "page": page_url,
        }
