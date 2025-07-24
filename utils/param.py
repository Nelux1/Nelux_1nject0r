import requests
import re
import json
import urllib3
import sys
import threading
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESET = "\033[0m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"

STATIC_EXTENSIONS = [
    ".jpg", ".jpeg", ".gif", ".css", ".tif", ".tiff", ".png", ".ttf", ".woff", ".woff2", ".ico",
    ".pdf", ".svg", ".txt", ".js", ".mp3", ".mp4", ".avi", ".mov", ".mpeg", ".mpg", ".webp", ".zip", ".rar"
]

BORING_PARAMS = ["utm_", "fbclid", "gclid", "ref", "rss", "session", "cookie"]

def is_static_resource(url):
    return any(url.lower().endswith(ext) for ext in STATIC_EXTENSIONS)

def fetch_sources(domain):
    urls = set()

    def get_from_wayback():
        try:
            r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey", timeout=10)
            if r.status_code == 200:
                for entry in r.json()[1:]:
                    url = entry[0]
                    sys.stdout.write(f"\r\033[K{CYAN}Searching:{RESET} {url[:100]}...")
                    sys.stdout.flush()
                    urls.add(url)
        except:
            pass

    def get_from_robots():
        try:
            r = requests.get(urljoin(domain, "/robots.txt"), timeout=8, verify=False)
            for line in r.text.splitlines():
                if line.lower().startswith("allow") or line.lower().startswith("disallow"):
                    parts = line.split(":")
                    if len(parts) == 2:
                        path = parts[1].strip()
                        full = urljoin(domain, path)
                        sys.stdout.write(f"\r\033[K{CYAN}Searching:{RESET} {full[:100]}...")
                        sys.stdout.flush()
                        urls.add(full)
        except:
            pass

    def get_from_sitemap():
        try:
            r = requests.get(urljoin(domain, "/sitemap.xml"), timeout=10, verify=False)
            sitemap_urls = re.findall(r"<loc>(.*?)</loc>", r.text)
            for u in sitemap_urls:
                sys.stdout.write(f"\r\033[K{CYAN}Searching:{RESET} {u[:100]}...")
                sys.stdout.flush()
                urls.add(u)
        except:
            pass

    def get_from_crtsh():
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        url = "http://" + sub.strip()
                        sys.stdout.write(f"\r\033[K{CYAN}Searching:{RESET} {url[:100]}...")
                        sys.stdout.flush()
                        urls.add(url)
        except:
            pass

    def get_from_commoncrawl():
        try:
            cc_index = "CC-MAIN-2024-10"
            index_url = f"http://index.commoncrawl.org/{cc_index}-index?url=*.{domain}/*&output=json"
            r = requests.get(index_url, timeout=15)
            for line in r.text.splitlines():
                try:
                    data = json.loads(line)
                    url = data.get("url")
                    sys.stdout.write(f"\r\033[K{CYAN}Searching:{RESET} {url[:100]}...")
                    sys.stdout.flush()
                    urls.add(url)
                except:
                    continue
        except:
            pass

    threads = [
        threading.Thread(target=get_from_wayback),
        threading.Thread(target=get_from_robots),
        threading.Thread(target=get_from_sitemap),
        threading.Thread(target=get_from_crtsh),
        threading.Thread(target=get_from_commoncrawl)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return urls

# ✅ SOLO ESTA FUNCIÓN CAMBIADA PARA USAR THREADPOOLEXECUTOR
def check_alive(urls, threads=50):
    alive = []
    lock = threading.Lock()

    def worker(url):
        try:
            r = requests.head(url, timeout=5, verify=False, allow_redirects=True)
            if r.status_code < 400:
                with lock:
                    alive.append(url)
            sys.stdout.write(f"\r\033[K{CYAN}Alive:{RESET} {url[:100]}...")
            sys.stdout.flush()
        except:
            pass

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(worker, urls)

    return alive

def crawl(domain, headers):
    visited = set()
    urls = set()
    try:
        r = requests.get(domain, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        visited.add(domain)
        for tag in soup.find_all(["a", "form"]):
            href = tag.get("href") or tag.get("action")
            if href:
                current = urljoin(domain, href)
                if current in visited:
                    continue
                visited.add(current)
                urls.add(current)
                sys.stdout.write(f"\r\033[K{CYAN}Crawling:{RESET} {current[:100]}.")
                sys.stdout.flush()
    except:
        pass
    return urls

def extract_params(domain, headers, threads):
    seen_params = set()
    final = []

    print(f"{CYAN}[*] Searching for parameters:{RESET}")
    all_urls = fetch_sources(domain)
    alive_urls = check_alive(all_urls, threads)
    crawled = crawl(domain, headers)
    all_urls.update(alive_urls)
    all_urls.update(crawled)

    print(f"\n{GREEN}[+] Total URLs found: {len(all_urls)}{RESET}")

    for url in all_urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs or is_static_resource(url):
            continue
        for param in qs:
            if any(param.lower().startswith(b) for b in BORING_PARAMS):
                continue
            key = f"{parsed.netloc}{parsed.path}?{param}"
            if key in seen_params:
                continue
            seen_params.add(key)
            final.append(url)

    print(f"{GREEN}[+] Found {len(final)} unique URLs with parameters (excluding non-injectables){RESET}")
    print(f"{CYAN}[*] Starting analysis with {threads} threads...{RESET}")
    return final
