import requests
import re, sys, random,time
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import parse_qs, urljoin, urlparse
from colorama import ansi, init

init()

WAYBACK_API = "http://web.archive.org/cdx/search/cdx"
URL_PARAM_REGEX = r"[\"']((?:https?:)?\/\/[^\"']+\?[^\s\"'>]+)[\"']"

CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"
RED = "\033[91m"

BORING_PARAMS = {
    "impolicy", "imformat", "fp_height", "height", "width", "resize",
    "format", "quality", "crop", "bgcolor", "fillcolor", "canvas", "cache"
}

STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ico", ".ttf", ".eot", ".mp4", ".webm", ".pdf"
)

def check_url_alive(url, headers):
    try:
        parsed = urlparse(url)
        if not parsed.netloc or "." not in parsed.netloc:
            raise ValueError("Invalid hostname")

        res = requests.head(url, headers=headers, timeout=10, allow_redirects=True)
        if res.status_code < 400:
            sys.stdout.write(f"\r\033[K{CYAN}Alive:{RESET} {url[:100]}")
            sys.stdout.flush()
            return url
    except Exception as e:
        #print(f"\n{RED}[!] Error processing the URL {url}: {RESET}{e}")
        pass
        return None

def filter_alive_urls(urls, headers, threads=50):
    print(f"\n{CYAN}[*]{RESET} Checking URLs are alive with {threads} threads...")
    alive_urls = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_url_alive, url, headers): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive_urls.append(result)
    return alive_urls

def is_static_resource(url):
    parsed = urlparse(url)
    return parsed.path.lower().endswith(STATIC_EXTENSIONS)

def get_wayback_urls(domain):
    print(f"{CYAN}[*]{RESET} Searching for parameters")

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:112.0) Gecko/20100101 Firefox/112.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/18.19041",
    ]

    for attempt in range(1, 4):  # 3 intentos
        try:
            headers = {
                "User-Agent": random.choice(USER_AGENTS)
            }
            timeout = 10 + attempt * 5  # 15, 20, 25 segundos
            #print(f"{CYAN}[*]{RESET} Attempt {attempt}: Querying Wayback for {domain} (timeout={timeout}s)")

            response = requests.get(WAYBACK_API, params={
                "url": domain + "/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey"
            }, headers=headers, timeout=timeout)

            response.raise_for_status()

            if response.status_code == 200:
                urls = list(set([entry[0] for entry in response.json()[1:]]))
                for url in urls:
                    sys.stdout.write(f"\r\033[K{CYAN}Searching:{RESET} {url[:100]}...")
                    sys.stdout.flush()
                return urls

        except requests.exceptions.RequestException as e:
            #print(f"{YELLOW}[!] Attempt {attempt} failed:{RESET} {e}")
            time.sleep(1.5 * attempt)

    print(f"{RED}[!] Error in Wayback Machine for the URL{RESET} {domain}: All attempts failed.")
    return []


def crawl_site(url, headers):
    print(f"{CYAN}[*]{RESET} Crawling site")
    visited = set()
    urls = set()
    queue = [url]

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    count = 0
    while queue and count < 50:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        try:
            sys.stdout.write(f"\r\033[K{CYAN}Crawling:{RESET} {current[:100]}...")
            sys.stdout.flush()
            res = requests.get(current, headers=headers, timeout=15)
            res.raise_for_status()
            base = res.url
            soup = BeautifulSoup(res.text, "html.parser")
            for tag in soup.find_all(["a", "script", "link", "iframe"]):
                attr = tag.get("href") or tag.get("src")
                if attr:
                    full_url = urljoin(base, attr)
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        if full_url not in visited:
                            queue.append(full_url)
                            urls.add(full_url)
            found = re.findall(URL_PARAM_REGEX, res.text)
            for f in found:
                if "?" in f:
                    full = f if f.startswith("http") else urljoin(base, f)
                    urls.add(full)
        except requests.exceptions.RequestException as e:
            print(f"\n{RED}[!] Network error while accessing{RESET} {current}: {e}")
        except Exception as e:
            print(f"\n{RED}[!] Error processing{RESET} {current}: {e}")
            continue
        count += 1
    return list(urls)

def is_same_domain(base_url, test_url):
    base_netloc = urlparse(base_url).netloc
    test_netloc = urlparse(test_url).netloc
    return test_netloc.endswith(base_netloc)

def extract_params(target_url, headers):
    all_urls = set()

    wayback_urls = get_wayback_urls(target_url)
    if wayback_urls:
        wayback_urls = filter_alive_urls(wayback_urls, headers)
        all_urls.update(wayback_urls)

    crawled_urls = crawl_site(target_url, headers)
    if crawled_urls:
        all_urls.update(crawled_urls)

    print(f"\n{CYAN}[+]{RESET} Total URLs found: {len(all_urls)}")

    urls_with_params = [
        u for u in all_urls
        if "?" in u and "=" in u and is_same_domain(target_url, u) and not is_static_resource(u)
    ]

    unique_param_urls = []
    seen_signatures = set()
    for url in urls_with_params:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_dict = parse_qs(parsed.query)
        for key in query_dict:
            if key.lower() in BORING_PARAMS:
                continue
            signature = f"{parsed.netloc}|{parsed.path}|{key.lower()}"
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            value = query_dict[key][0] if query_dict[key] else "FUZZ"
            clean_url = f"{base}?{key}={value}"
            unique_param_urls.append(clean_url)

    print(f"{CYAN}[+]{RESET} Found {len(unique_param_urls)} unique URLs with parameters (excluding non-injectables)")
    return unique_param_urls
