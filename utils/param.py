import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from tqdm import tqdm

WAYBACK_API = "http://web.archive.org/cdx/search/cdx"

# Regex de LinkFinder para encontrar URLs con parámetros
URL_PARAM_REGEX = r"[\"']((?:https?:)?\/\/[^\"']+\?[^\s\"'>]+)[\"']"

# Colores para salida en consola
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Parámetros comúnmente irrelevantes para pruebas (resolución, formato, etc.)
BORING_PARAMS = {
    "impolicy", "imformat", "fp_height", "height", "width", "resize",
    "format", "quality", "crop", "bgcolor", "fillcolor", "canvas", "cache",
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico", ".ttf", ".eot", ".mp4", ".webm", ".pdf"
}

def get_wayback_urls(domain):
    print(f"[*] Searching for parameters: {domain}")
    try:
        response = requests.get(WAYBACK_API, params={
            "url": domain + "/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey"
        }, timeout=10)
        response.raise_for_status()
        if response.status_code == 200:
            urls = list(set([entry[0] for entry in response.json()[1:]]))
            return urls
    except requests.exceptions.RequestException as e:
        print(f"[!] Error in Wayback Machine for the URL {domain}: {e}")
    except Exception as e:
        print(f"[!] Unknown error in Wayback Machine for the URL  {domain}: {e}")
    return []

def crawl_site(url,headers):
    print(f"[*] Crawling site: {url}")
    visited = set()
    urls = set()
    queue = [url]

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for _ in tqdm(range(50), desc="Crawling"):
        if not queue:
            break
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        try:
            res = requests.get(current, headers=headers, timeout=5)
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
            # Extraer también con regex desde el HTML/JS
            found = re.findall(URL_PARAM_REGEX, res.text)
            for f in found:
                if "?" in f:
                    full = f if f.startswith("http") else urljoin(base, f)
                    urls.add(full)
        except requests.exceptions.RequestException as e:
            print(f"[!] Network error while accessing {current}: {e}")
        except Exception as e:
            print(f"[!] Error processing {current}: {e}")
            continue

    return list(urls)

def is_same_domain(base_url, test_url):
    base_netloc = urlparse(base_url).netloc
    test_netloc = urlparse(test_url).netloc
    return test_netloc.endswith(base_netloc)

def extract_params(target_url, headers):
    all_urls = set()
    
    wayback_urls = get_wayback_urls(target_url)
    if wayback_urls:
        all_urls.update(wayback_urls)
    else:
        print(f"[!] Could not retrieve URLs from Wayback for {target_url}")

    crawled_urls = crawl_site(target_url,headers)
    if crawled_urls:
        all_urls.update(crawled_urls)
    else:
        print(f"[!] Could not retrieve URLs during crawling for {target_url}")

    print(f"\n[+] Total URLs found: {len(all_urls)}")

    urls_with_params = [
        u for u in all_urls 
        if "?" in u and "=" in u and is_same_domain(target_url, u)
    ]

    unique_param_urls = []
    seen_param_signatures = set()
    for url in urls_with_params:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query = parsed.query.split('&')
        for param in query:
            key = param.split("=")[0].lower()
            if key in BORING_PARAMS:
                continue  # Ignorar parámetros irrelevantes
            signature = f"{base}?{key}="
            if signature not in seen_param_signatures:
                seen_param_signatures.add(signature)
                clean_url = f"{base}?{param}"
                print(f"[{CYAN}+{RESET}] Param URL found: {clean_url}")
                unique_param_urls.append(clean_url)

    print(f"[+] Found {len(unique_param_urls)} unique URLs with parameters (excluding non-injectables).\n")
    return unique_param_urls
