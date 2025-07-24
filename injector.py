import requests
from requests.exceptions import RequestException, SSLError, ConnectionError, Timeout
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from re import sub
import urllib.parse
import sys, re
from urllib3.exceptions import InsecureRequestWarning, ProtocolError
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
import threading
from colorama import ansi, init

init()

print_lock = threading.Lock()
tested_urls = set()

FILTER_CHARS = ['"', "'", '<', '>', '$', '|', '(', ')', '`', ':', ';', '{', '}']

RED = '\033[91m'
GREEN = '\033[92m'
CYAN = '\033[96m'
RESET = '\033[0m'

def test_parameter_sanitization(url, param, headers=None):
    vulnerable_chars = []

    for char in FILTER_CHARS:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [char]
        new_query = urlencode(query, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            response = requests.get(test_url, timeout=5, headers=headers, verify=False)
            if response.status_code == 500:
                vulnerable_chars.append(char)
                continue

            if "SQL syntax" in response.text or "Warning: mysql" in response.text.lower():
                vulnerable_chars.append(char)
                continue

            if response.status_code == 200:
                if char in response.text and not any(encoded_char in response.text for encoded_char in [
                    urllib.parse.quote(char),
                    urllib.parse.quote(char, safe=''),
                    char.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
                ]):
                    vulnerable_chars.append(char)

        except (SSLError, ConnectionError, Timeout, ProtocolError):
            continue
        except RequestException:
            continue

    return vulnerable_chars

def detect_injection_type(chars):
    xss_set = {'<', '>', '"', "'", '`'}
    sqli_set = {"'", '"', ';', '--', '#', '(', ')'}

    if any(c in xss_set for c in chars):
        return 'XSS'
    elif any(c in sqli_set for c in chars):
        return 'SQLi'
    else:
        return 'SQLi or XSS'

def sanitize_filename(url):
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").split(":")[0]
    domain = re.sub(r'\.(com|net|org|io|gov|edu|co|ar|uk|es)$', '', domain)
    path = parsed.path.replace('/', '_').strip('_')
    filename = f"{domain}_{path}" if path else domain
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    return f"{filename}_parameters.txt"

def analyze_url(url, headers=None, output_filename=None):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for param in query_params:
        base_query = query_params.copy()
        base_query[param] = ["FUZZ"]
        base_query_encoded = urlencode(base_query, doseq=True)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, base_query_encoded, parsed.fragment))

        test_key = (base_url, param)
        if test_key in tested_urls:
            continue
        else:
            tested_urls.add(test_key)

        vulnerable_chars = test_parameter_sanitization(url, param, headers)

        if vulnerable_chars:
            vuln_type = detect_injection_type(vulnerable_chars)

            print(f"\n{RED}[⚠] Possible vulnerability detected:{RESET}")
            print(f"{CYAN}URL:{RESET} {url}")
            print(f"{CYAN}Parameter:{RESET} {param}")
            print(f"{GREEN}No filter: {', '.join(vulnerable_chars)}{RESET}")
            print()

            query = parse_qs(parsed.query)
            query[param] = ["FUZZ"]
            new_query = urlencode(query, doseq=True)
            clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            clean_url = sub(r'FUZZ\d*', 'FUZZ', clean_url)

            filename = output_filename if output_filename else sanitize_filename(url)
            with open(filename, "a") as f:
                f.write(clean_url + "\n")

def test_parameters(urls_with_params, threads=20, headers=None, output_filename=None):
    #print(f"{CYAN}[*]{RESET} Starting analysis with {threads} threads...\n")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(analyze_url, url, headers, output_filename) for url in urls_with_params]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass
    print(f"\n{CYAN}[*] saved by default in: {RED}{output_filename}{RESET}")
