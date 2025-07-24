from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
import threading, html
import urllib.parse
from colorama import ansi, init
from urllib.parse import urlparse, parse_qs
import requests, glob, os, sys
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

init()

# Colores
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

lock = threading.Lock()
vulnerable_count = 0

def load_payloads(wordlist_path):
    try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[!] Failed to open the wordlist: {wordlist_path}{RESET}")
        return []

def load_fuzz_targets(pattern="*_parameters.txt"):
    targets = []
    for file in glob.glob(pattern):
        with open(file, 'r') as f:
            targets += [line.strip() for line in f if "FUZZ" in line]
    return targets

def is_vulnerable(response, payload):
    reflected = payload in response.text
    html_decoded_reflection = html.unescape(response.text)

    if reflected:
        if payload not in html_decoded_reflection:
            return False

        xss_indicators = ['<script', 'onerror=', 'onload=', 'javascript:', '<img', '<svg', '<iframe']
        if any(indicator in html_decoded_reflection.lower() for indicator in xss_indicators):
            return True

        sql_indicators = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "ORA-",
            "SQLSTATE"
        ]
        if any(err in response.text.lower() for err in sql_indicators):
            return True

    if response.status_code == 500 and any(err in response.text.lower() for err in ["exception", "traceback", "fatal"]):
        return True

    return False

def get_domain_filename(url):
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").split(":")[0]
    domain = domain.split(".")[0]
    return f"{domain}_vulnerables.txt"

def test_payload(target_url, payload, headers):
    global vulnerable_count
    test_url = target_url.replace("FUZZ", payload)
    encoded_payload = urllib.parse.quote(payload, safe='')
    encoded_url = target_url.replace("FUZZ", encoded_payload)

    try:
        response = requests.get(test_url, headers=headers, timeout=5)

        with lock:
            sys.stdout.write(f"\r\033[K{CYAN}Testing:{RESET} {encoded_url[:100]}...")
            sys.stdout.flush()

        if is_vulnerable(response, payload):
            with lock:
                sys.stdout.write('\r' + ansi.clear_line())
                sys.stdout.flush()
                print(f"{RED}[VULNERABLE]{RESET} {encoded_url}")
                vuln_file = get_domain_filename(target_url)
                with open(vuln_file, "a") as out:
                    out.write(test_url + "\n")
                vulnerable_count += 1
            return True
        return False

    except RequestException:
        return False

def fuzz_from_file(wordlist_path, threads, headers=None):
    global vulnerable_count
    vulnerable_count = 0
    fuzz_targets = load_fuzz_targets()
    payloads = load_payloads(wordlist_path)

    if not fuzz_targets or not payloads:
        return

    print(f"{CYAN}[*] Starting fuzzing with {len(payloads)} payloads using {threads} threads...{RESET}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for target_url in fuzz_targets:
            parsed = urlparse(target_url)
            query = parse_qs(parsed.query)

            # Evitar repetir tests en el mismo param+payload aunque venga con otra URL
            already_exploited = set()

            for param in query:
                url_with_fuzz = target_url.replace(query[param][0], "FUZZ") if query[param] else target_url

                for payload in payloads:
                    key = (param, payload)
                    if key in already_exploited:
                        continue

                    if test_payload(url_with_fuzz, payload, headers):
                        already_exploited.add(key)
                        break  # Explotó → no seguimos con más payloads para este parámetro

    sys.stdout.write('\r' + ansi.clear_line())
    sys.stdout.flush()
    print(f"\n{CYAN}[*] Fuzzing completed. Vulnerable URLs found: {RED}{vulnerable_count}{RESET}")
