from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading, html
import urllib.parse
from urllib.parse import urlparse, parse_qs
import requests, glob, os, sys, json
from urllib3.exceptions import InsecureRequestWarning
import printer as P
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Colors
RED    = "\033[91m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

lock = threading.Lock()
vulnerable_count = 0
stop_event = threading.Event()  # Set on Ctrl+C to stop all fuzz workers fast
DEFAULT_FUZZ_THREADS = max(4, min(12, (os.cpu_count() or 4) * 2))

def load_payloads(wordlist_path):
    try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        P.log(f"{RED}[!] Failed to open the wordlist: {wordlist_path}{RESET}")
        return []

def load_fuzz_targets(pattern="*_parameters.txt"):
    targets = []
    for file in glob.glob(pattern):
        with open(file, 'r') as f:
            targets += [line.strip() for line in f if "FUZZ" in line]
    return targets

def is_vulnerable(response, payload):
    """
    Returns (True, vuln_type) only on confirmed vulnerability signals.
    - XSS: payload is reflected and contains executable XSS markers.
    - SQLi: known DB error signatures in server response.
    - SSTI: known SSTI probe appears evaluated in server response.
    """
    decoded = html.unescape(response.text)

    payload_lower = payload.lower()
    xss_indicators = ['<script', '<img', '<svg', '<body', '<iframe', '<details', 'onload=', 'onerror=', 'ontoggle=', 'alert(', 'prompt(', 'confirm(', 'javascript:']
    ssti_expected = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "#{7*7}": "49",
        "{{1338-1}}": "1337",
        "${1338-1}": "1337",
        "#{1338-1}": "1337",
    }

    # --- XSS: strict reflected execution-style payload ---
    if payload in decoded and any(indicator in payload_lower for indicator in xss_indicators):
        return True, "XSS"

    # --- SSTI: strict evaluation signal ---
    expected = ssti_expected.get(payload)
    if expected is not None:
        # Must contain evaluated marker; and original probe should not be the only thing present.
        if expected in decoded and payload not in decoded:
            return True, "SSTI"
        if expected in decoded and any(token in decoded.lower() for token in ["template", "jinja", "twig", "freemarker", "velocity"]):
            return True, "SSTI"

    # --- SQLi: error-based check (does NOT need reflection) ---
    sql_indicators = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysqli_sql_exception",
        "unclosed quotation mark after the character string",
        "microsoft ole db provider for sql server",
        "sqlstate[",
        "odbc sql server driver",
        "ora-01756",
        "ora-00933",
        "pg_query(",
        "postgresql",
        "psql:",
        "sqlite error",
        "sqlite_exception",
        "unterminated string constant",
        "quoted string not properly terminated"
    ]
    body_lower = response.text.lower()
    if any(err in body_lower for err in sql_indicators):
        return True, "SQLi"

    return False, None

def get_domain_filename(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]   # remove port
    parts = domain.split(".")
    root = parts[-2] if len(parts) >= 2 else parts[0]
    return f"{root}_vulnerables.txt"

def test_payload(target_url, payload, headers, session=None, method="GET", output_format="txt"):
    global vulnerable_count
    test_url = target_url.replace("FUZZ", payload)
    encoded_payload = urllib.parse.quote(payload, safe='')
    encoded_url = target_url.replace("FUZZ", encoded_payload)

    try:
        if stop_event.is_set():
            return False
        if method == "POST":
            req = session.post if session else requests.post
            response = req(target_url, data={"FUZZ": payload}, headers=headers, timeout=10)
        else:
            req = session.get if session else requests.get
            response = req(test_url, headers=headers, timeout=10)

        is_vuln, vuln_type = is_vulnerable(response, payload)

        if is_vuln:
            with lock:
                vulnerable_count += 1
                vuln_file_base = get_domain_filename(target_url).replace("_vulnerables.txt", "")
                entry = {
                    "type": vuln_type,
                    "method": method,
                    "url": encoded_url,
                    "payload": payload
                }
                if output_format == "json":
                    json_file = vuln_file_base + "_vulnerables.json"
                    # Read existing entries and append new one
                    existing = []
                    if os.path.exists(json_file):
                        try:
                            with open(json_file, "r") as jf:
                                existing = json.load(jf)
                        except Exception:
                            existing = []
                    existing.append(entry)
                    with open(json_file, "w") as jf:
                        json.dump(existing, jf, indent=2)
                else:
                    txt_file = vuln_file_base + "_vulnerables.txt"
                    with open(txt_file, "a") as out:
                        out.write(f"[{vuln_type}] [{method}] {encoded_url} | Payload: {payload}\n")

            # Send output to print queue (automatically clears spinner first)
            P.log(f"{RED}[VULN: {vuln_type}]{RESET}")
            P.log(f"   {CYAN}Method :{RESET} {method}")
            P.log(f"   {CYAN}Payload:{RESET} {payload}")
            P.log(f"   {CYAN}URL    :{RESET} {encoded_url}")
            P.log("")
            return True
        return False

    except RequestException:
        return False

def fuzz_single_target(url_with_fuzz, payloads, headers, output_format="txt", fuzz_threads=DEFAULT_FUZZ_THREADS):
    global vulnerable_count

    total = len(payloads)
    session = requests.Session()
    session.verify = False

    vuln_found = False
    progress = 0

    executor = ThreadPoolExecutor(max_workers=max(1, min(fuzz_threads, total)))
    try:
        futures = {executor.submit(test_payload, url_with_fuzz, p, headers, session, "GET", output_format): p for p in payloads}

        for future in as_completed(futures):
            if stop_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            payload = futures[future]
            progress += 1

            if not vuln_found:
                short = payload[:45]
                P.spin(f"{CYAN}[~]{RESET} {progress}/{total} │ {short}")

            try:
                if future.result():
                    vuln_found = True
            except Exception:
                pass
    finally:
        if stop_event.is_set():
            executor.shutdown(wait=False, cancel_futures=True)
        else:
            executor.shutdown(wait=True)

    # Clear the spinner line when done
    P.clear_spin()
    return vuln_found
