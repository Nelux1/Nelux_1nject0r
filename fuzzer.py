import requests
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
import threading

# Colores para salida
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

lock = threading.Lock()  # Para sincronizar impresión y escritura
vulnerable_count = 0     # Contador de URLs vulnerables

def load_payloads(wordlist_path):
    try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[!] Failed to open the wordlist: {wordlist_path}{RESET}")
        return []

def load_fuzz_targets():
    try:
        with open("parameters.txt", "r") as f:
            return [line.strip() for line in f if "FUZZ" in line]
    except FileNotFoundError:
        print(f"{RED}[!] parameters.txt file not found{RESET}")
        return []

def is_vulnerable(response, payload):
    if response.status_code == 500:
        return True
    if payload in response.text:
        return True
    if "SQL syntax" in response.text or "Warning: mysql" in response.text.lower():
        return True
    return False

def test_payload(target_url, payload, headers):
    global vulnerable_count
    test_url = target_url.replace("FUZZ", payload)
    try:
        response = requests.get(test_url,headers=headers, timeout=5)
        if is_vulnerable(response, payload):
            with lock:
                print(f"{RED}[VULNERABLE]{RESET} {test_url}")
                with open("vulnerables.txt", "a") as out:
                    out.write(test_url + "\n")
                vulnerable_count += 1
        else:
            with lock:
                print(f"{GREEN}[✓]{RESET} {test_url}")
    except RequestException as e:
        with lock:
            print(f"{RED}[!] Error with {test_url}: {e}{RESET}")

def fuzz_from_file(wordlist_path, threads,  headers=None):
    global vulnerable_count
    vulnerable_count = 0  # Reiniciar al comenzar
    fuzz_targets = load_fuzz_targets()
    payloads = load_payloads(wordlist_path)

    if not fuzz_targets or not payloads:
        return

    print(f"{CYAN}[*] Starting fuzzing with {len(payloads)} payloads using {threads} threads...{RESET}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for target_url in fuzz_targets:
            for payload in payloads:
                executor.submit(test_payload, target_url, payload, headers)

    print(f"\n{CYAN}[*] Fuzzing completed. Vulnerable URLs found: {RED}{vulnerable_count}{RESET}")

