from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
import threading,html
import urllib.parse
from urllib.parse import urlparse, parse_qs
import requests,glob
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


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

def load_fuzz_targets(pattern="*_parameters.txt"):
    targets = []
    for file in glob.glob(pattern):
        with open(file, 'r') as f:
            targets += [line.strip() for line in f if "FUZZ" in line]
    return targets


def is_vulnerable(response, payload):
    reflected = payload in response.text
    html_decoded_reflection = html.unescape(response.text)

    # Detectar si la reflexión está escapada o no
    if reflected:
        # Si el payload aparece, pero escapado, ignorar
        if payload not in html_decoded_reflection:
            return False  # Reflejado, pero seguro

        # Detectar patrones sospechosos sin escape
        xss_indicators = ['<script', 'onerror=', 'onload=', 'javascript:', '<img', '<svg', '<iframe']
        if any(indicator in html_decoded_reflection.lower() for indicator in xss_indicators):
            return True

        # Caso especial: SQLi - buscar errores
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

    # Error interno del servidor solo si hay indicios adicionales
    if response.status_code == 500 and any(err in response.text.lower() for err in ["exception", "traceback", "fatal"]):
        return True

    return False


def test_payload(target_url, payload, headers):
    global vulnerable_count
    test_url = target_url.replace("FUZZ", payload)
    # Codificar el payload para la URL
    encoded_payload = urllib.parse.quote(payload, safe='')
    encoded_url = target_url.replace("FUZZ", encoded_payload)
    try:
        response = requests.get(test_url,headers=headers, timeout=5)
        if is_vulnerable(response, payload):
            with lock:
                print(f"{RED}[VULNERABLE]{RESET} {encoded_url}")
                with open("vulnerables.txt", "a") as out:
                    out.write(test_url + "\n")
                vulnerable_count += 1
            return True
        else:
            with lock:
                print(f"{GREEN}[✓]{RESET} {encoded_url}")
            return False
    except RequestException as e:
        with lock:
            print(f"{RED}[!] Error with {encoded_url}: {e}{RESET}")
        return False

def fuzz_from_file(wordlist_path, threads, headers=None):
    global vulnerable_count
    vulnerable_count = 0  # Reiniciar al comenzar
    fuzz_targets = load_fuzz_targets()
    payloads = load_payloads(wordlist_path)

    if not fuzz_targets or not payloads:
        return

    print(f"{CYAN}[*] Starting fuzzing with {len(payloads)} payloads using {threads} threads...{RESET}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for target_url in fuzz_targets:
            # Creamos un set para rastrear parámetros vulnerables
            vulnerable_params = set()
            
            # Extraemos el parámetro de la URL
            parsed = urlparse(target_url)
            query = parse_qs(parsed.query)
            
            for param in query:
                # Si el parámetro ya es vulnerable, lo saltamos
                if param in vulnerable_params:
                    continue
                    
                for payload in payloads:
                    # Creamos una URL de prueba con el payload
                    test_url = target_url.replace("FUZZ", payload)
                    
                    # Si encontramos una vulnerabilidad, marcamos el parámetro y pasamos al siguiente
                    if test_payload(test_url, payload, headers):
                        vulnerable_params.add(param)
                        break  # Salimos del bucle de payloads para este parámetro

    print(f"\n{CYAN}[*] Fuzzing completed. Vulnerable URLs found: {RED}{vulnerable_count}{RESET}")
    print(f"\n{CYAN}[*] saved by default in: {RED}vulnerables.txt {RESET}")
    

