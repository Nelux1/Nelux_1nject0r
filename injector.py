import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from re import sub

# Characters to test for XSS or SQLi injection
FILTER_CHARS = ['"', "'", '<', '>', '$', '|', '(', ')', '`', ':', ';', '{', '}']

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'


def test_parameter_sanitization(url, param, headers=None):
    """
    Prueba si un parámetro permite caracteres especiales sin filtrar.
    """
    vulnerable_chars = []

    for char in FILTER_CHARS:
        # Reconstruye la URL con el carácter especial en el parámetro específico
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [char]
        new_query = urlencode(query, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            response = requests.get(test_url, timeout=5, headers=headers)
            if response.status_code == 200 and char in response.text:
                vulnerable_chars.append(char)
        except RequestException as e:
            print(f"{RED}[!] Error in request {test_url}: {e}{RESET}")
            continue

    return vulnerable_chars


def detect_injection_type(chars):
    """
    Dado un set de caracteres vulnerables, sugiere el tipo de inyección.
    """
    xss_set = {'<', '>', '"', "'", '`'}
    sqli_set = {"'", '"', ';', '--', '#', '(', ')'}

    if any(c in xss_set for c in chars):
        return 'XSS'
    elif any(c in sqli_set for c in chars):
        return 'SQLi'
    else:
        return 'SQLi or XSS'


def analyze_url(url, headers=None):
    """
    Analiza una única URL y prueba todos sus parámetros.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for param in query_params:
        print(f"{YELLOW}[*] Testing parameter: {param} en {url}{RESET}")
        vulnerable_chars = test_parameter_sanitization(url, param, headers)

        if vulnerable_chars:
            vuln_type = detect_injection_type(vulnerable_chars)
            print(f"{RED}[⚠] Possible vulnerability detected: {vuln_type}{RESET}")
            print(f"{CYAN}URL     : {url}{RESET}")
            print(f"{CYAN}Parameter: {param}{RESET}")
            print(f"{GREEN}No filter: {', '.join(vulnerable_chars)}{RESET}\n")

            query = parse_qs(parsed.query)
            query[param] = ["FUZZ"]
            new_query = urlencode(query, doseq=True)
            clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            clean_url = sub(r'FUZZ\d*', 'FUZZ', clean_url)

            with open("parameters.txt", "a") as f:
                f.write(clean_url + "\n")
        else:
            print(f"{GREEN}[✓] {param} (Not Vulnerable){RESET}\n")


def test_parameters(urls_with_params, threads=20, headers=None):
    """
    Toma una lista de URLs con parámetros y las analiza en paralelo.
    """
    print(f"{CYAN}[*] Starting analysis with {threads} threads...{RESET}\n")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(analyze_url, url, headers) for url in urls_with_params]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"{RED}[!] Error analyzing a parameter: {e}{RESET}")


