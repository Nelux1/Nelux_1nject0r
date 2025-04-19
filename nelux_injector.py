mport sys
import signal
import argparse
from injector import test_parameters
from utils.param import extract_params
from urllib.parse import urlparse
from fuzzer import fuzz_from_file
import random

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Lista básica de User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0)"
]

# Handle Ctrl+C
def signal_handler(sig, frame):
    print(f"\n{RED}[!] Interrupción detectada. Cerrando herramienta...{RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def banner():
    print(f"""
{CYAN}
███╗   ██╗███████╗██╗     ██╗   ██╗██╗  ██╗
████╗  ██║██╔════╝██║     ██║   ██║╚██╗██╔╝
██╔██╗ ██║█████╗  ██║     ██║   ██║ ╚███╔╝ 
██║╚██╗██║██╔══╝  ██║     ██║   ██║ ██╔██╗   1NJECT0R
██║ ╚████║███████╗███████╗╚██████╔╝██╔╝ ██╗
╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
Nelux 1nject0r - Param Filter Checker By Marcos Suarez V2.1
{RESET}
    """)

def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme and parsed.netloc

def build_headers(args):
    headers = {}

    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    if args.random_agent and "User-Agent" not in headers:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0"

    return headers

def process_url(url, threads, headers):
    if not is_valid_url(url):
        print(f"{RED}[!] URL inválida: {url}{RESET}")
        return

    try:
        urls_con_param = extract_params(url, headers)
        if not urls_con_param:
            print(f"{RED}[!] No injectable parameters found in: {url}{RESET}")
            return
        test_parameters(urls_con_param, threads, headers)
    except Exception as e:
        print(f"{RED}[!] Error processing the URL {url}: {e}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="Nelux 1nject0r - Param Filter Checker")
    parser.add_argument('-u', '--url', type=str, help="Single URL to check")
    parser.add_argument('-l', '--list', type=str, help="File containing a list of URLs to check")
    parser.add_argument('-t', '--threads', type=int, default=1, help="Number of threads to use (default: 1)")
    parser.add_argument("-w", '--wordlist', dest="word", help="wordlist of payloads", action='store')
    parser.add_argument("-ra","--random-agent", action="store_true", help="Usar un User-Agent aleatorio")
    parser.add_argument("-H", "--header", action="append", help="Custom header (can be used multiple times)")
    parser.add_argument('-pl', '--param-list', type=str, help="File with URLs that already contain parameters")


    args = parser.parse_args()
    banner()
    headers = build_headers(args)

    if args.url:
        print(f"{CYAN}[*] Scanning URL: {args.url}{RESET}")
        process_url(args.url, args.threads, headers)
        if args.word:
            fuzz_from_file(args.word, args.threads,headers)

    elif args.list:
        try:
            with open(args.list, 'r') as file:
                urls = file.readlines()
                print(f"{CYAN}[*] Scanning URLs from file: {args.list}{RESET}")
                for url in urls:
                    url = url.strip()
                    if url:
                        process_url(url, args.threads, headers)
            if args.word:
                fuzz_from_file(args.word, args.threads,headers)                                   
        except FileNotFoundError:
            print(f"{RED}[!] File not found: {args.list}{RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}[!] Error reading the file: {e}{RESET}")
            sys.exit(1)

    elif args.param_list:
        try:
            with open(args.param_list, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
                print(f"{CYAN}[*] Testing pre-found parameter URLs from file: {args.param_list}{RESET}")
                test_parameters(urls, args.threads, headers)
                if args.word:
                    fuzz_from_file(args.word, args.threads,headers)
        except FileNotFoundError:
            print(f"{RED}[!] File not found: {args.param_list}{RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}[!] Error reading param list file: {e}{RESET}")
            sys.exit(1)
        
    else:
        print(f"{RED}[!] Please specify a URL with -u or a file with -l.{RESET}")

if __name__ == "__main__":
    main()
