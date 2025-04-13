import sys
import signal
import argparse
from injector import test_parameters
from utils.param import extract_params
from urllib.parse import urlparse
from fuzzer import fuzz_from_file

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Handle Ctrl+C interruption
def signal_handler(sig, frame):
    print(f"\n{RED}[!] Interrupción detectada. Cerrando herramienta...{RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ASCII Art Banner
def banner():
    print(f"""
{CYAN}
███╗   ██╗███████╗██╗     ██╗   ██╗██╗  ██╗
████╗  ██║██╔════╝██║     ██║   ██║╚██╗██╔╝
██╔██╗ ██║█████╗  ██║     ██║   ██║ ╚███╔╝ 
██║╚██╗██║██╔══╝  ██║     ██║   ██║ ██╔██╗   1NJECT0R
██║ ╚████║███████╗███████╗╚██████╔╝██╔╝ ██╗
╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
Nelux 1nject0r - Param Filter Checker By Marcos Suarez V1.0
{RESET}
    """)

# Validate if the URL is at least well-formed
def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme and parsed.netloc

def process_url(url, threads):
    if not is_valid_url(url):
        print(f"{RED}[!] URL inválida: {url}{RESET}")
        return

    try:
        urls_con_param = extract_params(url)
        if not urls_con_param:
            print(f"{RED}[!] No se encontraron parámetros inyectables en: {url}{RESET}")
            return
        test_parameters(urls_con_param, threads)
    except Exception as e:
        print(f"{RED}[!] Error procesando la URL {url}: {e}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="Nelux 1nject0r - Param Filter Checker")
    parser.add_argument('-u', '--url', type=str, help="Single URL to check")
    parser.add_argument('-l', '--list', type=str, help="File containing a list of URLs to check")
    parser.add_argument('-t', '--threads', type=int, default=1, help="Number of threads to use (default: 1)")
    parser.add_argument("-w", '--wordlist', dest="word", help="wordlist of payloads",action= 'store' )
    args = parser.parse_args()

    banner()

    if args.url:
        print(f"{CYAN}[*] Escaneando URL individual: {args.url}{RESET}")
        process_url(args.url, args.threads)
        if args.word:
         fuzz_from_file(args.word, args.threads)

    elif args.list:
        try:
            with open(args.list, 'r') as file:
                urls = file.readlines()
                print(f"{CYAN}[*] Escaneando URLs desde archivo: {args.list}{RESET}")
                for url in urls:
                    url = url.strip()
                    if url:
                        process_url(url, args.threads)
            if args.word:
                 fuzz_from_file(args.word, args.threads)                                   
        except FileNotFoundError:
            print(f"{RED}[!] Archivo no encontrado: {args.list}{RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}[!] Error leyendo el archivo: {e}{RESET}")
            sys.exit(1)
    
    else:
        print(f"{RED}[!] Por favor especificá una URL con -u o un archivo con -l.{RESET}")

         
if __name__ == "__main__":
    main()
