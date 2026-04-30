#!/usr/bin/env python3

import sys, re
import signal
import argparse
import os
from injector import test_parameters
from utils.param import extract_params
from urllib.parse import urlparse
from fuzzer import load_payloads, stop_event as fuzz_stop
import printer as P
import random

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[1;36m"
RESET = "\033[0m"

# Basic list of User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0)"
]

# Handle Ctrl+C
_sigint_count = 0

def signal_handler(sig, frame):
    global _sigint_count
    _sigint_count += 1
    fuzz_stop.set()   # ask workers to stop as soon as possible

    if _sigint_count == 1:
        P.log(f"\n{RED}[!] Interruption detected. Stopping... (press Ctrl+C again to force quit){RESET}")
        return

    # Force immediate exit on repeated Ctrl+C, avoiding noisy shutdown tracebacks.
    os._exit(130)

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
Nelux 1nject0r - Param Filter Checker By Marcos Suarez V2.0
{RESET}
    """)

def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme and parsed.netloc

def get_output_filename(url):
    parsed = urlparse(url)
    parts = parsed.netloc.split(":")[0].split(".")  # remove port, split by dot
    root = parts[-2] if len(parts) >= 2 else parts[0]
    return f"{root}_parameters.txt"

def get_vulnerables_filename(url, output_format="txt"):
    parsed = urlparse(url)
    parts = parsed.netloc.split(":")[0].split(".")  # remove port
    root = parts[-2] if len(parts) >= 2 else parts[0]
    ext = "json" if output_format == "json" else "txt"
    return f"{root}_vulnerables.{ext}"

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

def process_url(url, threads, headers, output_filename, payloads=None, output_format="txt", fuzz_threads=8):
    if not is_valid_url(url):
        P.log(f"{RED}[!] Invalid URL: {url}{RESET}")
        return

    try:
        urls_con_param = extract_params(url, headers, threads)
        if not urls_con_param:
            P.log(f"{RED}[!] No injectable parameters found in: {url}{RESET}")
            return
        test_parameters(
            urls_con_param,
            threads,
            headers,
            output_filename,
            show_save_message=True,
            payloads=payloads,
            output_format=output_format,
            fuzz_threads=fuzz_threads
        )
    except Exception as e:
        P.log(f"{RED}[!] Error processing the URL {url}: {e}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="Nelux 1nject0r - Param Filter Checker")
    parser.add_argument('-u', '--url', type=str, help="Single URL to check")
    parser.add_argument('-l', '--list', type=str, help="File containing a list of URLs to check")
    parser.add_argument('-t', '--threads', type=int, default=15, help="Number of threads to use (default: 15)")
    parser.add_argument('--fuzz-threads', type=int, default=8, help="Max workers per parameter fuzzing phase (default: 8)")
    parser.add_argument("-w", '--wordlist', dest="word", help="wordlist of payloads", action='store')
    parser.add_argument("-ra","--random-agent", action="store_true", help="Random User-Agent")
    parser.add_argument("-H", "--header", action="append", help="Custom header (can be used multiple times)")
    parser.add_argument('-pl', '--param-list', type=str, help="File with URLs that already contain parameters")
    parser.add_argument('-of', '--output-format', dest="output_format", choices=["txt", "json"], default="txt",
                        help="Output format for vulnerables file: txt (default) or json")

    args = parser.parse_args()
    banner()
    headers = build_headers(args)
    
    payloads = None
    if args.word:
        payloads = load_payloads(args.word)
    
    if args.header:
        P.log(f"{CYAN}[*] Use Headers:{RESET} {args.header}")
    if args.random_agent:
        P.log(f"{CYAN}[*] Use random agent{RESET}")
    P.log(f"{CYAN}[*] Output format:{RESET} {args.output_format}")     

    if args.url:
        P.log(f"{CYAN}[*] Scanning URL:{RESET} {args.url}")
        output_filename = get_output_filename(args.url)
        process_url(args.url, args.threads, headers, output_filename, payloads, args.output_format, args.fuzz_threads)
        P.log(f"{CYAN}[*] Vulnerability output file:{RESET} {get_vulnerables_filename(args.url, args.output_format)}")
        P.log(f"{CYAN}[*] Saved at:{RESET} {re.sub(r'/$', '', os.getcwd())}/{get_vulnerables_filename(args.url, args.output_format)}")


    elif args.list:
        try:
            with open(args.list, 'r') as file:
                urls = file.readlines()
                P.log(f"{CYAN}[*] Scanning URLs from file:{RESET} {args.list}")
                vuln_files = set()
                for url in urls:
                    url = url.strip()
                    if url:
                        output_filename = get_output_filename(url)
                        process_url(url, args.threads, headers, output_filename, payloads, args.output_format, args.fuzz_threads)
                        vuln_files.add(get_vulnerables_filename(url, args.output_format))
                if vuln_files:
                    P.log(f"{CYAN}[*] Vulnerability output files are saved in:{RESET} {os.getcwd()}")
                    for vf in sorted(vuln_files):
                        P.log(f"{CYAN}   -{RESET} {vf}")
        except FileNotFoundError:
            P.log(f"{RED}[!] File not found: {args.list}{RESET}")
            sys.exit(1)
        except Exception as e:
            P.log(f"{RED}[!] Error reading the file: {e}{RESET}")
            sys.exit(1)

    elif args.param_list:
        try:
            with open(args.param_list, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
                P.log(f"{CYAN}[*] Testing pre-found parameter URLs from file: {args.param_list}{RESET}")
                test_parameters(
                    urls,
                    args.threads,
                    headers,
                    output_filename=None,
                    show_save_message=False,
                    payloads=payloads,
                    output_format=args.output_format,
                    fuzz_threads=args.fuzz_threads
                )
                vuln_files = sorted({get_vulnerables_filename(url, args.output_format) for url in urls})
                if vuln_files:
                    P.log(f"{CYAN}[*] Vulnerability output files are saved in:{RESET} {os.getcwd()}")
                    for vf in vuln_files:
                        P.log(f"{CYAN}   -{RESET} {vf}")
        except FileNotFoundError:
            P.log(f"{RED}[!] File not found: {args.param_list}{RESET}")
            sys.exit(1)
        except Exception as e:
            P.log(f"{RED}[!] Error reading param list file: {e}{RESET}")
            sys.exit(1)
    else:
        P.log(f"{RED}[!] Please specify a URL with -u or a file with -l.{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        fuzz_stop.set()
    finally:
        P.stop()
