import os
import requests
import time
import random
import threading
import argparse
import concurrent.futures
import json
import sys
import logging
import urllib.parse
import base64
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama for cross-platform color support
init(autoreset=True)

# URLs for payloads and user agents
XSS_PAYLOADS_URL = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/refs/heads/master/Intruder/xss-payload-list.txt"
USER_AGENTS_URL  = "https://gist.githubusercontent.com/pzb/b4b6f57144aea7827ae4/raw/cf847b76a142955b1410c8bcef3aabe221a63db1/user-agents.txt"

# Cache files and ETag/Last-Modified storage
XSS_PAYLOADS_FILE        = "xss_payloads.txt"
USER_AGENTS_FILE         = "user_agents.txt"
XSS_HEADER_CACHE_FILE    = "xss_header.cache"
UA_HEADER_CACHE_FILE     = "ua_header.cache"

# Thread lock for safe printing
print_lock = threading.Lock()

###############################################################################
#                            BANNER & HELPERS
###############################################################################
def print_banner():
    banner = r"""
<!-- /========================================================================================\ -->
<!-- ||                                                                                      || -->
<!-- ||     ███████╗██╗  ██╗██████╗ ███████╗██████╗ ████████╗  ██╗  ██╗███████╗███████╗      || -->
<!-- ||     ██╔════╝╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝  ╚██╗██╔╝██╔════╝██╔════╝      || -->
<!-- ||     █████╗   ╚███╔╝ ██████╔╝█████╗  ██████╔╝   ██║█████╗╚███╔╝ ███████╗███████╗      || -->
<!-- ||     ██╔══╝   ██╔██╗ ██╔═══╝ ██╔══╝  ██╔══██╗   ██║╚════╝██╔██╗ ╚════██║╚════██║      || -->
<!-- ||     ███████╗██╔╝ ██╗██║     ███████╗██║  ██║   ██║     ██╔╝ ██╗███████║███████║      || -->
<!-- ||     ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝      || -->
<!-- ||                                                                                      || -->
<!-- \========================================================================================/ -->
    ╔════════════════════════════════════════════════════════╗
    ║                     by Sudo3rs                         ║
    ║          (Enhanced XSS Scanner - v2.0)                 ║
    ╚════════════════════════════════════════════════════════╝
    """
    print(Fore.MAGENTA + banner + Style.RESET_ALL)

def random_user_agent(user_agents):
    if not user_agents:
        return "Mozilla/5.0 (compatible; EnhancedXSS/2.0)"
    return random.choice(user_agents)

###############################################################################
#                  REMOTE FETCH & CONDITIONAL GET (CACHING)
###############################################################################
def fetch_remote_file(url, local_file, header_cache_file):
    headers = {}
    etag = None
    last_modified = None

    if os.path.exists(header_cache_file):
        with open(header_cache_file, "r") as f:
            lines = f.read().splitlines()
            for line in lines:
                if line.startswith("ETag:"):
                    etag = line.replace("ETag:", "").strip()
                elif line.startswith("Last-Modified:"):
                    last_modified = line.replace("Last-Modified:", "").strip()

    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 304:
            print(Fore.YELLOW + f"[!] {url} unchanged. Using cached version." + Style.RESET_ALL)
            if os.path.exists(local_file):
                with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
                    return list(set(f.read().splitlines()))  # Deduplicate
            response = requests.get(url, timeout=10)

        if response.status_code == 200:
            with open(local_file, "w", encoding="utf-8", errors="ignore") as f:
                f.write(response.text)
            with open(header_cache_file, "w", encoding="utf-8") as f:
                if "ETag" in response.headers:
                    f.write(f"ETag:{response.headers['ETag']}\n")
                if "Last-Modified" in response.headers:
                    f.write(f"Last-Modified:{response.headers['Last-Modified']}\n")
            return list(set(response.text.splitlines()))  # Deduplicate
        else:
            print(Fore.RED + f"[-] Failed to fetch {url}. Status: {response.status_code}" + Style.RESET_ALL)
            if os.path.exists(local_file):
                with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
                    return list(set(f.read().splitlines()))
            return []
    except requests.RequestException as e:
        print(Fore.RED + f"[-] Error fetching {url}: {str(e)}" + Style.RESET_ALL)
        if os.path.exists(local_file):
            with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
                return list(set(f.read().splitlines()))
        return []

def get_xss_payloads():
    return fetch_remote_file(XSS_PAYLOADS_URL, XSS_PAYLOADS_FILE, XSS_HEADER_CACHE_FILE)

def get_user_agents():
    return fetch_remote_file(USER_AGENTS_URL, USER_AGENTS_FILE, UA_HEADER_CACHE_FILE)

###############################################################################
#                           OPTIONAL UTILITIES
###############################################################################
def save_results_as_json(results, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(Fore.GREEN + f"[+] Results saved to {filename}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Could not save results: {str(e)}" + Style.RESET_ALL)

def check_waf(target_url):
    waf_signs = ["403 Forbidden", "Cloudflare", "AWS WAF", "Access Denied", "WAF"]
    headers_to_check = ["Server", "X-WAF", "X-Cloudflare"]
    try:
        resp = requests.get(target_url, timeout=5)
        content = resp.text
        headers = resp.headers
        if any(ws in content for ws in waf_signs) or any(h in headers for h in headers_to_check):
            print(Fore.YELLOW + "[!] Possible WAF detected. Headers: " + str(dict(headers)) + Style.RESET_ALL)
            return True
        return False
    except requests.RequestException:
        print(Fore.YELLOW + "[!] WAF check failed. Proceeding anyway." + Style.RESET_ALL)
        return False

def encode_payload(payload, encoding):
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    return payload

###############################################################################
#                          CORE XSS TESTING LOGIC
###############################################################################
def test_single_payload(target_url, payload, user_agents, proxies=None, method="GET", param="q", delay=0, encoding=None):
    ua = random_user_agent(user_agents)
    headers = {"User-Agent": ua}
    payload = encode_payload(payload, encoding)

    if delay:
        time.sleep(delay)

    if method.upper() == "GET":
        params = {param: payload}
        try:
            response = requests.get(target_url, headers=headers, params=params, timeout=10, proxies=proxies)
            if payload in response.text:  # Basic reflection check
                return True, payload, ua
            return False, payload, ua
        except requests.RequestException as e:
            with print_lock:
                print(Fore.YELLOW + f"[!] Request failed for '{payload}': {str(e)}" + Style.RESET_ALL)
            return False, payload, ua

    elif method.upper() == "POST":
        data = {param: payload}
        try:
            response = requests.post(target_url, headers=headers, data=data, timeout=10, proxies=proxies)
            if payload in response.text:
                return True, payload, ua
            return False, payload, ua
        except requests.RequestException as e:
            with print_lock:
                print(Fore.YELLOW + f"[!] Request failed for '{payload}': {str(e)}" + Style.RESET_ALL)
            return False, payload, ua

def test_xss(target_url, payloads, user_agents, concurrency=1, proxies=None, method="GET", param="q", delay=0, encoding=None):
    success_payloads = []
    failure_payloads = []

    print(Fore.CYAN + "╔═══════════════════════════════════════╗" + Style.RESET_ALL)
    print(Fore.CYAN + f"║   STARTING XSS SCAN: {target_url}" + " " * (35 - len(target_url)) + "║" + Style.RESET_ALL)
    print(Fore.CYAN + "╚═══════════════════════════════════════╝" + Style.RESET_ALL)
    time.sleep(0.5)

    if concurrency > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_payload = {
                executor.submit(test_single_payload, target_url, payload, user_agents, proxies, method, param, delay, encoding): payload
                for payload in payloads
            }
            for future in tqdm(concurrent.futures.as_completed(future_to_payload), total=len(payloads), desc=Fore.GREEN + "Scanning" + Style.RESET_ALL, unit="payload"):
                success, used_payload, used_ua = future.result()
                with print_lock:
                    if success:
                        success_payloads.append(used_payload)
                        print(Fore.GREEN + "┌──[PAYLOAD INJECTED]" + Style.RESET_ALL)
                        print(Fore.GREEN + f"├──Payload     : {used_payload}" + Style.RESET_ALL)
                        print(Fore.GREEN + f"└──User-Agent  : {used_ua}" + Style.RESET_ALL)
                    else:
                        failure_payloads.append(used_payload)
                        print(Fore.RED + "┌──[NO VULN DETECTED]" + Style.RESET_ALL)
                        print(Fore.RED + f"├──Payload     : {used_payload}" + Style.RESET_ALL)
                        print(Fore.RED + f"└──User-Agent  : {used_ua}" + Style.RESET_ALL)
    else:
        for payload in tqdm(payloads, desc=Fore.GREEN + "Scanning" + Style.RESET_ALL, unit="payload"):
            success, used_payload, used_ua = test_single_payload(target_url, payload, user_agents, proxies, method, param, delay, encoding)
            with print_lock:
                if success:
                    success_payloads.append(used_payload)
                    print(Fore.GREEN + "┌──[PAYLOAD INJECTED]" + Style.RESET_ALL)
                    print(Fore.GREEN + f"├──Payload     : {used_payload}" + Style.RESET_ALL)
                    print(Fore.GREEN + f"└──User-Agent  : {used_ua}" + Style.RESET_ALL)
                else:
                    failure_payloads.append(used_payload)
                    print(Fore.RED + "┌──[NO VULN DETECTED]" + Style.RESET_ALL)
                    print(Fore.RED + f"├──Payload     : {used_payload}" + Style.RESET_ALL)
                    print(Fore.RED + f"└──User-Agent  : {used_ua}" + Style.RESET_ALL)

    print(Fore.CYAN + "\n[♦] TEST SUMMARY" + Style.RESET_ALL)
    if success_payloads:
        print(Fore.GREEN + f"  [+] Successful Payloads: {len(success_payloads)}" + Style.RESET_ALL)
        for p in success_payloads:
            print(Fore.GREEN + f"      - {p}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "  [-] No successful payloads found." + Style.RESET_ALL)
    print(Fore.CYAN + "[♦] END OF SCAN\n" + Style.RESET_ALL)

    return {
        "target_url": target_url,
        "method": method,
        "param": param,
        "success_payloads": success_payloads,
        "failure_payloads": failure_payloads,
    }

###############################################################################
#                                   MAIN
###############################################################################
def main():
    parser = argparse.ArgumentParser(description="Enhanced XSS Scanner (v2.0)")
    parser.add_argument("-u", "--url", help="Target URL for XSS testing.")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method.")
    parser.add_argument("-p", "--param", default="q", help="Parameter name.")
    parser.add_argument("--concurrency", type=int, default=1, help="Number of concurrent threads.")
    parser.add_argument("--proxy", help="Single proxy server (e.g., http://127.0.0.1:8080).")
    parser.add_argument("--proxy-list", help="File with list of proxies.")
    parser.add_argument("--output", help="JSON file to save results.")
    parser.add_argument("--payload-file", help="Custom XSS payload file.")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds.")
    parser.add_argument("--encode", choices=["url", "base64"], help="Encode payloads.")
    parser.add_argument("--no-waf-check", action="store_true", help="Skip WAF detection.")
    parser.add_argument("--log", help="Log file path.")
    args = parser.parse_args()

    # Setup logging
    if args.log:
        logging.basicConfig(filename=args.log, level=logging.INFO, format="%(asctime)s - %(message)s")
        logging.info("Scanner started.")

    print_banner()

    # Get target URL
    target_url = args.url or input(Fore.YELLOW + "[?] Enter target URL: " + Style.RESET_ALL).strip()
    if not target_url:
        print(Fore.RED + "[-] No URL provided. Exiting..." + Style.RESET_ALL)
        sys.exit(1)

    # Load payloads
    if args.payload_file:
        try:
            with open(args.payload_file, "r", encoding="utf-8") as f:
                xss_payloads = list(set(f.read().splitlines()))
        except Exception as e:
            print(Fore.RED + f"[-] Failed to load payload file: {str(e)}. Exiting..." + Style.RESET_ALL)
            sys.exit(1)
    else:
        xss_payloads = get_xss_payloads()
    if not xss_payloads:
        print(Fore.RED + "[-] No payloads available. Exiting..." + Style.RESET_ALL)
        sys.exit(1)

    user_agents = get_user_agents()
    if not user_agents:
        print(Fore.YELLOW + "[!] No User-Agents available. Using fallback." + Style.RESET_ALL)

    # WAF check
    if not args.no_waf_check:
        if check_waf(target_url) and args.log:
            logging.warning("Possible WAF detected.")

    # Proxy setup
    proxies = None
    proxy_pool = []
    if args.proxy_list:
        try:
            with open(args.proxy_list, "r") as f:
                proxy_pool = f.read().splitlines()
            proxies = {"http": random.choice(proxy_pool), "https": random.choice(proxy_pool)}
            print(Fore.YELLOW + f"[!] Using proxy pool with {len(proxy_pool)} proxies." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] Failed to load proxy list: {str(e)}" + Style.RESET_ALL)
    elif args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        try:
            requests.get("http://example.com", proxies=proxies, timeout=5)
            print(Fore.GREEN + f"[+] Proxy {args.proxy} is working." + Style.RESET_ALL)
        except requests.RequestException:
            print(Fore.RED + "[-] Proxy failed. Proceeding without proxy." + Style.RESET_ALL)
            proxies = None

    # Run the scan
    results = test_xss(
        target_url=target_url,
        payloads=xss_payloads,
        user_agents=user_agents,
        concurrency=args.concurrency,
        proxies=proxies,
        method=args.method,
        param=args.param,
        delay=args.delay,
        encoding=args.encode
    )

    if args.log:
        logging.info(f"Scan completed. Successes: {len(results['success_payloads'])}")
    if args.output:
        save_results_as_json(results, args.output)

if __name__ == "__main__":
    main()
