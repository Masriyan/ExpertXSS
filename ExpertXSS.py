import os
import requests
import time
import random
from colorama import Fore, Style, init
from tqdm import tqdm
import argparse
import concurrent.futures
import json
import sys

# Initialize colorama so colors work on Windows too
init(autoreset=True)

# URLs for payloads and user agents
XSS_PAYLOADS_URL = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/refs/heads/master/Intruder/xss-payload-list.txt"
USER_AGENTS_URL  = "https://gist.githubusercontent.com/pzb/b4b6f57144aea7827ae4/raw/cf847b76a142955b1410c8bcef3aabe221a63db1/user-agents.txt"

# Cache files and ETag/Last-Modified storage
XSS_PAYLOADS_FILE        = "xss_payloads.txt"
USER_AGENTS_FILE         = "user_agents.txt"
XSS_HEADER_CACHE_FILE    = "xss_header.cache"
UA_HEADER_CACHE_FILE     = "ua_header.cache"

###############################################################################
#                            BANNER & HELPERS
###############################################################################
def print_banner():
    """
    Print a futuristic/cyberpunk-style banner.
    """
    banner = r"""
<!-- /========================================================================================\ -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- ||     ███████╗██╗  ██╗██████╗ ███████╗██████╗ ████████╗  ██╗  ██╗███████╗███████╗      || -->
<!-- ||     ██╔════╝╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝  ╚██╗██╔╝██╔════╝██╔════╝      || -->
<!-- ||     █████╗   ╚███╔╝ ██████╔╝█████╗  ██████╔╝   ██║█████╗╚███╔╝ ███████╗███████╗      || -->
<!-- ||     ██╔══╝   ██╔██╗ ██╔═══╝ ██╔══╝  ██╔══██╗   ██║╚════╝██╔██╗ ╚════██║╚════██║      || -->
<!-- ||     ███████╗██╔╝ ██╗██║     ███████╗██║  ██║   ██║     ██╔╝ ██╗███████║███████║      || -->
<!-- ||     ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝      || -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- ||                                                                                      || -->
<!-- \========================================================================================/ -->
    ╔════════════════════════════════════════════════════════╗
    ║                     by Sudo3rs                         ║
    ║          (with dynamic payloads & user-agents)         ║
    ╚════════════════════════════════════════════════════════╝
    """
    print(Fore.MAGENTA + banner + Style.RESET_ALL)

def random_user_agent(user_agents):
    """
    Return a random user agent from the list.
    """
    if not user_agents:
        return "Mozilla/5.0 (compatible; FuturisticXSS/1.0)"
    return random.choice(user_agents)

###############################################################################
#                  REMOTE FETCH & CONDITIONAL GET (CACHING)
###############################################################################
def fetch_remote_file(url, local_file, header_cache_file):
    """
    Retrieve a remote file, using ETag/Last-Modified to check for updates.
    """
    headers = {}
    etag = None
    last_modified = None

    # If we have cached headers, load them
    if os.path.exists(header_cache_file):
        with open(header_cache_file, "r") as f:
            lines = f.read().splitlines()
            for line in lines:
                if line.startswith("ETag:"):
                    etag = line.replace("ETag:", "").strip()
                elif line.startswith("Last-Modified:"):
                    last_modified = line.replace("Last-Modified:", "").strip()

    # Conditional GET request
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 304:
            # Not modified
            print(Fore.YELLOW + f"[!] {url} has not changed. Using cached version." + Style.RESET_ALL)
            if os.path.exists(local_file):
                with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read().splitlines()
            else:
                # If local file doesn't exist, we still need to fetch full content
                response = requests.get(url, timeout=10)

        if response.status_code == 200:
            with open(local_file, "w", encoding="utf-8", errors="ignore") as f:
                f.write(response.text)
            # Update cache
            with open(header_cache_file, "w", encoding="utf-8", errors="ignore") as f:
                if "ETag" in response.headers:
                    f.write(f"ETag:{response.headers['ETag']}\n")
                if "Last-Modified" in response.headers:
                    f.write(f"Last-Modified:{response.headers['Last-Modified']}\n")
            return response.text.splitlines()
        else:
            print(Fore.RED + f"[-] Failed to fetch {url}. HTTP Status: {response.status_code}" + Style.RESET_ALL)
            if os.path.exists(local_file):
                with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read().splitlines()
            return []
    except requests.RequestException as e:
        print(Fore.RED + f"[-] Error fetching {url}: {str(e)}" + Style.RESET_ALL)
        if os.path.exists(local_file):
            with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().splitlines()
        return []

def get_xss_payloads():
    """
    Retrieve or update the XSS payload list from PayloadBox GitHub.
    """
    return fetch_remote_file(XSS_PAYLOADS_URL, XSS_PAYLOADS_FILE, XSS_HEADER_CACHE_FILE)

def get_user_agents():
    """
    Retrieve or update the User-Agent list from the gist.
    """
    return fetch_remote_file(USER_AGENTS_URL, USER_AGENTS_FILE, UA_HEADER_CACHE_FILE)

###############################################################################
#                           OPTIONAL UTILITIES
###############################################################################
def save_results_as_json(results, filename):
    """
    Save the test results (success/failure) to a JSON file.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(Fore.GREEN + f"[+] Results saved to {filename}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Could not save results to {filename}: {str(e)}" + Style.RESET_ALL)

def check_waf_simple(target_url):
    """
    Simple WAF detection by checking some common WAF patterns.
    """
    waf_signs = ["403 Forbidden", "Cloudflare", "AWS WAF", "Access Denied", "WAF"]
    try:
        resp = requests.get(target_url, timeout=5)
        if any(ws in resp.text for ws in waf_signs):
            print(Fore.YELLOW + "[!] Possible WAF detected. Proceed with caution." + Style.RESET_ALL)
    except:
        pass

###############################################################################
#                          CORE XSS TESTING LOGIC
###############################################################################
def test_single_payload(target_url, payload, user_agents, proxies=None, method="GET", param="q"):
    """
    Test a single payload against the target.  
    Returns a tuple (success: bool, payload: str, user_agent: str).
    """
    ua = random_user_agent(user_agents)
    headers = {"User-Agent": ua}

    # Only basic GET or POST demonstration
    if method.upper() == "GET":
        params = {param: payload}
        try:
            response = requests.get(
                target_url, 
                headers=headers, 
                params=params, 
                timeout=10,
                proxies=proxies
            )
            # Check reflection
            if payload in response.text:
                return True, payload, ua
            else:
                return False, payload, ua
        except requests.RequestException as e:
            # We'll treat any request error as a failure
            return False, payload, ua

    elif method.upper() == "POST":
        data = {param: payload}
        try:
            response = requests.post(
                target_url,
                headers=headers,
                data=data,
                timeout=10,
                proxies=proxies
            )
            if payload in response.text:
                return True, payload, ua
            else:
                return False, payload, ua
        except requests.RequestException as e:
            return False, payload, ua

def test_xss(
    target_url, 
    payloads, 
    user_agents, 
    concurrency=1,
    proxies=None,
    method="GET",
    param="q"
):
    """
    Perform the XSS test with a futuristic style output, showing the
    payload and user-agent used in each request. Supports concurrency.
    """
    success_payloads = []
    failure_payloads = []

    print(Fore.CYAN + "╔═══════════════════════════════════════╗" + Style.RESET_ALL)
    print(Fore.CYAN + f"║   STARTING XSS SCAN: {target_url}" + " " * (35 - len(target_url)) + "║" + Style.RESET_ALL)
    print(Fore.CYAN + "╚═══════════════════════════════════════╝" + Style.RESET_ALL)
    time.sleep(0.5)

    if concurrency > 1:
        # Use ThreadPoolExecutor for concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            # Map tasks
            future_to_payload = {
                executor.submit(test_single_payload, target_url, payload, user_agents, proxies, method, param): payload
                for payload in payloads
            }

            for future in tqdm(concurrent.futures.as_completed(future_to_payload),
                               total=len(payloads),
                               desc=Fore.GREEN + "Scanning" + Style.RESET_ALL,
                               unit="payload"):
                success, used_payload, used_ua = future.result()
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
        # Single-threaded approach
        for payload in tqdm(payloads, desc=Fore.GREEN + "Scanning" + Style.RESET_ALL, unit="payload"):
            success, used_payload, used_ua = test_single_payload(
                target_url, payload, user_agents, proxies, method, param
            )
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

    # Summaries
    print(Fore.CYAN + "\n[♦] TEST SUMMARY" + Style.RESET_ALL)
    if success_payloads:
        print(Fore.GREEN + f"  [+] Successful Payloads: {len(success_payloads)}" + Style.RESET_ALL)
        for p in success_payloads:
            print(Fore.GREEN + f"      - {p}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "  [-] No successful payloads found." + Style.RESET_ALL)

    print(Fore.CYAN + "[♦] END OF SCAN\n" + Style.RESET_ALL)

    # Return a result dict (could be used for JSON export)
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
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Futuristic XSS Scanner (Extended Version)."
    )
    parser.add_argument(
        "-u", "--url",
        help="Target URL for XSS testing."
    )
    parser.add_argument(
        "-m", "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method to use (default=GET)."
    )
    parser.add_argument(
        "-p", "--param",
        default="q",
        help="Parameter name to inject the payload (default=q)."
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Number of concurrent threads to use (default=1)."
    )
    parser.add_argument(
        "--proxy",
        help="Proxy server (e.g., http://127.0.0.1:8080)."
    )
    parser.add_argument(
        "--output",
        help="JSON file to save results."
    )
    parser.add_argument(
        "--no-waf-check",
        action="store_true",
        help="Skip simple WAF detection."
    )
    args = parser.parse_args()

    print_banner()

    # If user didn't provide URL in arguments, prompt for it
    if not args.url:
        target_url = input(Fore.YELLOW + "[?] Enter a single target URL: " + Style.RESET_ALL).strip()
        if not target_url:
            print(Fore.RED + "[-] No target URL provided. Exiting..." + Style.RESET_ALL)
            sys.exit(1)
    else:
        target_url = args.url.strip()

    # Fetch payloads & user-agents
    xss_payloads = get_xss_payloads()
    if not xss_payloads:
        print(Fore.RED + "[-] No XSS payloads available. Exiting..." + Style.RESET_ALL)
        sys.exit(1)

    user_agents = get_user_agents()
    if not user_agents:
        print(Fore.YELLOW + "[!] No User-Agent list available. Using fallback UA." + Style.RESET_ALL)

    # Optional simple WAF detection
    if not args.no_waf_check:
        check_waf_simple(target_url)

    # Configure proxy if provided
    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(Fore.YELLOW + f"[!] Using proxy: {args.proxy}" + Style.RESET_ALL)

    # Run the scan
    results = test_xss(
        target_url=target_url,
        payloads=xss_payloads,
        user_agents=user_agents,
        concurrency=args.concurrency,
        proxies=proxies,
        method=args.method,
        param=args.param
    )

    # If user wants to save JSON results
    if args.output:
        save_results_as_json(results, args.output)

if __name__ == "__main__":
    main()
