#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ExpertXSS — Enhanced XSS & Reflection Scanner (v3.5)
Author: Sudo3rs
License: MIT

FOR AUTHORIZED TESTING ONLY. Use on systems you own or are explicitly permitted to test.

Highlights
- Two-phase strategy: fast reflection discovery (marker-only) → targeted XSS payload tests
- Crawl mode: discover URLs & forms (respects robots.txt by default; can ignore)
- Form fuzzing: submits forms with preserved hidden fields and injected payloads
- Parameter fuzzing: iterates all query/body params; chooses context-aware payloads
- Header injection tests: Referer, X-Forwarded-For, X-Api-Version, etc.
- Heuristics: detects raw/HTML-encoded/URL-encoded reflections, basic context detection (HTML/Attr/JS)
- Security headers audit: CSP, X-Content-Type-Options, Referrer-Policy, etc.
- Output: colored CLI + JSON/CSV + pretty HTML report (self-contained)
- Robust networking: proxy/SOCKS, retries, backoff, concurrency, rate limiting
- Windows-friendly: colorama, safe paths, no POSIX-only calls

Dependencies
    pip install requests beautifulsoup4 colorama tqdm lxml html5lib
    # For SOCKS proxy support: pip install requests[socks]

Examples
    python ExpertXSS.py -u "https://target.tld/search?q=test"
    python ExpertXSS.py --crawl -u https://target.tld --max-pages 200 --concurrency 10
    python ExpertXSS.py -u https://target.tld/login --method POST --data "user=demo&pass=demo" \
        --cookie "sid=abc123" --header "X-Client: audit" --encode url --output results.json --html report.html
    python ExpertXSS.py -u https://target.tld --proxy http://127.0.0.1:8080 --ignore-robots

"""

from __future__ import annotations
import argparse
import base64
import concurrent.futures
import csv
import hashlib
import html
import json
import logging
import os
import queue
import random
import re
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Iterable, Set

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
from tqdm import tqdm
from urllib import robotparser

# --------------------------------------------------------------------------------------
# Constants & Globals
# --------------------------------------------------------------------------------------
APP_NAME = "ExpertXSS"
APP_VERSION = "3.5"

XSS_PAYLOADS_URL = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/refs/heads/master/Intruder/xss-payload-list.txt"
USER_AGENTS_URL  = "https://gist.githubusercontent.com/pzb/b4b6f57144aea7827ae4/raw/cf847b76a142955b1410c8bcef3aabe221a63db1/user-agents.txt"

XSS_PAYLOADS_FILE        = "xss_payloads.txt"
USER_AGENTS_FILE         = "user_agents.txt"
XSS_HEADER_CACHE_FILE    = "xss_header.cache"
UA_HEADER_CACHE_FILE     = "ua_header.cache"

DEFAULT_MARKER_PREFIX = "XSSX_"

print_lock = threading.Lock()

colorama_init(autoreset=True)

# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------

def banner() -> str:
    return f"""
{Fore.MAGENTA}
  ╔════════════════════════════════════════════════════════╗
  ║                 {APP_NAME} — v{APP_VERSION}                      ║
  ║                     by Sudo3rs                               ║
  ╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


def log_info(msg: str):
    with print_lock:
        print(Fore.CYAN + msg + Style.RESET_ALL)


def log_ok(msg: str):
    with print_lock:
        print(Fore.GREEN + msg + Style.RESET_ALL)


def log_warn(msg: str):
    with print_lock:
        print(Fore.YELLOW + msg + Style.RESET_ALL)


def log_err(msg: str):
    with print_lock:
        print(Fore.RED + msg + Style.RESET_ALL)


def dedupe_lines(text: str) -> List[str]:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return sorted(list(set(lines)))


# Remote fetch with conditional headers (ETag/Last-Modified)
def fetch_remote_file(url: str, local_file: str, header_cache_file: str) -> List[str]:
    headers = {}
    etag = None
    last_modified = None

    if os.path.exists(header_cache_file):
        try:
            with open(header_cache_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f.read().splitlines():
                    if line.startswith("ETag:"):
                        etag = line.split("ETag:", 1)[1].strip()
                    elif line.startswith("Last-Modified:"):
                        last_modified = line.split("Last-Modified:", 1)[1].strip()
        except Exception:
            pass

    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    try:
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code == 304 and os.path.exists(local_file):
            log_warn(f"[cache] {url} unchanged. Using local {local_file}")
            with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
                return dedupe_lines(f.read())
        if r.status_code == 200:
            with open(local_file, "w", encoding="utf-8", errors="ignore") as f:
                f.write(r.text)
            with open(header_cache_file, "w", encoding="utf-8", errors="ignore") as f:
                if "ETag" in r.headers:
                    f.write(f"ETag:{r.headers['ETag']}\n")
                if "Last-Modified" in r.headers:
                    f.write(f"Last-Modified:{r.headers['Last-Modified']}\n")
            return dedupe_lines(r.text)
        log_warn(f"[cache] Failed to fetch {url} (HTTP {r.status_code}). Falling back...")
    except requests.RequestException as e:
        log_warn(f"[cache] Error fetching {url}: {e}. Falling back...")

    if os.path.exists(local_file):
        with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
            return dedupe_lines(f.read())
    return []


def get_xss_payloads(custom_file: Optional[str] = None) -> List[str]:
    if custom_file:
        try:
            with open(custom_file, "r", encoding="utf-8", errors="ignore") as f:
                return dedupe_lines(f.read())
        except Exception as e:
            log_err(f"[-] Failed to load payload file: {e}")
            sys.exit(1)
    payloads = fetch_remote_file(XSS_PAYLOADS_URL, XSS_PAYLOADS_FILE, XSS_HEADER_CACHE_FILE)
    if not payloads:
        # Minimal built-ins
        payloads = [
            '<svg onload=alert(1)>',
            '\";alert(1);//',
            "</script><script>alert(1)</script>",
            "' onmouseover=alert(1) x='",
        ]
    return payloads


def get_user_agents() -> List[str]:
    uas = fetch_remote_file(USER_AGENTS_URL, USER_AGENTS_FILE, UA_HEADER_CACHE_FILE)
    return uas or ["Mozilla/5.0 (compatible; ExpertXSS/1.0)"]


def random_ua(uas: List[str]) -> str:
    return random.choice(uas) if uas else "Mozilla/5.0 (compatible; ExpertXSS/1.0)"


def encode_payload(payload: str, mode: Optional[str]) -> str:
    if not mode:
        return payload
    if mode == "url":
        return urllib.parse.quote(payload, safe="")
    if mode == "base64":
        return base64.b64encode(payload.encode()).decode()
    if mode == "double-url":
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    if mode == "html":
        return html.escape(payload)
    return payload


def marker_token() -> str:
    rnd = hashlib.sha1(os.urandom(16)).hexdigest()[:8]
    return f"{DEFAULT_MARKER_PREFIX}{rnd}"


# --------------------------------------------------------------------------------------
# Networking & Session
# --------------------------------------------------------------------------------------

class SessionManager:
    def __init__(self, proxies: Optional[Dict[str, str]], cookies: Optional[str], headers: List[str], uas: List[str],
                 timeout: float, rate: float, retries: int, backoff: float):
        self.session = requests.Session()
        self.proxies = proxies
        self.uas = uas
        self.timeout = timeout
        self.rate = rate
        self.retries = retries
        self.backoff = backoff
        self.last_request = 0.0

        # Base headers
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": random_ua(self.uas),
        })

        # Custom headers
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                self.session.headers[k.strip()] = v.strip()

        # Cookies
        if cookies:
            self.session.headers["Cookie"] = cookies

        if proxies:
            self.session.proxies.update(proxies)

    def _respect_rate(self):
        if self.rate <= 0:
            return
        elapsed = time.time() - self.last_request
        delay = max(0.0, (1.0 / self.rate) - elapsed)
        if delay > 0:
            time.sleep(delay)

    def _do(self, method: str, url: str, **kwargs) -> requests.Response:
        # rotate UA per request
        self.session.headers["User-Agent"] = random_ua(self.uas)
        self._respect_rate()

        for attempt in range(1, self.retries + 1):
            try:
                r = self.session.request(method, url, timeout=self.timeout, **kwargs)
                self.last_request = time.time()
                return r
            except requests.RequestException as e:
                if attempt == self.retries:
                    raise
                time.sleep(self.backoff * attempt)
        # should never reach
        raise RuntimeError("unreachable")

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._do("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self._do("POST", url, **kwargs)


# --------------------------------------------------------------------------------------
# Heuristics & Analysis
# --------------------------------------------------------------------------------------

@dataclass
class Finding:
    url: str
    method: str
    location: str  # query|body|form|header
    param: str
    context: str  # HTML|Attr|JS|Unknown
    reflected: str  # raw|html|url|double-url|none
    marker: str
    payload: Optional[str]
    evidence: str
    status: int
    security_headers: Dict[str, str]


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "X-Frame-Options",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def audit_security_headers(resp: requests.Response) -> Dict[str, str]:
    out = {}
    for h in SECURITY_HEADERS:
        out[h] = resp.headers.get(h, "(missing)")
    return out


def detect_context(html_text: str, idx: int) -> str:
    # Primitive context check using surrounding characters/tags
    left = max(0, idx - 200)
    right = min(len(html_text), idx + 200)
    segment = html_text[left:right].lower()
    if "<script" in segment and "</script>" in segment:
        return "JS"
    if re.search(r"<[^>]+\s+[a-z0-9_-]+=\"[^\"]*\Z", segment):  # inside attribute quotes
        return "Attr"
    return "HTML"


def reflection_style(resp_text: str, token: str) -> Tuple[str, int]:
    # Returns (style, index) where style in {raw, html, url, double-url, none}
    idx = resp_text.find(token)
    if idx != -1:
        return ("raw", idx)
    enc = html.escape(token)
    idx = resp_text.find(enc)
    if idx != -1:
        return ("html", idx)
    url1 = urllib.parse.quote(token, safe="")
    idx = resp_text.find(url1)
    if idx != -1:
        return ("url", idx)
    url2 = urllib.parse.quote(url1, safe="")
    idx = resp_text.find(url2)
    if idx != -1:
        return ("double-url", idx)
    return ("none", -1)


# --------------------------------------------------------------------------------------
# Crawler & Targets Discovery
# --------------------------------------------------------------------------------------

@dataclass
class Target:
    url: str
    method: str  # GET/POST
    params: Dict[str, str]  # name -> value
    location: str  # query|body|form
    form_meta: Optional[Dict[str, str]] = None


class Crawler:
    def __init__(self, base_url: str, session: SessionManager, respect_robots: bool, max_pages: int, max_depth: int,
                 allow_external: bool):
        self.base_url = base_url.rstrip('/')
        self.session = session
        self.parsed_base = urllib.parse.urlparse(self.base_url)
        self.respect_robots = respect_robots
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.allow_external = allow_external

        self.visited: Set[str] = set()
        self.targets: List[Target] = []
        self.rp = robotparser.RobotFileParser()
        self._init_robots()

    def _init_robots(self):
        if not self.respect_robots:
            return
        robots_url = urllib.parse.urljoin(self.base_url + '/', 'robots.txt')
        try:
            self.rp.set_url(robots_url)
            self.rp.read()
        except Exception:
            pass

    def allowed(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        try:
            return self.rp.can_fetch("*", url)
        except Exception:
            return True

    def same_scope(self, url: str) -> bool:
        if self.allow_external:
            return True
        p = urllib.parse.urlparse(url)
        return p.netloc == self.parsed_base.netloc

    def normalize(self, url: str, base: str) -> Optional[str]:
        try:
            if url.startswith('javascript:') or url.startswith('#'):
                return None
            u = urllib.parse.urljoin(base, url)
            u_parsed = urllib.parse.urlparse(u)
            if u_parsed.scheme not in ("http", "https"):
                return None
            return u
        except Exception:
            return None

    def enqueue_params(self, url: str):
        p = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        if q:
            params = {k: (v[0] if v else "") for k, v in q.items()}
            self.targets.append(Target(url=url, method="GET", params=params, location="query"))

    def discover_forms(self, url: str, html_text: str):
        try:
            soup = BeautifulSoup(html_text, "lxml")
        except Exception:
            soup = BeautifulSoup(html_text, "html.parser")
        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            action = form.get("action") or url
            form_url = urllib.parse.urljoin(url, action)
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                val = inp.get("value", "")
                inputs[name] = val
            loc = "form"
            self.targets.append(Target(url=form_url, method=method, params=inputs, location=loc,
                                       form_meta={"action": action, "method": method}))

    def crawl(self) -> List[Target]:
        q: queue.Queue = queue.Queue()
        q.put((self.base_url, 0))
        self.visited.add(self.base_url)

        pages = 0
        while not q.empty() and pages < self.max_pages:
            url, depth = q.get()
            try:
                if not self.allowed(url):
                    log_warn(f"[robots] Skipping disallowed URL: {url}")
                    continue
                resp = self.session.get(url)
                pages += 1
                text = resp.text
                # Add param targets
                self.enqueue_params(url)
                # Add forms
                self.discover_forms(url, text)

                # Follow links
                if depth < self.max_depth:
                    try:
                        soup = BeautifulSoup(text, "lxml")
                    except Exception:
                        soup = BeautifulSoup(text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        u2 = self.normalize(a["href"], url)
                        if not u2:
                            continue
                        if not self.same_scope(u2):
                            continue
                        if u2 in self.visited:
                            continue
                        self.visited.add(u2)
                        q.put((u2, depth + 1))
            except requests.RequestException as e:
                log_warn(f"[crawl] {url} failed: {e}")
                continue
        return self.targets


# --------------------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------------------

HEADER_INJECTION_CANDIDATES = [
    "Referer",
    "X-Forwarded-For",
    "X-Api-Version",
    "X-Request-ID",
    "X-Origin",
]


class Scanner:
    def __init__(self, session: SessionManager, encode_mode: Optional[str], delay: float):
        self.session = session
        self.encode_mode = encode_mode
        self.delay = delay

    # ---------------- Reflection Phase -----------------
    def reflect_check(self, url: str, method: str, params: Dict[str, str], location: str,
                      extra_headers: Optional[Dict[str, str]] = None) -> Optional[Finding]:
        token = marker_token()
        inj_params = {k: (v if v else token) for k, v in params.items()}
        # also try per-parameter rotation to increase hit rate
        if not inj_params:
            inj_params = {"_": token}

        if self.delay > 0:
            time.sleep(self.delay)

        try:
            if method == "GET":
                p = inj_params
                headers = dict(extra_headers or {})
                r = self.session.get(url, params=p, headers=headers)
            else:
                data = inj_params
                headers = dict(extra_headers or {})
                r = self.session.post(url, data=data, headers=headers)
        except requests.RequestException as e:
            log_warn(f"[reflect] {method} {url} failed: {e}")
            return None

        style, idx = reflection_style(r.text, token)
        if style == "none":
            return None
        ctx = detect_context(r.text, idx)
        snippet = r.text[max(0, idx - 80): idx + 80]
        finding = Finding(
            url=r.url, method=method, location=location, param=",".join(inj_params.keys()),
            context=ctx, reflected=style, marker=token, payload=None,
            evidence=snippet, status=r.status_code, security_headers=audit_security_headers(r)
        )
        return finding

    # ---------------- Payload Phase -----------------
    def test_payload(self, url: str, method: str, param_name: str, baseline_params: Dict[str, str],
                     location: str, payload: str, token: str) -> Optional[Finding]:
        injected = f"{token}{payload}{token}"
        sent_value = encode_payload(injected, self.encode_mode)
        params = dict(baseline_params)
        params[param_name] = sent_value

        if self.delay > 0:
            time.sleep(self.delay)
        try:
            if method == "GET":
                r = self.session.get(url, params=params)
            else:
                r = self.session.post(url, data=params)
        except requests.RequestException as e:
            log_warn(f"[xss] {method} {url} payload error: {e}")
            return None

        style, idx = reflection_style(r.text, token)
        if style == "none":
            return None
        ctx = detect_context(r.text, idx)
        snippet = r.text[max(0, idx - 80): idx + 80]
        return Finding(
            url=r.url, method=method, location=location, param=param_name, context=ctx, reflected=style,
            marker=token, payload=payload, evidence=snippet, status=r.status_code,
            security_headers=audit_security_headers(r)
        )

    def header_injection(self, url: str, method: str, params: Dict[str, str]) -> List[Finding]:
        finds: List[Finding] = []
        for h in HEADER_INJECTION_CANDIDATES:
            token = marker_token()
            headers = {h: token}
            try:
                if method == "GET":
                    r = self.session.get(url, params=params, headers=headers)
                else:
                    r = self.session.post(url, data=params, headers=headers)
            except requests.RequestException:
                continue
            style, idx = reflection_style(r.text, token)
            if style == "none":
                continue
            ctx = detect_context(r.text, idx)
            snippet = r.text[max(0, idx - 80): idx + 80]
            finds.append(Finding(
                url=r.url, method=method, location="header", param=h, context=ctx, reflected=style,
                marker=token, payload=None, evidence=snippet, status=r.status_code,
                security_headers=audit_security_headers(r)
            ))
        return finds


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------

class Reporter:
    def __init__(self):
        self.findings: List[Finding] = []

    def add(self, f: Optional[Finding]):
        if f:
            self.findings.append(f)

    def extend(self, fs: Iterable[Finding]):
        self.findings.extend([f for f in fs if f])

    def to_json(self, path: str):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump([asdict(x) for x in self.findings], f, indent=2)
        log_ok(f"[+] JSON saved → {path}")

    def to_csv(self, path: str):
        cols = list(asdict(self.findings[0]).keys()) if self.findings else [
            'url','method','location','param','context','reflected','marker','payload','evidence','status','security_headers'
        ]
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for row in self.findings:
                d = asdict(row)
                w.writerow(d)
        log_ok(f"[+] CSV saved → {path}")

    def to_html(self, path: str):
        # simple self-contained report
        rows = []
        for f in self.findings:
            sec = "".join([f"<div><b>{html.escape(k)}:</b> {html.escape(v)}</div>" for k, v in f.security_headers.items()])
            rows.append(f"""
<tr>
  <td>{html.escape(f.method)}</td>
  <td>{html.escape(f.location)}</td>
  <td>{html.escape(f.param)}</td>
  <td><code>{html.escape(f.payload or '')}</code></td>
  <td>{html.escape(f.context)}</td>
  <td>{html.escape(f.reflected)}</td>
  <td>{f.status}</td>
  <td style='word-break:break-all'><a href='{html.escape(f.url)}' target='_blank'>{html.escape(f.url)}</a></td>
</tr>
<tr><td colspan='8'>
  <details><summary>Evidence</summary><pre style='white-space:pre-wrap'>{html.escape(f.evidence)}</pre></details>
  <details><summary>Response Security Headers</summary>{sec}</details>
</td></tr>
""")
        html_doc = f"""
<!doctype html>
<html><head><meta charset='utf-8'>
<title>{APP_NAME} Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;line-height:1.4;padding:24px;background:#0b1020;color:#e8eaf6}}
.table{{width:100%;border-collapse:collapse}}
th,td{{border:1px solid #394264;padding:8px 10px}}
th{{background:#1a2238}}
tr:nth-child(odd){{background:#11162a}}
code,pre{{background:#0a0f1e;padding:2px 4px;border-radius:4px}}
details{{margin-top:6px}}
</style></head>
<body>
<h1>{APP_NAME} — v{APP_VERSION}</h1>
<p>Authorized testing only. Generated at {time.ctime()}.</p>
<table class='table'>
  <thead><tr><th>Method</th><th>Loc</th><th>Param</th><th>Payload</th><th>Ctx</th><th>Reflected</th><th>Status</th><th>URL</th></tr></thead>
  <tbody>
  {''.join(rows) if rows else '<tr><td colspan="8">No findings</td></tr>'}
  </tbody>
</table>
</body></html>
"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_doc)
        log_ok(f"[+] HTML report saved → {path}")


# --------------------------------------------------------------------------------------
# WAF Check (lightweight)
# --------------------------------------------------------------------------------------

def check_waf(session: SessionManager, url: str) -> bool:
    waf_signs = ["403 Forbidden", "Cloudflare", "AWS WAF", "Access Denied", "AkamaiGHost", "Sucuri"]
    header_keys = ["Server", "X-WAF", "CF-RAY", "X-Sucuri-ID"]
    try:
        r = session.get(url)
        if any(sig.lower() in r.text.lower() for sig in waf_signs):
            log_warn("[waf] Content suggests a WAF.")
            return True
        if any(h in r.headers for h in header_keys):
            log_warn(f"[waf] Headers suggest a WAF: {dict(r.headers)}")
            return True
    except requests.RequestException:
        log_warn("[waf] Check failed; proceeding anyway")
    return False


# --------------------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------------------

def run_scan(args: argparse.Namespace):
    # Proxies
    proxies = None
    if args.proxy_list:
        try:
            with open(args.proxy_list, 'r', encoding='utf-8') as f:
                pool = [ln.strip() for ln in f if ln.strip()]
            if pool:
                pick = random.choice(pool)
                proxies = {"http": pick, "https": pick}
                log_warn(f"[proxy] Using proxy pool ({len(pool)}); current: {pick}")
        except Exception as e:
            log_warn(f"[proxy] Failed to load proxy list: {e}")
    elif args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        try:
            requests.get("http://example.com", proxies=proxies, timeout=5)
            log_ok(f"[proxy] {args.proxy} OK")
        except Exception:
            log_warn("[proxy] Proxy failed. Disabling.")
            proxies = None

    # Inputs
    uas = get_user_agents()
    payloads = get_xss_payloads(args.payload_file)

    # Session
    session = SessionManager(
        proxies=proxies,
        cookies=args.cookie,
        headers=args.header or [],
        uas=uas,
        timeout=args.timeout,
        rate=args.rate,
        retries=args.retries,
        backoff=args.backoff,
    )

    # Safe access in case a user runs an older copy without the flag
    if not getattr(args, "no_waf_check", False):
        check_waf(session, args.url)

    # Discover targets
    targets: List[Target] = []
    if args.crawl:
        log_info(f"[crawl] Crawling {args.url} (max_pages={args.max_pages}, depth={args.max_depth})")
        crawler = Crawler(
            base_url=args.url,
            session=session,
            respect_robots=not args.ignore_robots,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            allow_external=args.allow_external,
        )
        targets.extend(crawler.crawl())
    else:
        # Use provided URL directly
        p = urllib.parse.urlparse(args.url)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        params = {k: (v[0] if v else '') for k, v in q.items()} if q else ({args.param: ""} if args.param else {})
        targets.append(Target(url=args.url, method=args.method.upper(), params=params,
                              location=("query" if q else ("body" if args.method.upper()=="POST" else "query"))))

        # If POST with --data, populate params
        if args.method.upper() == "POST" and args.data:
            body = urllib.parse.parse_qs(args.data, keep_blank_values=True)
            targets[-1].params = {k: (v[0] if v else '') for k, v in body.items()}

    reporter = Reporter()
    scanner = Scanner(session=session, encode_mode=args.encode, delay=args.delay)

    log_info("[phase 1] Reflection discovery")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = []
        for t in targets:
            futs.append(ex.submit(scanner.reflect_check, t.url, t.method, t.params, t.location))
            # header injection trials
            if args.test_headers:
                futs.append(ex.submit(scanner.header_injection, t.url, t.method, t.params))
        for f in tqdm(concurrent.futures.as_completed(futs), total=len(futs), desc="Reflect", unit="target"):
            res = f.result()
            if isinstance(res, list):
                reporter.extend(res)
            elif isinstance(res, Finding):
                reporter.add(res)

    log_info("[phase 2] Targeted payload testing")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = []
        for t in targets:
            for pname in (t.params.keys() or ["_"]):
                token = marker_token()
                sample_payloads = payloads[: args.max_payloads] if args.max_payloads else payloads
                for pl in sample_payloads:
                    futs.append(ex.submit(scanner.test_payload, t.url, t.method, pname, t.params, t.location, pl, token))
        for f in tqdm(concurrent.futures.as_completed(futs), total=len(futs), desc="Payloads", unit="case"):
            res = f.result()
            if res:
                reporter.add(res)
                log_ok(f"[hit] {res.method} {res.location}:{res.param} @ {res.url} — {res.context}/{res.reflected}")

    # Outputs
    if args.output:
        reporter.to_json(args.output)
    if args.csv:
        reporter.to_csv(args.csv)
    if args.html:
        reporter.to_html(args.html)

    # Console summary
    log_info("\n[summary]")
    hits = reporter.findings
    if not hits:
        log_warn("No reflections/XSS indicators found.")
    else:
        for i, h in enumerate(hits, 1):
            log_ok(f"{i:02d}. {h.method} {h.location}:{h.param} @ {h.url}  ctx={h.context} ref={h.reflected}")


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=f"{APP_NAME} (v{APP_VERSION}) — Enhanced XSS & Reflection Scanner")
    ap.add_argument("-u", "--url", required=True, help="Target URL (seed for crawl or single target)")
    ap.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method for direct mode")
    ap.add_argument("-p", "--param", default="q", help="Param name for single-target mode if URL has none")
    ap.add_argument("--data", help="POST body template, e.g., 'a=b&c=d' for single-target POST mode")

    # Modes
    ap.add_argument("--crawl", action="store_true", help="Enable crawler to discover URLs & forms")
    ap.add_argument("--max-pages", type=int, default=150, help="Maximum pages to crawl")
    ap.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth")
    ap.add_argument("--allow-external", action="store_true", help="Follow external domains (default: same host only)")
    ap.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt (default: respect)")

    # Networking
    ap.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout (s)")
    ap.add_argument("--rate", type=float, default=0.0, help="Requests per second cap (0 = unlimited)")
    ap.add_argument("--retries", type=int, default=2, help="Retry attempts on network errors")
    ap.add_argument("--backoff", type=float, default=0.7, help="Backoff factor between retries")
    ap.add_argument("--proxy", help="Proxy e.g. http://127.0.0.1:8080 or socks5h://127.0.0.1:9050")
    ap.add_argument("--proxy-list", help="File with list of proxies (one per line)")

    # Headers / Cookies / Auth
    ap.add_argument("--header", action="append", help="Custom header 'Name: value' (repeatable)")
    ap.add_argument("--cookie", help="Cookie string 'a=b; c=d' for session auth")

    # Testing options
    ap.add_argument("--encode", choices=["url", "base64", "double-url", "html"], help="Encode injected values")
    ap.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
    ap.add_argument("--concurrency", type=int, default=6, help="Concurrent workers")
    ap.add_argument("--max-payloads", type=int, help="Limit number of payloads per param (speeds up scans)")
    ap.add_argument("--test-headers", action="store_true", help="Try header-based reflection (Referer, XFF, etc.)")
    ap.add_argument("--no-waf-check", action="store_true", help="Skip WAF detection pre-check")

    # Payloads & Logging
    ap.add_argument("--payload-file", help="Custom payload file path")
    ap.add_argument("--log", help="Log file path")

    # Output
    ap.add_argument("--output", help="Save findings to JSON file")
    ap.add_argument("--csv", help="Save findings to CSV file")
    ap.add_argument("--html", help="Save a pretty HTML report")

    args = ap.parse_args()

    if args.log:
        logging.basicConfig(filename=args.log, level=logging.INFO, format="%(asctime)s - %(message)s")
        logging.info("Scanner started")

    print(banner())

    try:
        run_scan(args)
    except KeyboardInterrupt:
        log_warn("Interrupted by user")


if __name__ == "__main__":
    main()
