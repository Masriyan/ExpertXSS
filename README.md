[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#license)
[![Maintained?](https://img.shields.io/badge/Maintained-yes-green.svg)](#)

# ExpertXSS — Enhanced XSS & Reflection Scanner (v3.5)

**ExpertXSS** is a Python-based web security tool for **authorized** testing of Cross‑Site Scripting (XSS) exposure.  
It uses a **two‑phase** approach to rapidly locate **reflections** and then probe with **context‑aware payloads**. It can **crawl** a target, **fuzz forms/params**, test **header-based reflections**, and produce **JSON/CSV/HTML reports**.

> ⚠️ **Legal**: Use only on systems you own or have explicit permission to test.

---

## Table of Contents
- [About the Project](#about-the-project)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Quick Start](#quick-start)
  - [Command-Line Arguments](#command-line-arguments)
  - [Examples](#examples)
- [Output Formats](#output-formats)
- [Demo](#demo)
- [License](#license)

---

## About the Project

**ExpertXSS** automatically fetches fresh payloads from [PayloadBox’s XSS list](https://github.com/payloadbox/xss-payload-list) and rotates realistic User‑Agents from a popular [gist](https://gist.github.com/pzb/b4b6f57144aea7827ae4).  
Compared to simple “reflect and alert(1)” scripts, **ExpertXSS** adds:

- **Two-phase strategy**: fast **reflection discovery** (marker-only) → **targeted XSS payload tests**
- **Crawler** (respects `robots.txt` by default; `--ignore-robots` to override)
- **Form fuzzing**: submits forms, preserves hidden fields, injects values
- **Header injection trials**: `Referer`, `X-Forwarded-For`, `X-Api-Version`, etc.
- **Heuristics**: detects raw/HTML/URL/double‑URL reflections & infers **HTML/Attr/JS** contexts
- **Security headers audit**: CSP, X-Content-Type-Options, Referrer-Policy, etc.
- **Reports**: pretty **HTML**, plus **JSON** and **CSV** for pipelines
- **Networking**: proxy/SOCKS, retries with backoff, rate limit, concurrency, custom headers/cookies
- **Windows-friendly**: color output via `colorama`; no POSIX-only calls

---

## Features

- **Dynamic Payload Retrieval** — Pulls the latest payloads with conditional GET (ETag/Last‑Modified) caching.
- **User-Agent Rotation** — Randomizes a large UA pool to vary requests.
- **Concurrent Scanning** — Multi-threaded workers with request rate limiting.
- **Lightweight WAF Check** — Looks for common WAF telltales; can be disabled with `--no-waf-check`.
- **GET/POST/FORM Injection** — Injects into query/body params and discovered forms.
- **Header Injection** — Optional checks for reflections via common headers.
- **Save Results** — Export to `--output results.json`, `--csv results.csv`, and `--html report.html`.

---

## Requirements

- **Python 3.8+**
- Packages: `requests`, `beautifulsoup4`, `colorama`, `tqdm`, `lxml`, `html5lib`\n
  Optional: `requests[socks]` for SOCKS proxies.\n
  ```bash
  pip install requests beautifulsoup4 colorama tqdm lxml html5lib
  # optional (SOCKS): pip install 'requests[socks]'
  ```

---

## Installation

1. **Clone this repository**  
   ```bash
   git clone https://github.com/Masriyan/ExpertXSS.git
   cd ExpertXSS
   ```

2. **(Optional) Create a virtual environment**  
   ```bash
   python -m venv venv
   # Linux/Mac
   source venv/bin/activate
   # Windows
   venv\Scripts\activate
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt  # if provided
   # or
   pip install requests beautifulsoup4 colorama tqdm lxml html5lib
   ```

4. **Run the tool**  
   ```bash
   python ExpertXSS.py -h
   ```

---

## Usage

### Quick Start
```bash
# Single target (GET)
python ExpertXSS.py -u "https://example.com/search?q=test" --concurrency 8 --max-payloads 200 --html report.html

# Crawl and fuzz
python ExpertXSS.py --crawl -u https://example.com --max-pages 200 --max-depth 2 --concurrency 10 --html report.html

# Authenticated POST with headers/cookies and proxy
python ExpertXSS.py -u https://example.com/login -m POST \
  --data "user=demo&pass=demo" \
  --header "X-Client: audit" --cookie "sid=abc123" \
  --proxy http://127.0.0.1:8080 --test-headers \
  --max-payloads 150 --html report.html
```

### Command-Line Arguments

| Flag/Option           | Description                                                                                  | Default |
|-----------------------|----------------------------------------------------------------------------------------------|---------|
| **-u**, `--url`       | Target URL (seed for crawl or single target).                                                | —       |
| **-m**, `--method`    | HTTP method for direct mode: `GET` or `POST`.                                                | `GET`   |
| **-p**, `--param`     | Param name for single-target mode if URL has none.                                           | `q`     |
| `--data`              | POST body template for single-target POST mode, e.g., `a=b&c=d`.                             | —       |
| `--crawl`             | Enable crawler to discover URLs & forms.                                                     | off     |
| `--max-pages`         | Maximum pages to crawl.                                                                       | `150`   |
| `--max-depth`         | Maximum crawl depth.                                                                          | `2`     |
| `--allow-external`    | Follow external domains (default: same host only).                                           | off     |
| `--ignore-robots`     | Ignore `robots.txt` (default: respect).                                                       | off     |
| `--timeout`           | HTTP timeout (seconds).                                                                       | `12`    |
| `--rate`              | Requests per second cap (`0` = unlimited).                                                   | `0`     |
| `--retries`           | Retry attempts on network errors.                                                             | `2`     |
| `--backoff`           | Backoff factor between retries.                                                               | `0.7`   |
| `--proxy`             | Proxy URL (e.g., `http://127.0.0.1:8080` or `socks5h://127.0.0.1:9050`).                      | —       |
| `--proxy-list`        | File with a list of proxies (one per line).                                                  | —       |
| `--header`            | Custom header, e.g., `--header "X-Client: audit"` (repeatable).                               | —       |
| `--cookie`            | Cookie string, e.g., `sid=abc123; theme=dark`.                                               | —       |
| `--encode`            | Encode injected values: `url`, `base64`, `double-url`, `html`.                                | —       |
| `--delay`             | Delay between requests (seconds).                                                             | `0.0`   |
| `--concurrency`       | Concurrent workers.                                                                           | `6`     |
| `--max-payloads`      | Limit number of payloads per param (speeds up scans).                                         | all     |
| `--test-headers`      | Try header-based reflection (e.g., `Referer`, `X-Forwarded-For`).                              | off     |
| `--no-waf-check`      | Skip WAF detection.                                                                           | off     |
| `--payload-file`      | Custom payload file path.                                                                     | —       |
| `--log`               | Log file path.                                                                                | —       |
| `--output`            | Save findings to JSON file.                                                                   | —       |
| `--csv`               | Save findings to CSV file.                                                                    | —       |
| `--html`              | Save a pretty HTML report.                                                                    | —       |

### Examples

1) **Basic usage**  
```bash
python ExpertXSS.py -u "https://example.com"
```

2) **Concurrent scanning**  
```bash
python ExpertXSS.py -u "https://example.com" --concurrency 5
```

3) **Use a proxy & POST method**  
```bash
python ExpertXSS.py -u "https://example.com/vuln" -m POST -p "search" --proxy "http://127.0.0.1:8080"
```

4) **Save to JSON/CSV/HTML**  
```bash
python ExpertXSS.py -u "https://example.com" --output results.json --csv results.csv --html report.html
```

5) **Skip WAF check**  
```bash
python ExpertXSS.py -u "https://example.com" --no-waf-check
```

---

## Output Formats

- **JSON** (`--output results.json`) — Full finding objects, suitable for pipelines.
- **CSV**  (`--csv results.csv`) — Flat table for spreadsheets and quick diffing.
- **HTML** (`--html report.html`) — Self-contained, pretty report including evidence and security headers.

> Each finding includes: URL, method, location (query/body/form/header), parameter, reflection style (raw/html/url/double-url), inferred context (HTML/Attr/JS), status code, response security headers, and an evidence snippet.

---

## Demo

Below is a demonstration of **ExpertXSS** in action:

![ExpertXSS Demo](https://github.com/Masriyan/ExpertXSS/blob/main/XSS%20EXPERT.gif)

---

## License

Released under the **MIT License**. See [LICENSE](#) for details.

---

**Maintainer**: Sudo3rs
