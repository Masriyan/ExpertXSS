
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#license)
[![Maintained?](https://img.shields.io/badge/Maintained-yes-green.svg)](#)

## Table of Contents
- [About the Project](#about-the-project)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Arguments](#command-line-arguments)

---

## About the Project

The **ExpertXSS** is a Python-based penetration testing tool designed to check for Cross-Site Scripting (XSS) vulnerabilities on web applications. It automatically fetches the latest payloads from [PayloadBox’s XSS Payload List](https://github.com/payloadbox/xss-payload-list) and a pool of user agents from a popular [User-Agent gist](https://gist.github.com/pzb/b4b6f57144aea7827ae4). 

It also features:
- **ASCII cyberpunk flair** for a stylish console output
- **Conditional GET** (ETag/Last-Modified) caching to avoid re-downloading the same payload lists
- **Concurrency** options via threads
- **Basic WAF detection**  
- **Proxy support** for routing through tools like Burp Suite or ZAP
- **JSON logging** of results

---

## Features

- **Dynamic Payload Retrieval**  
  Grabs the latest XSS payloads directly from GitHub, checking if the file has changed since last time.

- **User-Agent Rotation**  
  Loads a list of user agents from a gist and rotates them randomly on each request, adding an extra layer of variety.

- **Concurrent Scanning**  
  Use multi-threading to speed up testing of multiple payloads.

- **Optional WAF Check**  
  A lightweight WAF detection that looks for common markers such as “403 Forbidden,” “Cloudflare,” etc.

- **ASCII Art & Colorized Output**  
  Color-coded success/fail messages displayed in a futuristic ASCII style.

- **GET/POST Parameter Injection**  
  Automatic injection into a specified parameter via either GET or POST requests.

- **Save Results to JSON**  
  Output all successful or failed payloads to a JSON file for further analysis.

---

## Requirements

- **Python 3.8+**
- **pip** or another Python package manager
- **colorama**, **requests**, **tqdm**, **argparse**, **concurrent.futures** (ships with Python 3.8+), etc.

Install dependencies manually or via a requirements file (if provided).
---
## Installation

1. **Clone this repository**:
    `git clone https://github.com/Masriyan/ExpertXSS.git`
       `cd ExpertXSS`

-   **(Optional) Create a virtual environment**:
     `python -m venv venv`
     `source venv/bin/activate  # Linux/Mac`
     `venv\Scripts\activate     # Windows`

-   **Install dependencies**:
      `pip install -r requirements.txt` 
-   **Run the tool**:
       `python ExpertXSS.py`
## Usage

### Command-Line Arguments
## Command-Line Arguments

| Flag/Option         | Description                                                   | Default Value  |
|---------------------|---------------------------------------------------------------|----------------|
| **-u**, `--url`     | Target URL for XSS testing.                                   | *Prompt user*  |
| **-m**, `--method`  | HTTP method: `GET` or `POST`.                                 | `GET`          |
| **-p**, `--param`   | Parameter name for injection.                                 | `q`            |
| **--concurrency**   | Number of concurrent threads.                                 | `1`            |
| **--proxy**         | Proxy URL (e.g., `http://127.0.0.1:8080`).                    | `None`         |
| **--output**        | JSON file path to store results.                              | `None`         |
| **--no-waf-check**  | Skip simple WAF detection.                                    | Not skipped    |

### Examples

1.  **Basic usage**:
    `python ExpertXSS.py -u "https://example.com"` 
    
2.  **Concurrent scanning**:
    `python ExpertXSS.py -u "https://example.com" --concurrency 5` 
    
3.  **Use a proxy & POST method**:
    `python ExpertXSS.py -u "https://example.com/vuln" -m POST -p "search" --proxy "http://127.0.0.1:8080"` 
    
4.  **Save to JSON**:
    `python ExpertXSS.py -u "https://example.com" --output results.json` 
    
5.  **Skip WAF check**:
    `python ExpertXSS.py -u "https://example.com" --no-waf-check`

## DEMO

Below is a demonstration of the **Expert XSS** in action:

![Expert XSS Demo](https://github.com/Masriyan/ExpertXSS/blob/main/XSS%20EXPERT.gif)
