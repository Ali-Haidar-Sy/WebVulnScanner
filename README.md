<!-- Badges -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
  <img src="https://img.shields.io/badge/Status-Educational-orange" />
  <img src="https://img.shields.io/badge/Tools-Nikto%20%7C%20Sqlmap%20%7C%20Nmap-important" />
  <img src="https://img.shields.io/badge/Version-3.0.0-brightgreen" />
</p>

<h1 align="center">🛡️ WebVulnScanner</h1>
<p align="center">
  <b>A professional, modular web vulnerability scanner for educational purposes.</b><br>
  <i>⚠️ For authorised penetration testing and learning only. Do not use illegally.</i>
</p>

<p align="center">
  <a href="https://t.me/P33_9"><img src="https://img.shields.io/badge/Telegram-@P33_9-26A5E4?logo=telegram" /></a>
  <a href="https://www.instagram.com/_ungn"><img src="https://img.shields.io/badge/Instagram-@_ungn-E4405F?logo=instagram" /></a>
</p>

---

## 📖 Description

**WebVulnScanner** is a comprehensive Python‑based tool that performs **30+ security checks** against a target website. It is designed to help cybersecurity students understand how modern scanners work, covering:

- ✅ **Port scanning** & service detection  
- 🛡️ **WAF/CDN fingerprinting**  
- 🔒 **SSL/TLS analysis** (including testssl.sh integration)  
- 📦 **CMS detection** (WordPress, Joomla, Drupal, and more)  
- 📂 **Directory/file enumeration** (smart wordlist)  
- 🧾 **Security headers analysis** (HSTS, CSP, X‑Frame‑Options, etc.)  
- 💥 **Vulnerability tests**:  
  - Cross‑Site Scripting (XSS)  
  - SQL Injection (error‑based & time‑based)  
  - Server‑Side Template Injection (SSTI)  
  - XML External Entity (XXE) injection  
  - Path Traversal  
  - Open Redirect  
  - CSRF (token absence)  
- 🔧 **HTTP method tampering** (PUT/DELETE/TRACE)  
- 🌐 **CORS misconfiguration detection**  
- 🧩 **Host header injection**  
- 🌍 **Subdomain enumeration** (DNS brute‑force)  
- 🔑 **JavaScript secret scanning** (API keys, tokens, etc.)  
- 🧪 **Integration with external tools**: Nikto, sqlmap, testssl.sh, whatweb (if installed)  

The scanner is **modular** – if one module fails, the rest continue. It outputs a detailed report in **JSON, HTML, or TXT** format.

---

## ⚠️ IMPORTANT: You MUST update the tool before use!

- **Dependencies**: Install `requirements.txt` with the latest versions.  
- **External tools** (nikto, sqlmap, testssl.sh, whatweb) – for full functionality, install them separately and ensure they are in your `PATH`.  
- **User‑agent & delays**: The script rotates user‑agents. For stealth, use the `--stealth` flag.  
- **Legal**: You must have **explicit written authorisation** to scan any target. Unauthorised scanning is illegal.

---

## 📋 Requirements

- **Python** 3.7 or higher  
- **Python libraries** (install via `pip`):  
  - `requests`  
  - `beautifulsoup4`  
  - `lxml`  
  - `python-nmap` (optional – for faster port scanning)  
- **Optional external tools** (for extended checks):  
  - [nikto](https://github.com/sullo/nikto)  
  - [sqlmap](https://github.com/sqlmapproject/sqlmap)  
  - [testssl.sh](https://github.com/drwetter/testssl.sh)  
  - [whatweb](https://github.com/urbanadventurer/WhatWeb)  
  - [nmap](https://nmap.org/)  

Install Python dependencies with:

```bash
pip install -r requirements.txt
