"""
Privilege Escalation Tester - Tests for vertical privilege escalation vulnerabilities
"""
import sys
import argparse
import requests
import urllib3
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import AuthTool
from utils.output_parser import Finding, Severity

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class PrivEscResult:
    """Result of a privilege escalation test"""
    test_type: str
    technique: str
    success: bool
    status_code: int
    response_length: int
    url: str
    payload: str = ""
    evidence: str = ""


class PrivilegeEscalationTester(AuthTool):
    """Tester for vertical privilege escalation vulnerabilities"""

    # Admin/privileged endpoints to test
    ADMIN_ENDPOINTS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/admin/dashboard",
        "/admin/users",
        "/admin/settings",
        "/admin/config",
        "/admin/logs",
        "/admin/panel",
        "/management",
        "/manage",
        "/manager",
        "/console",
        "/dashboard",
        "/control",
        "/controlpanel",
        "/cp",
        "/backend",
        "/private",
        "/internal",
        "/superuser",
        "/root",
        "/system",
        "/api/admin",
        "/api/v1/admin",
        "/api/users/admin",
        "/api/settings",
        "/api/config",
    ]

    # Role manipulation payloads
    ROLE_PAYLOADS = [
        {"role": "admin"},
        {"role": "administrator"},
        {"role": "superuser"},
        {"role": "root"},
        {"isAdmin": True},
        {"is_admin": True},
        {"admin": True},
        {"administrator": True},
        {"user_role": "admin"},
        {"userRole": "admin"},
        {"access_level": "admin"},
        {"accessLevel": "admin"},
        {"level": 0},
        {"level": 1},
        {"level": 9999},
        {"permissions": ["admin"]},
        {"permissions": ["*"]},
        {"group": "administrators"},
        {"groups": ["admin"]},
        {"privilege": "admin"},
    ]

    # Parameter tampering values
    PARAM_TAMPERING = {
        "admin": ["true", "1", "yes", "on"],
        "is_admin": ["true", "1", "yes", "on"],
        "isAdmin": ["true", "1", "yes", "on"],
        "role": ["admin", "administrator", "superuser"],
        "access": ["admin", "full", "all"],
        "level": ["0", "1", "9999", "admin"],
        "user_id": ["1", "0", "-1"],
        "uid": ["1", "0", "-1"],
        "debug": ["true", "1"],
        "test": ["true", "1"],
    }

    @property
    def tool_name(self) -> str:
        return "privilege_escalation"

    def check_tool_installed(self) -> bool:
        """This is a pure Python tool"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Not used for pure Python tool"""
        return []

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Execute privilege escalation tests"""
        from datetime import datetime

        self.start_time = datetime.now()
        results = []
        findings = []

        print(f"[*] Starting privilege escalation tests on {target}")

        # Configuration
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies", {})
        timeout = kwargs.get("timeout", 10)
        verify_ssl = kwargs.get("verify_ssl", False)
        test_types = kwargs.get("test_types", ["endpoint", "role", "param", "method", "header"])

        # Low-privilege token
        low_priv_token = kwargs.get("low_priv_token")
        if low_priv_token:
            headers["Authorization"] = f"Bearer {low_priv_token}"

        # Admin endpoints test
        if "endpoint" in test_types:
            print("[*] Testing admin endpoint access...")
            endpoint_results = self._test_admin_endpoints(
                target, headers, cookies, timeout, verify_ssl
            )
            results.extend(endpoint_results)

            accessible = [r for r in endpoint_results if r.success]
            if accessible:
                findings.append(Finding(
                    tool="privilege_escalation",
                    target=target,
                    finding_type="priv_esc",
                    title="Admin Endpoint Access with Low Privilege",
                    description=f"Low-privileged user can access {len(accessible)} admin endpoints",
                    severity=Severity.CRITICAL,
                    evidence=f"Accessible: {[r.url for r in accessible[:5]]}",
                    remediation="Implement proper role-based access control (RBAC)"
                ))

        # Role manipulation in requests
        if "role" in test_types:
            print("[*] Testing role manipulation...")
            api_endpoint = kwargs.get("api_endpoint", f"{target}/api/user")
            role_results = self._test_role_manipulation(
                api_endpoint, headers, cookies, timeout, verify_ssl
            )
            results.extend(role_results)

            successful = [r for r in role_results if r.success]
            if successful:
                findings.append(Finding(
                    tool="privilege_escalation",
                    target=target,
                    finding_type="priv_esc",
                    title="Role Manipulation Vulnerability",
                    description="Server accepts client-supplied role/privilege parameters",
                    severity=Severity.CRITICAL,
                    evidence=f"Accepted payloads: {[r.payload for r in successful[:3]]}",
                    remediation="Never trust client-supplied role/permission values"
                ))

        # Parameter tampering
        if "param" in test_types:
            print("[*] Testing parameter tampering...")
            param_results = self._test_parameter_tampering(
                target, headers, cookies, timeout, verify_ssl
            )
            results.extend(param_results)

            successful = [r for r in param_results if r.success]
            if successful:
                findings.append(Finding(
                    tool="privilege_escalation",
                    target=target,
                    finding_type="priv_esc",
                    title="Parameter Tampering for Privilege Escalation",
                    description="Privilege escalation possible via parameter manipulation",
                    severity=Severity.HIGH,
                    evidence=f"Vulnerable params: {[r.technique for r in successful[:3]]}",
                    remediation="Validate all parameters server-side, use signed tokens"
                ))

        # HTTP method override
        if "method" in test_types:
            print("[*] Testing HTTP method override...")
            method_results = self._test_method_override(
                target, headers, cookies, timeout, verify_ssl
            )
            results.extend(method_results)

            successful = [r for r in method_results if r.success]
            if successful:
                findings.append(Finding(
                    tool="privilege_escalation",
                    target=target,
                    finding_type="priv_esc",
                    title="HTTP Method Override Vulnerability",
                    description="Access control bypassed via HTTP method override headers",
                    severity=Severity.HIGH,
                    evidence=f"Successful overrides: {[r.technique for r in successful[:3]]}",
                    remediation="Disable HTTP method override headers in production"
                ))

        # Header-based privilege escalation
        if "header" in test_types:
            print("[*] Testing header-based privilege escalation...")
            header_results = self._test_header_privilege_escalation(
                target, headers, cookies, timeout, verify_ssl
            )
            results.extend(header_results)

            successful = [r for r in header_results if r.success]
            if successful:
                findings.append(Finding(
                    tool="privilege_escalation",
                    target=target,
                    finding_type="priv_esc",
                    title="Header-based Privilege Escalation",
                    description="Access control bypassed via header manipulation",
                    severity=Severity.HIGH,
                    evidence=f"Successful headers: {[r.technique for r in successful[:3]]}",
                    remediation="Do not trust client headers for authorization decisions"
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
                "successful_escalations": len([r for r in results if r.success]),
                "findings_count": len(findings)
            }
        }

    def _test_admin_endpoints(self, base_url: str, headers: dict, cookies: dict,
                               timeout: int, verify_ssl: bool) -> List[PrivEscResult]:
        """Test access to admin endpoints with low-privilege credentials"""
        results = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in self.ADMIN_ENDPOINTS:
            try:
                url = f"{base}{endpoint}"
                response = requests.get(
                    url, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl, allow_redirects=False
                )

                # Check if access was granted (200 OK with actual content)
                success = self._is_admin_access_granted(response)

                results.append(PrivEscResult(
                    test_type="admin_endpoint",
                    technique=endpoint,
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=url,
                    evidence=response.text[:300] if success else ""
                ))

            except Exception as e:
                results.append(PrivEscResult(
                    test_type="admin_endpoint",
                    technique=endpoint,
                    success=False,
                    status_code=0,
                    response_length=0,
                    url=f"{base}{endpoint}",
                    evidence=str(e)
                ))

        return results

    def _test_role_manipulation(self, url: str, headers: dict, cookies: dict,
                                 timeout: int, verify_ssl: bool) -> List[PrivEscResult]:
        """Test role manipulation in API requests"""
        results = []

        for payload in self.ROLE_PAYLOADS:
            try:
                # Test POST with JSON body
                test_headers = {**headers, "Content-Type": "application/json"}
                response = requests.post(
                    url, headers=test_headers, cookies=cookies,
                    json=payload, timeout=timeout, verify=verify_ssl
                )

                success = self._is_privilege_escalated(response)

                results.append(PrivEscResult(
                    test_type="role_manipulation",
                    technique="json_body",
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=url,
                    payload=json.dumps(payload),
                    evidence=response.text[:300] if success else ""
                ))

                # Test PUT with JSON body
                response = requests.put(
                    url, headers=test_headers, cookies=cookies,
                    json=payload, timeout=timeout, verify=verify_ssl
                )

                success = self._is_privilege_escalated(response)

                results.append(PrivEscResult(
                    test_type="role_manipulation",
                    technique="json_body_put",
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=url,
                    payload=json.dumps(payload),
                    evidence=response.text[:300] if success else ""
                ))

            except Exception as e:
                results.append(PrivEscResult(
                    test_type="role_manipulation",
                    technique="json_body",
                    success=False,
                    status_code=0,
                    response_length=0,
                    url=url,
                    payload=json.dumps(payload),
                    evidence=str(e)
                ))

        return results

    def _test_parameter_tampering(self, url: str, headers: dict, cookies: dict,
                                   timeout: int, verify_ssl: bool) -> List[PrivEscResult]:
        """Test parameter tampering for privilege escalation"""
        results = []

        for param, values in self.PARAM_TAMPERING.items():
            for value in values:
                try:
                    # Test in query string
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[param] = [value]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    response = requests.get(
                        test_url, headers=headers, cookies=cookies,
                        timeout=timeout, verify=verify_ssl
                    )

                    success = self._is_privilege_escalated(response)

                    results.append(PrivEscResult(
                        test_type="param_tampering",
                        technique=f"{param}={value}",
                        success=success,
                        status_code=response.status_code,
                        response_length=len(response.text),
                        url=test_url,
                        payload=f"{param}={value}",
                        evidence=response.text[:300] if success else ""
                    ))

                except Exception as e:
                    results.append(PrivEscResult(
                        test_type="param_tampering",
                        technique=f"{param}={value}",
                        success=False,
                        status_code=0,
                        response_length=0,
                        url=url,
                        payload=f"{param}={value}",
                        evidence=str(e)
                    ))

        return results

    def _test_method_override(self, url: str, headers: dict, cookies: dict,
                               timeout: int, verify_ssl: bool) -> List[PrivEscResult]:
        """Test HTTP method override for privilege escalation"""
        results = []

        override_headers = [
            ("X-HTTP-Method-Override", "PUT"),
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-HTTP-Method-Override", "PATCH"),
            ("X-HTTP-Method", "PUT"),
            ("X-HTTP-Method", "DELETE"),
            ("X-Method-Override", "PUT"),
            ("X-Method-Override", "DELETE"),
            ("_method", "PUT"),
            ("_method", "DELETE"),
        ]

        for header_name, header_value in override_headers:
            try:
                test_headers = {**headers, header_name: header_value}

                response = requests.get(
                    url, headers=test_headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                success = response.status_code == 200

                results.append(PrivEscResult(
                    test_type="method_override",
                    technique=f"{header_name}: {header_value}",
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=url,
                    payload=f"{header_name}: {header_value}",
                    evidence=response.text[:300] if success else ""
                ))

            except Exception as e:
                results.append(PrivEscResult(
                    test_type="method_override",
                    technique=f"{header_name}: {header_value}",
                    success=False,
                    status_code=0,
                    response_length=0,
                    url=url,
                    payload=f"{header_name}: {header_value}",
                    evidence=str(e)
                ))

        return results

    def _test_header_privilege_escalation(self, url: str, headers: dict, cookies: dict,
                                           timeout: int, verify_ssl: bool) -> List[PrivEscResult]:
        """Test header-based privilege escalation"""
        results = []

        priv_headers = [
            {"X-Admin": "true"},
            {"X-Admin": "1"},
            {"X-Is-Admin": "true"},
            {"X-Role": "admin"},
            {"X-User-Role": "admin"},
            {"X-Access-Level": "admin"},
            {"X-Privilege": "admin"},
            {"X-Debug": "true"},
            {"X-Internal": "true"},
            {"X-Test": "true"},
            {"X-Bypass-Auth": "true"},
            {"X-Original-User": "admin"},
            {"X-Forwarded-User": "admin"},
            {"X-Remote-User": "admin"},
        ]

        for priv_header in priv_headers:
            try:
                test_headers = {**headers, **priv_header}

                response = requests.get(
                    url, headers=test_headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                success = self._is_privilege_escalated(response)

                results.append(PrivEscResult(
                    test_type="header_priv_esc",
                    technique=str(priv_header),
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=url,
                    payload=str(priv_header),
                    evidence=response.text[:300] if success else ""
                ))

            except Exception as e:
                results.append(PrivEscResult(
                    test_type="header_priv_esc",
                    technique=str(priv_header),
                    success=False,
                    status_code=0,
                    response_length=0,
                    url=url,
                    payload=str(priv_header),
                    evidence=str(e)
                ))

        return results

    def _is_admin_access_granted(self, response: requests.Response) -> bool:
        """Check if admin access was granted"""
        if response.status_code != 200:
            return False

        body_lower = response.text.lower()

        # Check for admin indicators
        admin_indicators = [
            'admin dashboard', 'admin panel', 'administration',
            'user management', 'system settings', 'configuration',
            'manage users', 'admin area', 'control panel'
        ]

        # Check for access denied
        denied_indicators = [
            'access denied', 'forbidden', 'unauthorized', 'not authorized',
            'permission denied', 'login required', '403', '401'
        ]

        has_admin = any(ind in body_lower for ind in admin_indicators)
        has_denied = any(ind in body_lower for ind in denied_indicators)

        return has_admin and not has_denied

    def _is_privilege_escalated(self, response: requests.Response) -> bool:
        """Check if privilege escalation succeeded"""
        if response.status_code not in [200, 201]:
            return False

        body_lower = response.text.lower()

        # Success indicators
        success_indicators = [
            'admin', 'administrator', 'superuser', 'elevated',
            'privilege', 'role":"admin', 'isadmin":true', '"admin":true'
        ]

        # Failure indicators
        failure_indicators = [
            'unauthorized', 'forbidden', 'denied', 'invalid',
            'error', 'failed', 'not allowed'
        ]

        has_success = any(ind in body_lower for ind in success_indicators)
        has_failure = any(ind in body_lower for ind in failure_indicators)

        return has_success and not has_failure

    def _save_results(self, output_file: str, results: List[PrivEscResult], findings: List[Finding]):
        """Save results to file"""
        output = {
            "findings": [f.to_dict() for f in findings],
            "raw_results": [vars(r) for r in results],
            "summary": {
                "total_tests": len(results),
                "successful_escalations": len([r for r in results if r.success])
            }
        }

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"[+] Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Privilege Escalation Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python privilege_escalation.py -u https://example.com
  python privilege_escalation.py -u https://example.com -t "Bearer low_priv_token"
  python privilege_escalation.py -u https://example.com --api-endpoint /api/user/update
  python privilege_escalation.py -u https://example.com --test-types endpoint,role,param
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--token", dest="low_priv_token", help="Low-privilege auth token")
    parser.add_argument("--api-endpoint", help="API endpoint for role manipulation tests")
    parser.add_argument("--test-types", default="endpoint,role,param,method,header",
                        help="Test types: endpoint,role,param,method,header")
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

    tester = PrivilegeEscalationTester()

    result = tester.run(
        target=args.url,
        output_file=args.output,
        low_priv_token=args.low_priv_token,
        api_endpoint=args.api_endpoint,
        test_types=args.test_types.split(','),
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl
    )

    # Print summary
    print(f"\n{'='*60}")
    print("PRIVILEGE ESCALATION TEST RESULTS")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Total Tests: {result['summary']['total_tests']}")
    print(f"Successful Escalations: {result['summary']['successful_escalations']}")
    print(f"Duration: {result['duration']:.2f}s")

    if result['results']:
        print(f"\n[!] PRIVILEGE ESCALATION VULNERABILITIES FOUND!")
        for finding in result['results']:
            print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
            print(f"  Description: {finding.description}")
            print(f"  Evidence: {finding.evidence}")
            print(f"  Remediation: {finding.remediation}")
    else:
        print("\n[+] No privilege escalation vulnerabilities found")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
