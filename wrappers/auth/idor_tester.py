"""
IDOR Tester - Insecure Direct Object Reference vulnerability testing
"""
import sys
import argparse
import requests
import urllib3
import re
import uuid
import json
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
class IDORResult:
    """Result of an IDOR test"""
    test_type: str
    original_id: str
    tested_id: str
    accessible: bool
    status_code: int
    response_length: int
    url: str
    evidence: str = ""
    same_user_data: bool = False


class IDORTester(AuthTool):
    """Tester for Insecure Direct Object Reference vulnerabilities"""

    @property
    def tool_name(self) -> str:
        return "idor_tester"

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
        """Execute IDOR tests"""
        from datetime import datetime

        self.start_time = datetime.now()
        results = []
        findings = []

        print(f"[*] Starting IDOR tests on {target}")

        # Get test configuration
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies", {})
        timeout = kwargs.get("timeout", 10)
        verify_ssl = kwargs.get("verify_ssl", False)
        param_name = kwargs.get("param_name")
        test_types = kwargs.get("test_types", ["numeric", "uuid", "encoded", "path"])

        # User tokens for horizontal privilege testing
        user1_token = kwargs.get("user1_token")
        user2_resources = kwargs.get("user2_resources", [])

        # Add authorization header if token provided
        if user1_token:
            headers["Authorization"] = f"Bearer {user1_token}"

        # Numeric IDOR
        if "numeric" in test_types:
            print("[*] Testing numeric IDOR...")
            start_id = kwargs.get("start_id", 1)
            count = kwargs.get("count", 20)
            numeric_results = self._test_numeric_idor(
                target, param_name, start_id, count,
                headers, cookies, timeout, verify_ssl
            )
            results.extend(numeric_results)

            accessible = [r for r in numeric_results if r.accessible]
            if len(accessible) > 1:  # Multiple accessible = potential IDOR
                findings.append(Finding(
                    tool="idor_tester",
                    target=target,
                    finding_type="idor",
                    title="Numeric IDOR Vulnerability",
                    description=f"Multiple resources accessible via sequential IDs. {len(accessible)} of {len(numeric_results)} IDs returned data.",
                    severity=Severity.HIGH,
                    evidence=f"Accessible IDs: {[r.tested_id for r in accessible[:5]]}",
                    remediation="Implement proper authorization checks for each resource access"
                ))

        # UUID IDOR
        if "uuid" in test_types:
            print("[*] Testing UUID IDOR...")
            known_uuid = kwargs.get("known_uuid")
            test_uuids = kwargs.get("test_uuids", self._generate_test_uuids())
            uuid_results = self._test_uuid_idor(
                target, param_name, known_uuid, test_uuids,
                headers, cookies, timeout, verify_ssl
            )
            results.extend(uuid_results)

            accessible = [r for r in uuid_results if r.accessible]
            if accessible:
                findings.append(Finding(
                    tool="idor_tester",
                    target=target,
                    finding_type="idor",
                    title="UUID IDOR Vulnerability",
                    description=f"Resources accessible via UUID manipulation. {len(accessible)} UUIDs returned data.",
                    severity=Severity.HIGH,
                    evidence=f"Accessible UUIDs: {[r.tested_id for r in accessible[:3]]}",
                    remediation="UUIDs alone don't provide security - implement authorization checks"
                ))

        # Encoded ID IDOR (Base64, etc.)
        if "encoded" in test_types:
            print("[*] Testing encoded ID IDOR...")
            encoded_results = self._test_encoded_idor(
                target, param_name,
                headers, cookies, timeout, verify_ssl
            )
            results.extend(encoded_results)

            accessible = [r for r in encoded_results if r.accessible]
            if accessible:
                findings.append(Finding(
                    tool="idor_tester",
                    target=target,
                    finding_type="idor",
                    title="Encoded ID IDOR Vulnerability",
                    description=f"Resources accessible via encoded ID manipulation.",
                    severity=Severity.HIGH,
                    evidence=f"Accessible encoded IDs: {[r.tested_id for r in accessible[:3]]}",
                    remediation="Encoding is not encryption - implement proper authorization"
                ))

        # Path-based IDOR
        if "path" in test_types:
            print("[*] Testing path-based IDOR...")
            path_results = self._test_path_idor(
                target, headers, cookies, timeout, verify_ssl
            )
            results.extend(path_results)

            accessible = [r for r in path_results if r.accessible]
            if accessible:
                findings.append(Finding(
                    tool="idor_tester",
                    target=target,
                    finding_type="idor",
                    title="Path-based IDOR Vulnerability",
                    description=f"Resources accessible via path manipulation.",
                    severity=Severity.HIGH,
                    evidence=f"Accessible paths: {[r.url for r in accessible[:3]]}",
                    remediation="Validate user authorization for path-based resource access"
                ))

        # Horizontal privilege escalation
        if "horizontal" in test_types and user2_resources:
            print("[*] Testing horizontal privilege escalation...")
            horiz_results = self._test_horizontal_escalation(
                user2_resources, headers, cookies, timeout, verify_ssl
            )
            results.extend(horiz_results)

            accessible = [r for r in horiz_results if r.accessible]
            if accessible:
                findings.append(Finding(
                    tool="idor_tester",
                    target=target,
                    finding_type="idor",
                    title="Horizontal Privilege Escalation",
                    description=f"User can access other users' resources. {len(accessible)} resources accessible.",
                    severity=Severity.CRITICAL,
                    evidence=f"Accessible resources: {[r.url for r in accessible[:3]]}",
                    remediation="Implement strict user-based authorization for all resources"
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
                "accessible_resources": len([r for r in results if r.accessible]),
                "findings_count": len(findings)
            }
        }

    def _test_numeric_idor(self, url: str, param_name: str, start_id: int, count: int,
                           headers: dict, cookies: dict, timeout: int, verify_ssl: bool) -> List[IDORResult]:
        """Test for numeric IDOR vulnerabilities"""
        results = []

        for i in range(start_id, start_id + count):
            try:
                test_url = self._replace_id_in_url(url, param_name, str(i))

                response = requests.get(
                    test_url, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                accessible = self._is_resource_accessible(response)

                results.append(IDORResult(
                    test_type="numeric",
                    original_id=str(start_id),
                    tested_id=str(i),
                    accessible=accessible,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=test_url,
                    evidence=response.text[:200] if accessible else ""
                ))

            except Exception as e:
                results.append(IDORResult(
                    test_type="numeric",
                    original_id=str(start_id),
                    tested_id=str(i),
                    accessible=False,
                    status_code=0,
                    response_length=0,
                    url=url,
                    evidence=str(e)
                ))

        return results

    def _test_uuid_idor(self, url: str, param_name: str, known_uuid: str,
                        test_uuids: List[str], headers: dict, cookies: dict,
                        timeout: int, verify_ssl: bool) -> List[IDORResult]:
        """Test for UUID-based IDOR vulnerabilities"""
        results = []

        # Get baseline with known UUID if provided
        baseline_length = 0
        if known_uuid:
            try:
                baseline_url = self._replace_id_in_url(url, param_name, known_uuid)
                baseline_resp = requests.get(baseline_url, headers=headers, cookies=cookies,
                                            timeout=timeout, verify=verify_ssl)
                baseline_length = len(baseline_resp.text)
            except:
                pass

        for test_uuid in test_uuids:
            try:
                test_url = self._replace_id_in_url(url, param_name, test_uuid)

                response = requests.get(
                    test_url, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                accessible = self._is_resource_accessible(response)
                same_data = baseline_length > 0 and abs(len(response.text) - baseline_length) < 50

                results.append(IDORResult(
                    test_type="uuid",
                    original_id=known_uuid or "",
                    tested_id=test_uuid,
                    accessible=accessible,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=test_url,
                    evidence=response.text[:200] if accessible else "",
                    same_user_data=same_data
                ))

            except Exception as e:
                results.append(IDORResult(
                    test_type="uuid",
                    original_id=known_uuid or "",
                    tested_id=test_uuid,
                    accessible=False,
                    status_code=0,
                    response_length=0,
                    url=url,
                    evidence=str(e)
                ))

        return results

    def _test_encoded_idor(self, url: str, param_name: str, headers: dict,
                           cookies: dict, timeout: int, verify_ssl: bool) -> List[IDORResult]:
        """Test for encoded ID IDOR (Base64, hex, etc.)"""
        import base64

        results = []

        # Generate encoded test IDs
        test_ids = []
        for i in range(1, 21):
            # Base64 encoded
            test_ids.append(("base64", base64.b64encode(str(i).encode()).decode()))
            # Hex encoded
            test_ids.append(("hex", hex(i)[2:]))
            # Padded Base64
            test_ids.append(("base64_padded", base64.b64encode(f"user_{i}".encode()).decode()))

        for encoding, encoded_id in test_ids:
            try:
                test_url = self._replace_id_in_url(url, param_name, encoded_id)

                response = requests.get(
                    test_url, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                accessible = self._is_resource_accessible(response)

                results.append(IDORResult(
                    test_type=f"encoded_{encoding}",
                    original_id="",
                    tested_id=encoded_id,
                    accessible=accessible,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=test_url,
                    evidence=response.text[:200] if accessible else ""
                ))

            except Exception as e:
                results.append(IDORResult(
                    test_type=f"encoded_{encoding}",
                    original_id="",
                    tested_id=encoded_id,
                    accessible=False,
                    status_code=0,
                    response_length=0,
                    url=url,
                    evidence=str(e)
                ))

        return results

    def _test_path_idor(self, url: str, headers: dict, cookies: dict,
                        timeout: int, verify_ssl: bool) -> List[IDORResult]:
        """Test for path-based IDOR"""
        results = []

        # Extract ID patterns from URL
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')

        # Find numeric or UUID-like segments
        id_indices = []
        for i, part in enumerate(path_parts):
            if part.isdigit() or self._is_uuid(part):
                id_indices.append(i)

        if not id_indices:
            return results

        # Test with different IDs
        for idx in id_indices:
            original_id = path_parts[idx]

            # Test numeric variations
            if original_id.isdigit():
                test_ids = [str(int(original_id) + i) for i in range(-5, 10)]
            else:
                test_ids = self._generate_test_uuids()

            for test_id in test_ids:
                try:
                    new_parts = path_parts.copy()
                    new_parts[idx] = test_id
                    new_path = '/'.join(new_parts)

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))

                    response = requests.get(
                        test_url, headers=headers, cookies=cookies,
                        timeout=timeout, verify=verify_ssl
                    )

                    accessible = self._is_resource_accessible(response)

                    results.append(IDORResult(
                        test_type="path",
                        original_id=original_id,
                        tested_id=test_id,
                        accessible=accessible,
                        status_code=response.status_code,
                        response_length=len(response.text),
                        url=test_url,
                        evidence=response.text[:200] if accessible else ""
                    ))

                except Exception as e:
                    results.append(IDORResult(
                        test_type="path",
                        original_id=original_id,
                        tested_id=test_id,
                        accessible=False,
                        status_code=0,
                        response_length=0,
                        url=url,
                        evidence=str(e)
                    ))

        return results

    def _test_horizontal_escalation(self, user2_resources: List[str], headers: dict,
                                     cookies: dict, timeout: int, verify_ssl: bool) -> List[IDORResult]:
        """Test horizontal privilege escalation (accessing other user's resources)"""
        results = []

        for resource_url in user2_resources:
            try:
                response = requests.get(
                    resource_url, headers=headers, cookies=cookies,
                    timeout=timeout, verify=verify_ssl
                )

                accessible = self._is_resource_accessible(response)

                results.append(IDORResult(
                    test_type="horizontal_escalation",
                    original_id="user1",
                    tested_id="user2_resource",
                    accessible=accessible,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    url=resource_url,
                    evidence=response.text[:200] if accessible else ""
                ))

            except Exception as e:
                results.append(IDORResult(
                    test_type="horizontal_escalation",
                    original_id="user1",
                    tested_id="user2_resource",
                    accessible=False,
                    status_code=0,
                    response_length=0,
                    url=resource_url,
                    evidence=str(e)
                ))

        return results

    def _replace_id_in_url(self, url: str, param_name: str, new_id: str) -> str:
        """Replace ID in URL (query parameter or path placeholder)"""
        if param_name:
            # Check if placeholder in URL
            if f"{{{param_name}}}" in url:
                return url.replace(f"{{{param_name}}}", new_id)

            # Check if parameter in query string
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if param_name in params:
                params[param_name] = [new_id]
                new_query = urlencode(params, doseq=True)
                return urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

            # Add as new parameter
            if parsed.query:
                return f"{url}&{param_name}={new_id}"
            return f"{url}?{param_name}={new_id}"

        return url

    def _is_resource_accessible(self, response: requests.Response) -> bool:
        """Determine if a resource was successfully accessed"""
        if response.status_code == 200:
            # Check for common error messages in body
            body_lower = response.text.lower()
            error_indicators = [
                'not found', 'does not exist', 'no access', 'unauthorized',
                'forbidden', 'permission denied', 'access denied', '404',
                'invalid id', 'resource not found'
            ]
            return not any(err in body_lower for err in error_indicators)

        return False

    def _is_uuid(self, s: str) -> bool:
        """Check if string is a valid UUID"""
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        return bool(uuid_pattern.match(s))

    def _generate_test_uuids(self) -> List[str]:
        """Generate test UUIDs"""
        return [
            str(uuid.uuid4()),
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "12345678-1234-1234-1234-123456789012",
        ]

    def _save_results(self, output_file: str, results: List[IDORResult], findings: List[Finding]):
        """Save results to file"""
        output = {
            "findings": [f.to_dict() for f in findings],
            "raw_results": [vars(r) for r in results],
            "summary": {
                "total_tests": len(results),
                "accessible_resources": len([r for r in results if r.accessible])
            }
        }

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"[+] Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="IDOR (Insecure Direct Object Reference) Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python idor_tester.py -u "https://example.com/api/users/{id}" -p id
  python idor_tester.py -u "https://example.com/api/users?id=1" -p id --start-id 1 --count 50
  python idor_tester.py -u "https://example.com/api/profile" -t "Bearer token123" --test-types numeric,uuid
  python idor_tester.py -u "https://example.com/api/doc/123" --test-types path
        """
    )

    parser.add_argument("-u", "--url", required=True, help="URL to test (use {param} for path params)")
    parser.add_argument("-p", "--param", dest="param_name", help="Parameter name containing the ID")
    parser.add_argument("--start-id", type=int, default=1, help="Starting ID for numeric tests")
    parser.add_argument("--count", type=int, default=20, help="Number of IDs to test")
    parser.add_argument("--known-uuid", help="Known valid UUID for comparison")
    parser.add_argument("--test-uuids", nargs="+", help="Specific UUIDs to test")
    parser.add_argument("--test-types", default="numeric,uuid,encoded,path",
                        help="Test types (comma-separated): numeric,uuid,encoded,path,horizontal")
    parser.add_argument("-t", "--token", dest="user1_token", help="Authorization token")
    parser.add_argument("--user2-resources", nargs="+", help="Other user's resource URLs for horizontal test")
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

    tester = IDORTester()

    result = tester.run(
        target=args.url,
        output_file=args.output,
        param_name=args.param_name,
        start_id=args.start_id,
        count=args.count,
        known_uuid=args.known_uuid,
        test_uuids=args.test_uuids,
        test_types=args.test_types.split(','),
        user1_token=args.user1_token,
        user2_resources=args.user2_resources or [],
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl
    )

    # Print summary
    print(f"\n{'='*60}")
    print("IDOR TEST RESULTS")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Total Tests: {result['summary']['total_tests']}")
    print(f"Accessible Resources: {result['summary']['accessible_resources']}")
    print(f"Duration: {result['duration']:.2f}s")

    if result['results']:
        print(f"\n[!] IDOR VULNERABILITIES FOUND!")
        for finding in result['results']:
            print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
            print(f"  Description: {finding.description}")
            print(f"  Evidence: {finding.evidence}")
            print(f"  Remediation: {finding.remediation}")
    else:
        print("\n[+] No IDOR vulnerabilities found")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
