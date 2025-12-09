"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Testing Wrapper

Tests for CORS misconfigurations including:
- Reflected origin
- Wildcard origin with credentials
- Null origin bypass
- Subdomain matching bypass
- Pre-domain/post-domain bypass
- Protocol downgrade
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
class CORSFinding:
    """Represents a CORS misconfiguration finding"""
    origin_tested: str
    origin_type: str
    acao_header: str  # Access-Control-Allow-Origin
    acac_header: str  # Access-Control-Allow-Credentials
    status_code: int
    reflected: bool
    credentials_allowed: bool
    vulnerability_level: str  # none, low, medium, high, critical
    evidence: Optional[str] = None


class CORSTester(BaseToolWrapper):
    """CORS misconfiguration testing wrapper."""

    @property
    def tool_name(self) -> str:
        return "cors_tester"

    @property
    def tool_category(self) -> str:
        return "advanced"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """CORS tester doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def _generate_test_origins(self, target_domain: str) -> List[Dict[str, str]]:
        """Generate list of origins to test based on target domain."""
        # Parse target domain
        if '://' in target_domain:
            parsed = urlparse(target_domain)
            target_domain = parsed.netloc

        # Remove port if present
        if ':' in target_domain:
            target_domain = target_domain.split(':')[0]

        # Extract base domain (handle subdomains)
        parts = target_domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = target_domain

        return [
            # Completely different domains
            {'origin': 'https://evil.com', 'type': 'external'},
            {'origin': 'https://attacker.com', 'type': 'external'},
            {'origin': 'http://malicious-site.com', 'type': 'external'},

            # Null origin (can be triggered by sandboxed iframes, file://, etc.)
            {'origin': 'null', 'type': 'null'},

            # Pre-domain attacks (attacker registers similar domain)
            {'origin': f'https://evil{target_domain}', 'type': 'pre_domain'},
            {'origin': f'https://attacker{target_domain}', 'type': 'pre_domain'},
            {'origin': f'https://{target_domain}.evil.com', 'type': 'post_domain'},

            # Subdomain attacks
            {'origin': f'https://evil.{target_domain}', 'type': 'subdomain'},
            {'origin': f'https://attacker.{target_domain}', 'type': 'subdomain'},
            {'origin': f'https://test.evil.{base_domain}', 'type': 'subdomain'},

            # Post-domain attacks
            {'origin': f'https://{target_domain}evil.com', 'type': 'post_domain'},
            {'origin': f'https://{target_domain}.attacker.com', 'type': 'post_domain'},

            # Protocol downgrade
            {'origin': f'http://{target_domain}', 'type': 'protocol_downgrade'},

            # Variations with port
            {'origin': f'https://{target_domain}:443', 'type': 'port_variation'},
            {'origin': f'https://{target_domain}:8443', 'type': 'port_variation'},

            # Special characters
            {'origin': f'https://{target_domain}%60.evil.com', 'type': 'special_char'},
            {'origin': f'https://{target_domain}`.evil.com', 'type': 'special_char'},

            # Regex bypass attempts
            {'origin': f'https://{target_domain}@evil.com', 'type': 'regex_bypass'},
            {'origin': f'https://evil.com?.{target_domain}', 'type': 'regex_bypass'},
            {'origin': f'https://evil.com#{target_domain}', 'type': 'regex_bypass'},
        ]

    def test_cors(self, url: str, headers: Optional[Dict] = None,
                  cookies: Optional[Dict] = None, timeout: int = 10,
                  custom_origins: Optional[List[str]] = None) -> List[CORSFinding]:
        """Test for CORS misconfigurations."""
        findings = []
        headers = headers or {}

        # Parse target for generating test origins
        parsed = urlparse(url)
        target_domain = parsed.netloc

        # Generate test origins or use custom ones
        if custom_origins:
            test_origins = [{'origin': o, 'type': 'custom'} for o in custom_origins]
        else:
            test_origins = self._generate_test_origins(target_domain)

        for origin_data in test_origins:
            finding = self._test_origin(
                url, origin_data['origin'], origin_data['type'],
                headers, cookies, timeout
            )
            findings.append(finding)

        return findings

    def _test_origin(self, url: str, origin: str, origin_type: str,
                     headers: Dict, cookies: Optional[Dict], timeout: int) -> CORSFinding:
        """Test a specific origin."""
        test_headers = headers.copy()
        test_headers['Origin'] = origin

        try:
            response = requests.get(
                url,
                headers=test_headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=False,
                verify=False
            )

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            # Check if origin is reflected
            reflected = (origin == acao) or (acao == '*')

            # Check if credentials are allowed
            credentials_allowed = acac.lower() == 'true'

            # Assess vulnerability level
            vuln_level = self._assess_vulnerability(origin, acao, acac, origin_type)

            evidence = None
            if vuln_level != 'none':
                evidence = f"ACAO: {acao}, ACAC: {acac}"

            return CORSFinding(
                origin_tested=origin,
                origin_type=origin_type,
                acao_header=acao,
                acac_header=acac,
                status_code=response.status_code,
                reflected=reflected,
                credentials_allowed=credentials_allowed,
                vulnerability_level=vuln_level,
                evidence=evidence
            )
        except Exception as e:
            return CORSFinding(
                origin_tested=origin,
                origin_type=origin_type,
                acao_header='',
                acac_header='',
                status_code=0,
                reflected=False,
                credentials_allowed=False,
                vulnerability_level='none',
                evidence=str(e)
            )

    def _assess_vulnerability(self, origin: str, acao: str, acac: str,
                              origin_type: str) -> str:
        """Assess CORS vulnerability severity."""
        if not acao:
            return 'none'

        credentials = acac.lower() == 'true'

        # Critical: Wildcard with credentials (technically invalid but some servers)
        if acao == '*' and credentials:
            return 'critical'

        # Critical: Null origin reflected with credentials
        if origin == 'null' and acao == 'null' and credentials:
            return 'critical'

        # High: External/attacker origin reflected with credentials
        if origin == acao and credentials and origin_type in ['external', 'pre_domain', 'post_domain']:
            return 'high'

        # High: Subdomain reflected with credentials (if subdomain takeover possible)
        if origin == acao and credentials and origin_type == 'subdomain':
            return 'high'

        # Medium: External origin reflected without credentials
        if origin == acao and origin_type in ['external', 'pre_domain', 'post_domain']:
            return 'medium'

        # Medium: Null origin reflected without credentials
        if origin == 'null' and acao == 'null':
            return 'medium'

        # Low: Wildcard without credentials
        if acao == '*':
            return 'low'

        # Low: Same-site variations
        if origin == acao and origin_type in ['protocol_downgrade', 'port_variation']:
            return 'low'

        # Info: Subdomain reflected without credentials
        if origin == acao and origin_type == 'subdomain':
            return 'info'

        return 'none'

    def test_preflight(self, url: str, origin: str = 'https://evil.com',
                       method: str = 'POST', headers: Optional[Dict] = None,
                       cookies: Optional[Dict] = None, timeout: int = 10) -> Dict[str, Any]:
        """Test preflight (OPTIONS) request handling."""
        test_headers = headers.copy() if headers else {}
        test_headers['Origin'] = origin
        test_headers['Access-Control-Request-Method'] = method
        test_headers['Access-Control-Request-Headers'] = 'X-Custom-Header'

        try:
            response = requests.options(
                url,
                headers=test_headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=False,
                verify=False
            )

            return {
                'status_code': response.status_code,
                'acao': response.headers.get('Access-Control-Allow-Origin', ''),
                'acam': response.headers.get('Access-Control-Allow-Methods', ''),
                'acah': response.headers.get('Access-Control-Allow-Headers', ''),
                'acac': response.headers.get('Access-Control-Allow-Credentials', ''),
                'acma': response.headers.get('Access-Control-Max-Age', ''),
                'potential_vuln': origin == response.headers.get('Access-Control-Allow-Origin', '')
            }
        except Exception as e:
            return {
                'status_code': 0,
                'error': str(e),
                'potential_vuln': False
            }

    def test_with_credentials(self, url: str, origin: str = 'https://evil.com',
                              headers: Optional[Dict] = None, timeout: int = 10) -> Dict[str, Any]:
        """Test if credentials (cookies, auth headers) are exposed."""
        test_headers = headers.copy() if headers else {}
        test_headers['Origin'] = origin

        try:
            response = requests.get(
                url,
                headers=test_headers,
                timeout=timeout,
                allow_redirects=False,
                verify=False
            )

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            # Check for sensitive data in response that would be accessible
            sensitive_indicators = [
                'password', 'token', 'api_key', 'secret', 'session',
                'credit_card', 'ssn', 'email', 'phone', 'address'
            ]
            has_sensitive_data = any(
                ind in response.text.lower() for ind in sensitive_indicators
            )

            is_vulnerable = (
                origin == acao and
                acac.lower() == 'true'
            )

            return {
                'origin': origin,
                'acao': acao,
                'acac': acac,
                'credentials_exposed': is_vulnerable,
                'has_sensitive_data': has_sensitive_data,
                'response_length': len(response.text),
                'vulnerability': 'critical' if is_vulnerable and has_sensitive_data else (
                    'high' if is_vulnerable else 'none'
                )
            }
        except Exception as e:
            return {
                'origin': origin,
                'error': str(e),
                'credentials_exposed': False,
                'vulnerability': 'none'
            }

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run CORS tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        timeout = kwargs.get('timeout', 10)
        custom_origins = kwargs.get('custom_origins')

        all_findings = []

        print(f"[*] Testing CORS on {target}")

        findings = self.test_cors(
            url=target, headers=headers, cookies=cookies,
            timeout=timeout, custom_origins=custom_origins
        )
        all_findings.extend(findings)

        # Test preflight
        print("[*] Testing preflight request...")
        preflight_result = self.test_preflight(url=target, headers=headers, timeout=timeout)

        # Test with credentials
        print("[*] Testing credential exposure...")
        creds_result = self.test_with_credentials(url=target, headers=headers, timeout=timeout)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter vulnerable findings
        vulnerable = [f for f in all_findings if f.vulnerability_level not in ['none', 'info']]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"cors_test_{timestamp}.json"

        results_data = {
            'target': target,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'preflight_test': preflight_result,
            'credentials_test': creds_result,
            'findings': [
                {
                    'origin_tested': f.origin_tested,
                    'origin_type': f.origin_type,
                    'acao_header': f.acao_header,
                    'acac_header': f.acac_header,
                    'status_code': f.status_code,
                    'reflected': f.reflected,
                    'credentials_allowed': f.credentials_allowed,
                    'vulnerability_level': f.vulnerability_level,
                    'evidence': f.evidence
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
            'vulnerable_count': len(vulnerable),
            'preflight': preflight_result,
            'credentials': creds_result
        }


def main():
    parser = argparse.ArgumentParser(
        description="CORS Tester - Test for CORS misconfiguration vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cors_tester.py -u "https://example.com/api/data"
  python cors_tester.py -u "https://api.example.com/users" --origins "https://evil.com,https://attacker.com"
  python cors_tester.py -u "https://example.com/sensitive" -H "Authorization: Bearer token"
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--origins", help="Comma-separated list of custom origins to test")
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

    # Parse custom origins
    custom_origins = None
    if args.origins:
        custom_origins = [o.strip() for o in args.origins.split(',')]

    tester = CORSTester()

    result = tester.run(
        target=args.url,
        headers=headers if headers else None,
        cookies=cookies,
        timeout=args.timeout,
        custom_origins=custom_origins,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"CORS Misconfiguration Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    # Print vulnerability breakdown by level
    vuln_levels = {}
    for finding in result['results']:
        level = finding.vulnerability_level
        vuln_levels[level] = vuln_levels.get(level, 0) + 1

    print(f"\nVulnerability Levels:")
    for level in ['critical', 'high', 'medium', 'low', 'info', 'none']:
        if level in vuln_levels:
            print(f"  {level.upper()}: {vuln_levels[level]}")

    if result['vulnerable_count'] > 0:
        print(f"\n[!] CORS MISCONFIGURATION FOUND!")
        for finding in result['results']:
            if finding.vulnerability_level in ['critical', 'high', 'medium']:
                print(f"\n  Origin: {finding.origin_tested}")
                print(f"  Type: {finding.origin_type}")
                print(f"  Level: {finding.vulnerability_level.upper()}")
                print(f"  ACAO: {finding.acao_header}")
                print(f"  ACAC: {finding.acac_header}")
    else:
        print("\n[+] No significant CORS vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
