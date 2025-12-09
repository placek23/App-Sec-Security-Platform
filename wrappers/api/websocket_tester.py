"""
WebSocket Security Testing Wrapper

Comprehensive WebSocket security testing including:
- Connection testing (with/without authentication)
- Origin bypass testing
- Message injection testing
- Authentication bypass
- Cross-Site WebSocket Hijacking (CSWSH)
- Message fuzzing
- Denial of Service testing
"""
import sys
import argparse
import json
import ssl
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import APITool
from utils.output_parser import Finding, Severity


@dataclass
class WebSocketFinding:
    """Represents a WebSocket security finding"""
    test_type: str
    title: str
    description: str
    severity: str
    evidence: str = ""
    payload: str = ""
    vulnerable: bool = False


@dataclass
class MessageResult:
    """Result of sending a WebSocket message"""
    payload: str
    response: str
    success: bool
    response_time: float = 0.0
    error: str = ""


class WebSocketTester(APITool):
    """WebSocket security testing wrapper."""

    # Common WebSocket message payloads for testing
    INJECTION_PAYLOADS = [
        # JSON injection
        '{"type": "test", "data": "value"}',
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
        # XSS payloads
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        # SQL injection (if messages hit DB)
        "' OR '1'='1",
        '1; DROP TABLE users--',
        # NoSQL injection
        '{"$gt": ""}',
        '{"$ne": null}',
        # Command injection
        '; ls -la',
        '| cat /etc/passwd',
        '`id`',
        # Large payload for DoS
        'A' * 10000,
        # Null bytes
        '\x00' * 100,
        # Unicode
        '\u0000\u0001\u0002',
    ]

    # Common authentication bypass messages
    AUTH_BYPASS_PAYLOADS = [
        '{"type": "auth", "token": ""}',
        '{"type": "auth", "token": null}',
        '{"type": "auth", "token": "admin"}',
        '{"type": "auth", "admin": true}',
        '{"type": "subscribe", "channel": "admin"}',
        '{"action": "elevate", "role": "admin"}',
    ]

    @property
    def tool_name(self) -> str:
        return "websocket_tester"

    def _build_target_args(self, target: str, **kwargs) -> List[str]:
        """WebSocket tester is pure Python."""
        return []

    def check_tool_installed(self) -> bool:
        """Check if websocket dependencies are available."""
        try:
            import websocket
            return True
        except ImportError:
            try:
                import websockets
                return True
            except ImportError:
                return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run WebSocket security tests."""
        from datetime import datetime

        self.start_time = datetime.now()
        findings = []

        # Normalize WebSocket URL
        if target.startswith('http://'):
            target = target.replace('http://', 'ws://')
        elif target.startswith('https://'):
            target = target.replace('https://', 'wss://')
        elif not target.startswith('ws://') and not target.startswith('wss://'):
            target = f'wss://{target}'

        headers = kwargs.get('headers', {})
        if isinstance(headers, list):
            headers = dict(h.split(': ', 1) for h in headers if ': ' in h)

        test_types = kwargs.get('tests', 'all')
        timeout = kwargs.get('timeout', 10)

        print(f"[*] Testing WebSocket endpoint: {target}")

        # Run selected tests
        if test_types == 'all' or 'connection' in test_types:
            print("\n[*] Testing basic connection...")
            findings.extend(self.test_connection(target, headers, timeout))

        if test_types == 'all' or 'origin' in test_types:
            print("\n[*] Testing origin validation...")
            findings.extend(self.test_origin_bypass(target, headers, timeout))

        if test_types == 'all' or 'auth' in test_types:
            print("\n[*] Testing authentication bypass...")
            findings.extend(self.test_auth_bypass(target, headers, timeout))

        if test_types == 'all' or 'injection' in test_types:
            print("\n[*] Testing message injection...")
            findings.extend(self.test_injection(target, headers, timeout))

        if test_types == 'all' or 'cswsh' in test_types:
            print("\n[*] Testing Cross-Site WebSocket Hijacking...")
            findings.extend(self.test_cswsh(target, headers, timeout))

        if test_types == 'all' or 'dos' in test_types:
            print("\n[*] Testing DoS vulnerabilities...")
            findings.extend(self.test_dos(target, headers, timeout))

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        vulnerable_findings = [f for f in findings if f.vulnerable]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"websocket_test_{timestamp}.json"

        results_data = {
            'target': target,
            'duration': duration,
            'total_tests': len(findings),
            'vulnerabilities_found': len(vulnerable_findings),
            'findings': [
                {
                    'test_type': f.test_type,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity,
                    'evidence': f.evidence,
                    'payload': f.payload,
                    'vulnerable': f.vulnerable
                }
                for f in findings
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        print(f"\n[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'results': findings,
            'vulnerabilities_count': len(vulnerable_findings)
        }

    def _create_connection(self, url: str, headers: Dict = None,
                          origin: str = None, timeout: int = 10):
        """Create WebSocket connection using websocket-client library."""
        try:
            import websocket

            header_list = []
            if headers:
                for k, v in headers.items():
                    header_list.append(f"{k}: {v}")

            ws = websocket.create_connection(
                url,
                header=header_list if header_list else None,
                origin=origin,
                timeout=timeout,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )
            return ws, None
        except Exception as e:
            return None, str(e)

    def test_connection(self, url: str, headers: Dict, timeout: int) -> List[WebSocketFinding]:
        """Test basic WebSocket connection."""
        findings = []

        # Test with provided headers
        ws, error = self._create_connection(url, headers, timeout=timeout)

        if ws:
            findings.append(WebSocketFinding(
                test_type='connection',
                title='WebSocket Connection Successful',
                description='Successfully connected to WebSocket endpoint',
                severity='info',
                evidence='Connection established',
                vulnerable=False
            ))
            print("    [+] Connection successful")
            ws.close()
        else:
            findings.append(WebSocketFinding(
                test_type='connection',
                title='WebSocket Connection Failed',
                description=f'Could not establish WebSocket connection: {error}',
                severity='info',
                evidence=error,
                vulnerable=False
            ))
            print(f"    [-] Connection failed: {error}")

        # Test without authentication headers
        clean_headers = {k: v for k, v in headers.items()
                        if 'auth' not in k.lower() and 'token' not in k.lower() and 'cookie' not in k.lower()}

        if clean_headers != headers:
            ws_noauth, error = self._create_connection(url, clean_headers, timeout=timeout)

            if ws_noauth:
                findings.append(WebSocketFinding(
                    test_type='no_auth_connection',
                    title='WebSocket Accepts Unauthenticated Connections',
                    description='WebSocket endpoint accepts connections without authentication headers',
                    severity='medium',
                    evidence='Connection succeeded without auth headers',
                    vulnerable=True
                ))
                print("    [+] Unauthenticated connection accepted")
                ws_noauth.close()

        return findings

    def test_origin_bypass(self, url: str, headers: Dict, timeout: int) -> List[WebSocketFinding]:
        """Test Origin header validation."""
        findings = []

        parsed = urlparse(url)
        legitimate_origin = f"{parsed.scheme.replace('ws', 'http')}://{parsed.netloc}"

        malicious_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            f'https://{parsed.netloc}.evil.com',
            f'https://evil.{parsed.netloc}',
            f'https://evil.com.{parsed.netloc}',
            '',  # Empty origin
        ]

        for origin in malicious_origins:
            ws, error = self._create_connection(url, headers, origin=origin, timeout=timeout)

            if ws:
                findings.append(WebSocketFinding(
                    test_type='origin_bypass',
                    title='WebSocket Origin Validation Bypass',
                    description=f'WebSocket accepts connections from untrusted origin: {origin or "(empty)"}',
                    severity='high',
                    evidence=f'Connected with Origin: {origin or "(empty)"}',
                    payload=f'Origin: {origin}',
                    vulnerable=True
                ))
                print(f"    [+] Origin bypass: {origin or '(empty)'}")
                ws.close()
                break

        return findings

    def test_auth_bypass(self, url: str, headers: Dict, timeout: int) -> List[WebSocketFinding]:
        """Test authentication bypass via messages."""
        findings = []

        ws, error = self._create_connection(url, headers, timeout=timeout)
        if not ws:
            return findings

        try:
            for payload in self.AUTH_BYPASS_PAYLOADS:
                try:
                    ws.send(payload)
                    ws.settimeout(3)

                    try:
                        response = ws.recv()

                        # Check for success indicators
                        response_lower = response.lower()
                        if any(ind in response_lower for ind in ['success', 'authenticated', 'authorized', 'admin', 'granted']):
                            findings.append(WebSocketFinding(
                                test_type='auth_bypass',
                                title='Potential Authentication Bypass',
                                description='Server responded positively to auth bypass payload',
                                severity='high',
                                evidence=response[:500],
                                payload=payload,
                                vulnerable=True
                            ))
                            print(f"    [+] Auth bypass potential: {payload[:50]}...")
                            break
                    except:
                        pass

                except Exception:
                    continue
        finally:
            ws.close()

        return findings

    def test_injection(self, url: str, headers: Dict, timeout: int) -> List[WebSocketFinding]:
        """Test message injection vulnerabilities."""
        findings = []

        ws, error = self._create_connection(url, headers, timeout=timeout)
        if not ws:
            return findings

        try:
            for payload in self.INJECTION_PAYLOADS[:10]:
                try:
                    ws.send(payload)
                    ws.settimeout(3)

                    try:
                        response = ws.recv()

                        # Check for error indicators that suggest injection
                        error_indicators = [
                            'syntax', 'error', 'sql', 'mysql', 'postgres',
                            'mongodb', 'exception', 'undefined', 'null pointer',
                            'stack trace', 'internal server'
                        ]

                        response_lower = response.lower()
                        if any(ind in response_lower for ind in error_indicators):
                            findings.append(WebSocketFinding(
                                test_type='injection',
                                title='Potential Injection Vulnerability',
                                description='Error response suggests potential injection point',
                                severity='high',
                                evidence=response[:500],
                                payload=payload[:100],
                                vulnerable=True
                            ))
                            print(f"    [+] Injection error: {payload[:30]}...")

                        # Check if payload is reflected
                        if payload in response:
                            findings.append(WebSocketFinding(
                                test_type='reflection',
                                title='Message Reflection',
                                description='Payload is reflected in response (potential XSS)',
                                severity='medium',
                                evidence=response[:500],
                                payload=payload[:100],
                                vulnerable=True
                            ))
                            print(f"    [+] Reflected payload: {payload[:30]}...")

                    except:
                        pass

                except Exception:
                    continue
        finally:
            ws.close()

        return findings

    def test_cswsh(self, url: str, headers: Dict, timeout: int) -> List[WebSocketFinding]:
        """Test for Cross-Site WebSocket Hijacking vulnerability."""
        findings = []

        # Remove authentication to simulate CSWSH
        attacker_headers = {'Origin': 'https://attacker.com'}

        ws, error = self._create_connection(url, attacker_headers, origin='https://attacker.com', timeout=timeout)

        if ws:
            findings.append(WebSocketFinding(
                test_type='cswsh',
                title='Cross-Site WebSocket Hijacking (CSWSH)',
                description='WebSocket accepts connections from attacker-controlled origins without authentication validation',
                severity='high',
                evidence='Connection established from attacker.com without credentials',
                vulnerable=True
            ))
            print("    [+] CSWSH vulnerability detected")

            # Try to send a message to verify functionality
            try:
                ws.send('{"type": "ping"}')
                ws.settimeout(3)
                try:
                    response = ws.recv()
                    findings[-1].evidence += f"\nReceived: {response[:200]}"
                except:
                    pass
            except:
                pass

            ws.close()

        return findings

    def test_dos(self, url: str, headers: Dict, timeout: int) -> List[WebSocketFinding]:
        """Test DoS vulnerabilities."""
        findings = []

        # Test large message handling
        ws, error = self._create_connection(url, headers, timeout=timeout)
        if not ws:
            return findings

        try:
            # Send large message
            large_payload = 'A' * 1000000  # 1MB
            try:
                ws.send(large_payload)
                ws.settimeout(5)
                try:
                    response = ws.recv()
                    findings.append(WebSocketFinding(
                        test_type='large_message',
                        title='Large Message Accepted',
                        description='Server accepts very large WebSocket messages (1MB+)',
                        severity='low',
                        evidence='1MB message processed',
                        vulnerable=True
                    ))
                    print("    [+] Large message accepted (1MB)")
                except:
                    pass
            except Exception as e:
                if 'size' in str(e).lower() or 'limit' in str(e).lower():
                    print("    [-] Large messages blocked")
        finally:
            ws.close()

        # Test rapid message sending
        ws, error = self._create_connection(url, headers, timeout=timeout)
        if ws:
            try:
                message_count = 0
                start_time = time.time()
                for i in range(100):
                    try:
                        ws.send('{"type": "ping"}')
                        message_count += 1
                    except:
                        break

                elapsed = time.time() - start_time
                if message_count == 100:
                    findings.append(WebSocketFinding(
                        test_type='rate_limiting',
                        title='No Message Rate Limiting',
                        description=f'Sent {message_count} messages in {elapsed:.2f}s without rate limiting',
                        severity='low',
                        evidence=f'{message_count} messages in {elapsed:.2f}s',
                        vulnerable=True
                    ))
                    print(f"    [+] No rate limiting ({message_count} msgs in {elapsed:.2f}s)")
            finally:
                ws.close()

        return findings

    def fuzz_messages(self, url: str, headers: Dict, payloads: List[str],
                     timeout: int = 10) -> List[MessageResult]:
        """Send custom payloads to WebSocket endpoint."""
        results = []

        ws, error = self._create_connection(url, headers, timeout=timeout)
        if not ws:
            return [MessageResult(payload='N/A', response='', success=False, error=error)]

        try:
            for payload in payloads:
                start_time = time.time()
                try:
                    ws.send(payload)
                    ws.settimeout(5)

                    try:
                        response = ws.recv()
                        elapsed = time.time() - start_time
                        results.append(MessageResult(
                            payload=payload,
                            response=response[:1000],
                            success=True,
                            response_time=elapsed
                        ))
                    except:
                        results.append(MessageResult(
                            payload=payload,
                            response='',
                            success=True,
                            response_time=time.time() - start_time,
                            error='No response received'
                        ))

                except Exception as e:
                    results.append(MessageResult(
                        payload=payload,
                        response='',
                        success=False,
                        error=str(e)
                    ))
        finally:
            ws.close()

        return results


def main():
    parser = argparse.ArgumentParser(
        description="WebSocket Security Tester - Comprehensive WebSocket vulnerability testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python websocket_tester.py -u wss://example.com/ws
  python websocket_tester.py -u https://example.com/socket --tests connection,origin
  python websocket_tester.py -u wss://api.example.com/ws -H "Authorization: Bearer token"
  python websocket_tester.py -u wss://example.com/ws --fuzz payloads.txt
        """
    )

    parser.add_argument("-u", "--url", required=True, help="WebSocket endpoint URL")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="HTTP headers (format: 'Name: Value')")
    parser.add_argument("--tests", default="all",
                       help="Tests to run: all, connection, origin, auth, injection, cswsh, dos")
    parser.add_argument("--fuzz", dest="fuzz_file",
                       help="File with custom payloads for fuzzing")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Connection timeout (default: 10)")

    args = parser.parse_args()

    tester = WebSocketTester()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ': ' in h:
                name, value = h.split(': ', 1)
                headers[name] = value

    # Run fuzzing if payload file provided
    if args.fuzz_file:
        try:
            with open(args.fuzz_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]

            print(f"[*] Fuzzing with {len(payloads)} payloads...")
            results = tester.fuzz_messages(args.url, headers, payloads, args.timeout)

            print(f"\n[+] Fuzz Results:")
            for r in results:
                status = "OK" if r.success else "FAIL"
                print(f"  [{status}] {r.payload[:50]}... -> {r.response[:100] if r.response else r.error}")

            return 0
        except FileNotFoundError:
            print(f"[-] Payload file not found: {args.fuzz_file}")
            return 1

    # Run standard tests
    result = tester.run(
        target=args.url,
        output_file=args.output,
        headers=headers,
        tests=args.tests,
        timeout=args.timeout
    )

    if result['success']:
        vuln_findings = [f for f in result['results'] if f.vulnerable]
        print(f"\n{'='*60}")
        print(f"WebSocket Security Assessment Complete")
        print(f"{'='*60}")
        print(f"Total tests: {len(result['results'])}")
        print(f"Vulnerabilities: {len(vuln_findings)}")

        if vuln_findings:
            print("\n[!] Vulnerabilities Found:")
            for finding in vuln_findings:
                print(f"\n  [{finding.severity.upper()}] {finding.title}")
                print(f"  {finding.description}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
