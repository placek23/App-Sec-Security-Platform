"""
JWT Tool - JWT token testing and exploitation
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import AuthTool
from utils.output_parser import Finding, Severity


class JwtToolWrapper(AuthTool):
    """Wrapper for jwt_tool JWT testing tool"""
    
    @property
    def tool_name(self) -> str:
        return "jwt_tool"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build jwt_tool-specific arguments"""
        args = [target]  # JWT token
        
        # Target URL
        if kwargs.get("target_url"):
            args.extend(["-t", kwargs["target_url"]])
        
        # Request options
        if kwargs.get("cookies"):
            args.extend(["-c", kwargs["cookies"]])
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        if kwargs.get("data"):
            args.extend(["-d", kwargs["data"]])
        if kwargs.get("method"):
            args.extend(["-X", kwargs["method"]])
        
        # Mode - All tests
        if kwargs.get("mode") == "at" or kwargs.get("all_tests"):
            args.extend(["-M", "at"])
        # Mode - Exploit
        elif kwargs.get("mode") == "pb":
            args.extend(["-M", "pb"])
        
        # Specific exploits
        if kwargs.get("exploit"):
            args.extend(["-X", kwargs["exploit"]])
        
        # Key for signing
        if kwargs.get("key"):
            args.extend(["-pk", kwargs["key"]])
        
        # Key file
        if kwargs.get("key_file"):
            args.extend(["-pkf", kwargs["key_file"]])
        
        # Crack secret
        if kwargs.get("crack"):
            args.extend(["-C", "-d", kwargs["crack"]])
        
        # Wordlist for cracking
        if kwargs.get("wordlist"):
            args.extend(["-d", kwargs["wordlist"]])
        
        # Tamper claims
        if kwargs.get("tamper"):
            args.extend(["-T"])
        
        # Inject claims
        if kwargs.get("inject"):
            args.extend(["-I"])
        if kwargs.get("inject_claim"):
            args.extend(["-pc", kwargs["inject_claim"]])
        if kwargs.get("inject_value"):
            args.extend(["-pv", kwargs["inject_value"]])
        
        # Sign with algorithm
        if kwargs.get("sign_alg"):
            args.extend(["-S", kwargs["sign_alg"]])
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse jwt_tool output"""
        results = []
        output = stdout.lower()
        
        # Check for vulnerabilities
        if "vulnerable" in output or "exploit" in output:
            if "alg:none" in output or "algorithm none" in output:
                results.append(Finding(
                    tool="jwt_tool",
                    target="",
                    finding_type="jwt",
                    title="JWT Algorithm None Attack",
                    description="The server accepts tokens with 'none' algorithm",
                    severity=Severity.CRITICAL
                ))
            
            if "key confusion" in output or "algorithm confusion" in output:
                results.append(Finding(
                    tool="jwt_tool",
                    target="",
                    finding_type="jwt",
                    title="JWT Algorithm Confusion",
                    description="The server is vulnerable to algorithm confusion attack",
                    severity=Severity.CRITICAL
                ))
            
            if "weak secret" in output or "cracked" in output:
                results.append(Finding(
                    tool="jwt_tool",
                    target="",
                    finding_type="jwt",
                    title="Weak JWT Secret",
                    description="The JWT secret was successfully cracked",
                    severity=Severity.HIGH
                ))
        
        # Check for expired/invalid tokens
        if "expired" in output:
            results.append(Finding(
                tool="jwt_tool",
                target="",
                finding_type="jwt",
                title="JWT Token Expired",
                description="The JWT token has expired",
                severity=Severity.INFO
            ))
        
        return results


def main():
    parser = argparse.ArgumentParser(
        description="JWT Tool - JWT token testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_tool.py "eyJhbG..." -M at
  python jwt_tool.py "eyJhbG..." -t https://example.com/api -C -d wordlist.txt
  python jwt_tool.py "eyJhbG..." -I -pc "role" -pv "admin"
  python jwt_tool.py "eyJhbG..." -S hs256 -pk "secret123"
        """
    )
    
    parser.add_argument("token", help="JWT token to test")
    
    # Target options
    parser.add_argument("-t", "--target", dest="target_url", help="Target URL to test against")
    parser.add_argument("-c", "--cookie", dest="cookies", help="Cookies")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Headers")
    parser.add_argument("-d", "--data", help="POST data")
    parser.add_argument("-X", "--method", help="HTTP method")
    
    # Mode options
    parser.add_argument("-M", "--mode", choices=["at", "pb"], help="Mode (at=all tests, pb=playbook)")
    parser.add_argument("--all-tests", action="store_true", help="Run all tests")
    
    # Exploit options
    parser.add_argument("--exploit", help="Specific exploit to run")
    parser.add_argument("-pk", "--key", help="Key for signing")
    parser.add_argument("-pkf", "--key-file", help="Key file path")
    
    # Cracking options
    parser.add_argument("-C", "--crack", action="store_true", help="Crack JWT secret")
    parser.add_argument("-w", "--wordlist", help="Wordlist for cracking")
    
    # Injection options
    parser.add_argument("-T", "--tamper", action="store_true", help="Tamper mode")
    parser.add_argument("-I", "--inject", action="store_true", help="Inject claims")
    parser.add_argument("-pc", "--inject-claim", help="Claim to inject")
    parser.add_argument("-pv", "--inject-value", help="Value for injected claim")
    
    # Signing options
    parser.add_argument("-S", "--sign", dest="sign_alg", help="Sign with algorithm")
    
    # Output options
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    wrapper = JwtToolWrapper()
    
    result = wrapper.run(
        target=args.token,
        target_url=args.target_url,
        cookies=args.cookies,
        headers=args.headers,
        data=args.data,
        method=args.method,
        mode=args.mode,
        all_tests=args.all_tests,
        exploit=args.exploit,
        key=args.key,
        key_file=args.key_file,
        crack=args.crack,
        wordlist=args.wordlist,
        tamper=args.tamper,
        inject=args.inject,
        inject_claim=args.inject_claim,
        inject_value=args.inject_value,
        sign_alg=args.sign_alg,
        output=args.output,
        verbose=args.verbose
    )
    
    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] JWT VULNERABILITIES FOUND!")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  {finding.description}")
        else:
            print("\n[+] No JWT vulnerabilities detected")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
