"""
TestSSL - SSL/TLS configuration testing
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import APITool
from utils.output_parser import Finding, Severity


class TestsslWrapper(APITool):
    """Wrapper for testssl.sh SSL/TLS testing tool"""
    
    @property
    def tool_name(self) -> str:
        return "testssl"
    
    def get_binary(self) -> str:
        return "testssl.sh"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build testssl-specific arguments"""
        args = []
        
        # Output
        if kwargs.get("output"):
            if kwargs.get("json"):
                args.extend(["--jsonfile", kwargs["output"]])
            elif kwargs.get("html"):
                args.extend(["--htmlfile", kwargs["output"]])
            else:
                args.extend(["--logfile", kwargs["output"]])
        
        # JSON output
        if kwargs.get("json"):
            args.append("--json")
        
        # HTML output
        if kwargs.get("html"):
            args.append("--html")
        
        # CSV output
        if kwargs.get("csv"):
            args.append("--csv")
        
        # Specific tests
        if kwargs.get("protocols"):
            args.append("-p")
        if kwargs.get("ciphers"):
            args.append("-E")
        if kwargs.get("vulnerabilities"):
            args.append("-U")
        if kwargs.get("headers"):
            args.append("-h")
        
        # All tests
        if kwargs.get("full"):
            # Default behavior without specific flags
            pass
        
        # Server preferences
        if kwargs.get("server_preferences"):
            args.append("-P")
        
        # Certificate
        if kwargs.get("certificate"):
            args.append("-S")
        
        # Server defaults
        if kwargs.get("server_defaults"):
            args.append("-s")
        
        # Heartbleed
        if kwargs.get("heartbleed"):
            args.append("-H")
        
        # CCS injection
        if kwargs.get("ccs"):
            args.append("-I")
        
        # ROBOT
        if kwargs.get("robot"):
            args.append("-R")
        
        # CRIME
        if kwargs.get("crime"):
            args.append("-C")
        
        # BREACH
        if kwargs.get("breach"):
            args.append("-B")
        
        # POODLE
        if kwargs.get("poodle"):
            args.append("-O")
        
        # BEAST
        if kwargs.get("beast"):
            args.append("-A")
        
        # FREAK
        if kwargs.get("freak"):
            args.append("-F")
        
        # Logjam
        if kwargs.get("logjam"):
            args.append("-J")
        
        # DROWN
        if kwargs.get("drown"):
            args.append("-D")
        
        # Quiet mode
        if kwargs.get("quiet"):
            args.append("--quiet")
        
        # No color
        args.append("--color")
        args.append("0")
        
        # Warnings
        if kwargs.get("warnings"):
            args.append("--warnings")
            args.append(kwargs["warnings"])
        
        # IP address
        if kwargs.get("ip"):
            args.extend(["--ip", kwargs["ip"]])
        
        # SNI
        if kwargs.get("sni"):
            args.extend(["--sni", kwargs["sni"]])
        
        # Add target
        args.append(target)
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse testssl output"""
        results = []
        output = stdout.lower()
        
        # Check for critical vulnerabilities
        critical_vulns = [
            ("heartbleed", "Heartbleed Vulnerability", "Server is vulnerable to Heartbleed (CVE-2014-0160)"),
            ("robot", "ROBOT Vulnerability", "Server is vulnerable to ROBOT attack"),
            ("drown", "DROWN Vulnerability", "Server is vulnerable to DROWN attack"),
            ("poodle", "POODLE Vulnerability", "Server is vulnerable to POODLE attack"),
        ]
        
        for vuln_name, title, description in critical_vulns:
            if f"{vuln_name}" in output and ("vulnerable" in output or "not ok" in output):
                results.append(Finding(
                    tool="testssl",
                    target="",
                    finding_type="ssl",
                    title=title,
                    description=description,
                    severity=Severity.CRITICAL
                ))
        
        # Check for high severity issues
        high_issues = [
            ("beast", "BEAST Vulnerability", "Server may be vulnerable to BEAST attack"),
            ("crime", "CRIME Vulnerability", "Server is vulnerable to CRIME attack"),
            ("breach", "BREACH Vulnerability", "Server is vulnerable to BREACH attack"),
            ("freak", "FREAK Vulnerability", "Server is vulnerable to FREAK attack"),
            ("logjam", "Logjam Vulnerability", "Server is vulnerable to Logjam attack"),
            ("ccs", "CCS Injection", "Server is vulnerable to CCS injection"),
        ]
        
        for vuln_name, title, description in high_issues:
            if vuln_name in output and "vulnerable" in output:
                results.append(Finding(
                    tool="testssl",
                    target="",
                    finding_type="ssl",
                    title=title,
                    description=description,
                    severity=Severity.HIGH
                ))
        
        # Check for weak protocols
        if "sslv2" in output and ("offered" in output or "supported" in output):
            results.append(Finding(
                tool="testssl",
                target="",
                finding_type="ssl",
                title="SSLv2 Enabled",
                description="SSLv2 is enabled, which is insecure",
                severity=Severity.HIGH
            ))
        
        if "sslv3" in output and ("offered" in output or "supported" in output):
            results.append(Finding(
                tool="testssl",
                target="",
                finding_type="ssl",
                title="SSLv3 Enabled",
                description="SSLv3 is enabled, which is insecure",
                severity=Severity.HIGH
            ))
        
        if "tls 1.0" in output and "offered" in output:
            results.append(Finding(
                tool="testssl",
                target="",
                finding_type="ssl",
                title="TLS 1.0 Enabled",
                description="TLS 1.0 is enabled, which is deprecated",
                severity=Severity.MEDIUM
            ))
        
        # Check for weak ciphers
        if "weak" in output and "cipher" in output:
            results.append(Finding(
                tool="testssl",
                target="",
                finding_type="ssl",
                title="Weak Ciphers Supported",
                description="Server supports weak cipher suites",
                severity=Severity.MEDIUM
            ))
        
        # Check for certificate issues
        if "expired" in output and "cert" in output:
            results.append(Finding(
                tool="testssl",
                target="",
                finding_type="ssl",
                title="Expired Certificate",
                description="The SSL certificate has expired",
                severity=Severity.HIGH
            ))
        
        if "self-signed" in output:
            results.append(Finding(
                tool="testssl",
                target="",
                finding_type="ssl",
                title="Self-Signed Certificate",
                description="Server uses a self-signed certificate",
                severity=Severity.MEDIUM
            ))
        
        return results


def main():
    parser = argparse.ArgumentParser(
        description="TestSSL - SSL/TLS configuration testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python testssl.py example.com
  python testssl.py example.com:443 -o results.json --json
  python testssl.py example.com -U  # Vulnerabilities only
  python testssl.py example.com -p -E  # Protocols and ciphers
        """
    )
    
    parser.add_argument("target", help="Target host[:port]")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--html", action="store_true", help="HTML output")
    parser.add_argument("--csv", action="store_true", help="CSV output")
    
    # Test types
    parser.add_argument("-p", "--protocols", action="store_true", help="Check protocols")
    parser.add_argument("-E", "--ciphers", action="store_true", help="Check ciphers")
    parser.add_argument("-U", "--vulnerabilities", action="store_true", help="Check vulnerabilities")
    parser.add_argument("-h", "--headers", action="store_true", help="Check HTTP headers")
    parser.add_argument("-S", "--certificate", action="store_true", help="Check certificate")
    parser.add_argument("-P", "--server-preferences", action="store_true", help="Server preferences")
    parser.add_argument("--full", action="store_true", help="Run all tests")
    
    # Specific vulnerability tests
    parser.add_argument("-H", "--heartbleed", action="store_true", help="Test for Heartbleed")
    parser.add_argument("-I", "--ccs", action="store_true", help="Test for CCS injection")
    parser.add_argument("-R", "--robot", action="store_true", help="Test for ROBOT")
    parser.add_argument("-C", "--crime", action="store_true", help="Test for CRIME")
    parser.add_argument("-B", "--breach", action="store_true", help="Test for BREACH")
    parser.add_argument("-O", "--poodle", action="store_true", help="Test for POODLE")
    parser.add_argument("-A", "--beast", action="store_true", help="Test for BEAST")
    parser.add_argument("-F", "--freak", action="store_true", help="Test for FREAK")
    parser.add_argument("-J", "--logjam", action="store_true", help="Test for Logjam")
    parser.add_argument("-D", "--drown", action="store_true", help="Test for DROWN")
    
    # Other options
    parser.add_argument("--ip", help="IP address")
    parser.add_argument("--sni", help="Server Name Indication")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--warnings", choices=["batch", "off"], help="Warnings handling")
    
    args = parser.parse_args()
    
    wrapper = TestsslWrapper()
    
    result = wrapper.run(
        target=args.target,
        output_file=args.output,
        json=args.json,
        html=args.html,
        csv=args.csv,
        protocols=args.protocols,
        ciphers=args.ciphers,
        vulnerabilities=args.vulnerabilities,
        headers=args.headers,
        certificate=args.certificate,
        server_preferences=args.server_preferences,
        full=args.full,
        heartbleed=args.heartbleed,
        ccs=args.ccs,
        robot=args.robot,
        crime=args.crime,
        breach=args.breach,
        poodle=args.poodle,
        beast=args.beast,
        freak=args.freak,
        logjam=args.logjam,
        drown=args.drown,
        ip=args.ip,
        sni=args.sni,
        quiet=args.quiet,
        warnings=args.warnings
    )
    
    if result["success"]:
        findings = result["results"]
        print(f"\n[+] SSL/TLS Assessment Complete")
        
        if findings:
            print(f"\n[!] Found {len(findings)} issues:")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  {finding.description}")
        else:
            print("\n[+] No significant SSL/TLS issues detected")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
