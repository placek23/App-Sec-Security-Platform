"""
Authentication & Authorization Testing Workflow
Phase 5: Comprehensive auth security testing
"""
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.auth import (
    AuthBypassTester,
    IDORTester,
    JWTAttacksTester,
    PrivilegeEscalationTester,
    HydraWrapper
)
from utils.output_parser import Finding, Severity
from utils.reporter import Reporter


class AuthTestingWorkflow:
    """Comprehensive authentication and authorization testing workflow"""

    def __init__(self, target: str, output_dir: str = None):
        self.target = target
        self.output_dir = Path(output_dir or f"./output/auth_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize testers
        self.auth_bypass = AuthBypassTester()
        self.idor_tester = IDORTester()
        self.jwt_attacks = JWTAttacksTester()
        self.priv_esc = PrivilegeEscalationTester()
        self.hydra = HydraWrapper()

        # Results storage
        self.all_findings: List[Finding] = []
        self.results: Dict[str, Any] = {
            "auth_bypass": [],
            "idor": [],
            "jwt": [],
            "privilege_escalation": [],
            "brute_force": []
        }

    def run_auth_bypass_tests(self, login_url: str, username_field: str = "username",
                               password_field: str = "password", **kwargs) -> Dict[str, Any]:
        """Run authentication bypass tests"""
        print("\n" + "=" * 60)
        print("AUTHENTICATION BYPASS TESTING")
        print("=" * 60)

        result = self.auth_bypass.run(
            target=login_url,
            output_file=str(self.output_dir / "auth_bypass.json"),
            username_field=username_field,
            password_field=password_field,
            **kwargs
        )

        self.results["auth_bypass"] = result.get("results", [])
        self.all_findings.extend(result.get("results", []))

        print(f"[+] Auth bypass tests completed: {result['summary']['findings_count']} findings")
        return result

    def run_idor_tests(self, api_url: str, param_name: str = None, **kwargs) -> Dict[str, Any]:
        """Run IDOR vulnerability tests"""
        print("\n" + "=" * 60)
        print("IDOR VULNERABILITY TESTING")
        print("=" * 60)

        result = self.idor_tester.run(
            target=api_url,
            output_file=str(self.output_dir / "idor.json"),
            param_name=param_name,
            **kwargs
        )

        self.results["idor"] = result.get("results", [])
        self.all_findings.extend(result.get("results", []))

        print(f"[+] IDOR tests completed: {result['summary']['findings_count']} findings")
        return result

    def run_jwt_tests(self, token: str, test_url: str = None, **kwargs) -> Dict[str, Any]:
        """Run JWT security tests"""
        print("\n" + "=" * 60)
        print("JWT SECURITY TESTING")
        print("=" * 60)

        result = self.jwt_attacks.run(
            target=token,
            output_file=str(self.output_dir / "jwt.json"),
            test_url=test_url,
            **kwargs
        )

        self.results["jwt"] = result.get("results", [])
        self.all_findings.extend(result.get("results", []))

        print(f"[+] JWT tests completed: {result['summary']['findings_count']} findings")
        return result

    def run_privilege_escalation_tests(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Run privilege escalation tests"""
        print("\n" + "=" * 60)
        print("PRIVILEGE ESCALATION TESTING")
        print("=" * 60)

        result = self.priv_esc.run(
            target=target_url,
            output_file=str(self.output_dir / "priv_esc.json"),
            **kwargs
        )

        self.results["privilege_escalation"] = result.get("results", [])
        self.all_findings.extend(result.get("results", []))

        print(f"[+] Privilege escalation tests completed: {result['summary']['findings_count']} findings")
        return result

    def run_brute_force(self, target: str, service: str, **kwargs) -> Dict[str, Any]:
        """Run password brute forcing (Hydra)"""
        print("\n" + "=" * 60)
        print("PASSWORD BRUTE FORCE TESTING")
        print("=" * 60)

        # Check if hydra is installed
        if not self.hydra.check_tool_installed():
            print("[-] Hydra not installed, skipping brute force tests")
            return {"success": False, "error": "Hydra not installed"}

        result = self.hydra.run(
            target=target,
            service=service,
            output_file=str(self.output_dir / "brute_force.txt"),
            **kwargs
        )

        self.results["brute_force"] = result.get("results", [])
        self.all_findings.extend(result.get("results", []))

        print(f"[+] Brute force tests completed")
        return result

    def run(self, login_url: str = None, api_url: str = None, jwt_token: str = None,
            jwt_test_url: str = None, test_types: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Run comprehensive auth testing workflow"""
        start_time = datetime.now()

        print("\n" + "=" * 60)
        print("AUTHENTICATION & AUTHORIZATION TESTING WORKFLOW")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Output: {self.output_dir}")
        print(f"Started: {start_time.isoformat()}")

        test_types = test_types or ["bypass", "idor", "jwt", "priv_esc"]

        # Auth bypass tests
        if "bypass" in test_types and login_url:
            self.run_auth_bypass_tests(
                login_url=login_url,
                username_field=kwargs.get("username_field", "username"),
                password_field=kwargs.get("password_field", "password"),
                headers=kwargs.get("headers", {}),
                cookies=kwargs.get("cookies", {})
            )

        # IDOR tests
        if "idor" in test_types and api_url:
            self.run_idor_tests(
                api_url=api_url,
                param_name=kwargs.get("param_name"),
                headers=kwargs.get("headers", {}),
                cookies=kwargs.get("cookies", {}),
                user1_token=kwargs.get("user1_token")
            )

        # JWT tests
        if "jwt" in test_types and jwt_token:
            self.run_jwt_tests(
                token=jwt_token,
                test_url=jwt_test_url,
                wordlist=kwargs.get("jwt_wordlist"),
                public_key=kwargs.get("public_key"),
                headers=kwargs.get("headers", {}),
                cookies=kwargs.get("cookies", {})
            )

        # Privilege escalation tests
        if "priv_esc" in test_types:
            self.run_privilege_escalation_tests(
                target_url=self.target,
                low_priv_token=kwargs.get("low_priv_token"),
                api_endpoint=kwargs.get("api_endpoint"),
                headers=kwargs.get("headers", {}),
                cookies=kwargs.get("cookies", {})
            )

        # Brute force (optional, requires hydra)
        if "brute_force" in test_types and kwargs.get("brute_force_target"):
            self.run_brute_force(
                target=kwargs.get("brute_force_target"),
                service=kwargs.get("brute_force_service", "ssh"),
                username_list=kwargs.get("username_list"),
                password_list=kwargs.get("password_list")
            )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Generate summary
        summary = self._generate_summary(duration)

        # Save combined results
        self._save_results(summary)

        # Generate report
        self._generate_report(summary)

        print("\n" + "=" * 60)
        print("WORKFLOW COMPLETE")
        print("=" * 60)
        print(f"Duration: {duration:.2f}s")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Critical: {summary['by_severity']['critical']}")
        print(f"High: {summary['by_severity']['high']}")
        print(f"Medium: {summary['by_severity']['medium']}")
        print(f"Low: {summary['by_severity']['low']}")
        print(f"\nResults saved to: {self.output_dir}")

        return {
            "success": True,
            "target": self.target,
            "duration": duration,
            "findings": self.all_findings,
            "summary": summary,
            "output_dir": str(self.output_dir)
        }

    def _generate_summary(self, duration: float) -> Dict[str, Any]:
        """Generate summary of all findings"""
        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        by_type = {
            "auth_bypass": 0,
            "idor": 0,
            "jwt": 0,
            "priv_esc": 0,
            "credentials": 0
        }

        for finding in self.all_findings:
            severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity).lower()
            if severity in by_severity:
                by_severity[severity] += 1

            finding_type = finding.finding_type
            if finding_type in by_type:
                by_type[finding_type] += 1

        return {
            "target": self.target,
            "duration": duration,
            "total_findings": len(self.all_findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "timestamp": datetime.now().isoformat()
        }

    def _save_results(self, summary: Dict[str, Any]):
        """Save combined results to JSON"""
        output = {
            "summary": summary,
            "findings": [f.to_dict() if hasattr(f, 'to_dict') else vars(f) for f in self.all_findings],
            "raw_results": self.results
        }

        output_file = self.output_dir / "combined_results.json"
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)

        print(f"[+] Combined results saved to: {output_file}")

    def _generate_report(self, summary: Dict[str, Any]):
        """Generate HTML report"""
        try:
            reporter = Reporter(str(self.output_dir))
            report_file = reporter.generate_html_report(
                findings=self.all_findings,
                target=self.target,
                title="Authentication & Authorization Security Report"
            )
            print(f"[+] HTML report generated: {report_file}")
        except Exception as e:
            print(f"[-] Could not generate HTML report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Authentication & Authorization Testing Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full auth testing
  python auth_testing.py -t https://example.com --login-url https://example.com/login

  # Test specific login form
  python auth_testing.py -t https://example.com --login-url https://example.com/login \\
    --username-field user --password-field pass

  # IDOR testing with API
  python auth_testing.py -t https://api.example.com --api-url "https://api.example.com/users/{id}" \\
    --param-name id --token "Bearer xxx"

  # JWT testing
  python auth_testing.py -t https://api.example.com --jwt-token "eyJhbG..." \\
    --jwt-test-url https://api.example.com/me

  # Specific tests only
  python auth_testing.py -t https://example.com --login-url /login --test-types bypass,priv_esc
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output directory")

    # Test URLs
    urls = parser.add_argument_group("Test URLs")
    urls.add_argument("--login-url", help="Login form URL for auth bypass tests")
    urls.add_argument("--api-url", help="API URL for IDOR tests (use {param} placeholder)")
    urls.add_argument("--jwt-test-url", help="URL to test JWT tokens against")

    # Credentials
    creds = parser.add_argument_group("Credentials")
    creds.add_argument("--username-field", default="username", help="Username field name")
    creds.add_argument("--password-field", default="password", help="Password field name")
    creds.add_argument("--jwt-token", help="JWT token to test")
    creds.add_argument("--token", dest="user1_token", help="Auth token for IDOR/priv esc tests")
    creds.add_argument("--low-priv-token", help="Low-privilege token for priv esc tests")

    # Test configuration
    config = parser.add_argument_group("Configuration")
    config.add_argument("--test-types", default="bypass,idor,jwt,priv_esc",
                        help="Test types: bypass,idor,jwt,priv_esc,brute_force")
    config.add_argument("--param-name", help="Parameter name for IDOR tests")
    config.add_argument("--api-endpoint", help="API endpoint for role manipulation tests")
    config.add_argument("--public-key", help="Public key file for JWT algorithm confusion")
    config.add_argument("--jwt-wordlist", help="Wordlist for JWT secret brute force")

    # Brute force
    brute = parser.add_argument_group("Brute Force")
    brute.add_argument("--brute-force-target", help="Target for brute force")
    brute.add_argument("--brute-force-service", default="ssh", help="Service for brute force")
    brute.add_argument("--username-list", help="Username wordlist")
    brute.add_argument("--password-list", help="Password wordlist")

    # Headers/cookies
    parser.add_argument("-H", "--header", action="append", dest="headers",
                        help="Custom header (format: 'Name: Value')")
    parser.add_argument("-c", "--cookie", help="Cookies")

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

    # Run workflow
    workflow = AuthTestingWorkflow(args.target, args.output)

    result = workflow.run(
        login_url=args.login_url,
        api_url=args.api_url,
        jwt_token=args.jwt_token,
        jwt_test_url=args.jwt_test_url,
        test_types=args.test_types.split(','),
        username_field=args.username_field,
        password_field=args.password_field,
        param_name=args.param_name,
        user1_token=args.user1_token,
        low_priv_token=args.low_priv_token,
        api_endpoint=args.api_endpoint,
        public_key=args.public_key,
        jwt_wordlist=args.jwt_wordlist,
        brute_force_target=args.brute_force_target,
        brute_force_service=args.brute_force_service,
        username_list=args.username_list,
        password_list=args.password_list,
        headers=headers,
        cookies=cookies
    )

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
