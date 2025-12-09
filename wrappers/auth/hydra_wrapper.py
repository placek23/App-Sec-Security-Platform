"""
Hydra Wrapper - Password brute forcing tool wrapper
"""
import sys
import argparse
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import AuthTool
from utils.output_parser import Finding, Severity


class HydraWrapper(AuthTool):
    """Wrapper for THC Hydra password brute forcing tool"""

    # Supported protocols
    SUPPORTED_PROTOCOLS = [
        "ftp", "ftps", "http-get", "http-post", "http-head",
        "http-get-form", "http-post-form", "https-get-form", "https-post-form",
        "http-proxy", "https-proxy", "icq", "imap", "imaps", "irc",
        "ldap2", "ldap3", "mssql", "mysql", "ncp", "nntp", "oracle",
        "oracle-listener", "oracle-sid", "pcanywhere", "pcnfs", "pop3",
        "pop3s", "postgres", "rdp", "rexec", "rlogin", "rsh", "sip",
        "smb", "smtp", "smtps", "smtp-enum", "snmp", "socks5", "ssh",
        "sshkey", "svn", "teamspeak", "telnet", "telnets", "vmauthd",
        "vnc", "xmpp"
    ]

    @property
    def tool_name(self) -> str:
        return "hydra"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build Hydra-specific arguments"""
        args = []

        # Single username or username list
        username = kwargs.get("username")
        username_list = kwargs.get("username_list")

        if username:
            args.extend(["-l", username])
        elif username_list:
            args.extend(["-L", username_list])

        # Single password or password list
        password = kwargs.get("password")
        password_list = kwargs.get("password_list")

        if password:
            args.extend(["-p", password])
        elif password_list:
            args.extend(["-P", password_list])

        # Combined user:pass file
        combo_list = kwargs.get("combo_list")
        if combo_list:
            args.extend(["-C", combo_list])

        # Threading
        threads = kwargs.get("threads", 16)
        args.extend(["-t", str(threads)])

        # Timeout per connection
        timeout = kwargs.get("wait_timeout", 30)
        args.extend(["-w", str(timeout)])

        # Exit on first found
        if kwargs.get("exit_on_first", True):
            args.append("-f")

        # Verbose mode
        if kwargs.get("verbose"):
            args.append("-V")

        # Service-specific options
        service = kwargs.get("service")
        port = kwargs.get("port")

        if port:
            args.extend(["-s", str(port)])

        # SSL
        if kwargs.get("ssl"):
            args.append("-S")

        # Output file
        output_file = kwargs.get("output_file")
        if output_file:
            args.extend(["-o", output_file])

        # Target specification
        args.append(target)

        # Service and additional options
        if service:
            if service in ["http-get-form", "http-post-form", "https-get-form", "https-post-form"]:
                # Form-based login
                form_path = kwargs.get("form_path", "/login")
                form_data = kwargs.get("form_data", "username=^USER^&password=^PASS^")
                fail_string = kwargs.get("fail_string", "incorrect")
                args.append(service)
                args.append(f"{form_path}:{form_data}:F={fail_string}")
            else:
                args.append(service)

        return args

    def parse_output(self, stdout: str, stderr: str) -> List[Finding]:
        """Parse Hydra output for found credentials"""
        findings = []

        # Pattern for successful login
        # [22][ssh] host: 192.168.1.1   login: admin   password: admin123
        success_pattern = re.compile(
            r'\[(\d+)\]\[(\w+(?:-\w+)?)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)',
            re.IGNORECASE
        )

        for match in success_pattern.finditer(stdout):
            port, service, host, username, password = match.groups()

            findings.append(Finding(
                tool="hydra",
                target=host,
                finding_type="credentials",
                title=f"Valid Credentials Found ({service})",
                description=f"Brute force attack found valid credentials for {service} on {host}:{port}",
                severity=Severity.CRITICAL,
                evidence=f"Username: {username}, Password: {password}",
                url=f"{service}://{host}:{port}",
                remediation="Change passwords immediately, implement account lockout, use MFA"
            ))

        return findings

    def run_http_form_attack(self, target: str, form_path: str, form_data: str,
                              fail_string: str, username_list: str = None,
                              password_list: str = None, **kwargs) -> Dict[str, Any]:
        """Convenience method for HTTP form brute forcing"""
        return self.run(
            target=target,
            service="http-post-form",
            form_path=form_path,
            form_data=form_data,
            fail_string=fail_string,
            username_list=username_list,
            password_list=password_list,
            **kwargs
        )

    def run_ssh_attack(self, target: str, username_list: str = None,
                       password_list: str = None, **kwargs) -> Dict[str, Any]:
        """Convenience method for SSH brute forcing"""
        return self.run(
            target=target,
            service="ssh",
            username_list=username_list,
            password_list=password_list,
            **kwargs
        )

    def run_ftp_attack(self, target: str, username_list: str = None,
                       password_list: str = None, **kwargs) -> Dict[str, Any]:
        """Convenience method for FTP brute forcing"""
        return self.run(
            target=target,
            service="ftp",
            username_list=username_list,
            password_list=password_list,
            **kwargs
        )


def main():
    parser = argparse.ArgumentParser(
        description="Hydra Wrapper - Password Brute Forcing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SSH brute force
  python hydra_wrapper.py -t 192.168.1.1 -s ssh -l admin -P passwords.txt

  # FTP brute force
  python hydra_wrapper.py -t 192.168.1.1 -s ftp -L users.txt -P passwords.txt

  # HTTP form brute force
  python hydra_wrapper.py -t example.com -s http-post-form \\
    --form-path "/login" \\
    --form-data "username=^USER^&password=^PASS^" \\
    --fail-string "Invalid" \\
    -L users.txt -P passwords.txt

  # MySQL brute force
  python hydra_wrapper.py -t 192.168.1.1 -s mysql -l root -P passwords.txt

Supported services:
  ftp, ftps, http-get, http-post, http-get-form, http-post-form,
  https-get-form, https-post-form, imap, imaps, ldap, mssql, mysql,
  oracle, pop3, pop3s, postgres, rdp, smb, smtp, ssh, telnet, vnc
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target host/IP")
    parser.add_argument("-s", "--service", required=True, choices=HydraWrapper.SUPPORTED_PROTOCOLS,
                        help="Service to attack")
    parser.add_argument("-p", "--port", type=int, help="Target port (default: service default)")

    # Credentials
    creds = parser.add_argument_group("Credentials")
    creds.add_argument("-l", "--username", help="Single username to test")
    creds.add_argument("-L", "--username-list", help="File containing usernames")
    creds.add_argument("-pw", "--password", help="Single password to test")
    creds.add_argument("-P", "--password-list", help="File containing passwords")
    creds.add_argument("-C", "--combo-list", help="File with user:pass combinations")

    # HTTP Form options
    form = parser.add_argument_group("HTTP Form Options")
    form.add_argument("--form-path", default="/login", help="Form submission path")
    form.add_argument("--form-data", default="username=^USER^&password=^PASS^",
                      help="Form data (use ^USER^ and ^PASS^ as placeholders)")
    form.add_argument("--fail-string", default="incorrect",
                      help="String indicating failed login")

    # Performance
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--threads", type=int, default=16, help="Number of parallel threads")
    perf.add_argument("--wait-timeout", type=int, default=30, help="Connection timeout")
    perf.add_argument("--no-exit-first", action="store_true",
                      help="Continue after first valid credential found")

    # Other options
    parser.add_argument("--ssl", action="store_true", help="Use SSL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    # Validate credentials provided
    if not any([args.username, args.username_list, args.combo_list]):
        parser.error("Must provide -l, -L, or -C for credentials")
    if not any([args.password, args.password_list, args.combo_list]):
        parser.error("Must provide -pw, -P, or -C for credentials")

    wrapper = HydraWrapper()

    result = wrapper.run(
        target=args.target,
        service=args.service,
        port=args.port,
        username=args.username,
        username_list=args.username_list,
        password=args.password,
        password_list=args.password_list,
        combo_list=args.combo_list,
        threads=args.threads,
        wait_timeout=args.wait_timeout,
        exit_on_first=not args.no_exit_first,
        ssl=args.ssl,
        verbose=args.verbose,
        output_file=args.output,
        form_path=args.form_path,
        form_data=args.form_data,
        fail_string=args.fail_string
    )

    # Print summary
    print(f"\n{'='*60}")
    print("HYDRA BRUTE FORCE RESULTS")
    print(f"{'='*60}")
    print(f"Target: {args.target}")
    print(f"Service: {args.service}")
    print(f"Duration: {result.get('duration', 0):.2f}s")

    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] CREDENTIALS FOUND!")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  {finding.evidence}")
                print(f"  Remediation: {finding.remediation}")
        else:
            print("\n[+] No valid credentials found")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
