"""
Commix - Command injection exploitation tool
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool
from utils.output_parser import Finding, Severity


class CommixWrapper(InjectionTool):
    """Wrapper for commix command injection tool"""
    
    @property
    def tool_name(self) -> str:
        return "commix"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build commix-specific arguments"""
        args = []
        
        # Target
        if kwargs.get("request_file"):
            args.extend(["-r", kwargs["request_file"]])
        else:
            args.extend(["-u", target])
        
        # Data
        if kwargs.get("data"):
            args.extend(["--data", kwargs["data"]])
        
        # Cookie
        if kwargs.get("cookies"):
            args.extend(["--cookie", kwargs["cookies"]])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["--header", header])
        
        # User agent
        if kwargs.get("user_agent"):
            args.extend(["--user-agent", kwargs["user_agent"]])
        if kwargs.get("random_agent"):
            args.append("--random-agent")
        
        # Proxy
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])
        
        # Level
        if kwargs.get("level"):
            args.extend(["--level", str(kwargs["level"])])
        
        # Parameter to test
        if kwargs.get("param"):
            args.extend(["-p", kwargs["param"]])
        
        # Technique
        if kwargs.get("technique"):
            args.extend(["--technique", kwargs["technique"]])
        
        # OS
        if kwargs.get("os"):
            args.extend(["--os", kwargs["os"]])
        
        # Tamper
        if kwargs.get("tamper"):
            args.extend(["--tamper", kwargs["tamper"]])
        
        # Shell type
        if kwargs.get("shell"):
            args.extend(["--os-cmd", kwargs["shell"]])
        
        # Specific OS command
        if kwargs.get("os_cmd"):
            args.extend(["--os-cmd", kwargs["os_cmd"]])
        
        # Interactive shell
        if kwargs.get("os_shell"):
            args.append("--os-shell")
        
        # File read
        if kwargs.get("file_read"):
            args.extend(["--file-read", kwargs["file_read"]])
        
        # File write
        if kwargs.get("file_write"):
            args.extend(["--file-write", kwargs["file_write"]])
        if kwargs.get("file_dest"):
            args.extend(["--file-dest", kwargs["file_dest"]])
        
        # Output directory
        if kwargs.get("output_dir"):
            args.extend(["--output-dir", kwargs["output_dir"]])
        
        # Batch mode
        if kwargs.get("batch", True):
            args.append("--batch")
        
        # Skip tests
        if kwargs.get("skip"):
            args.extend(["--skip", kwargs["skip"]])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])
        
        # Retries
        if kwargs.get("retries"):
            args.extend(["--retries", str(kwargs["retries"])])
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse commix output"""
        results = []
        
        # Look for vulnerability indicators
        if "is vulnerable" in stdout.lower() or "command injection" in stdout.lower():
            results.append(Finding(
                tool="commix",
                target="",
                finding_type="command_injection",
                title="Command Injection Vulnerability",
                description="The target appears to be vulnerable to command injection",
                severity=Severity.CRITICAL,
                evidence=stdout[:500]
            ))
        
        # Look for successful exploitation
        if "os shell" in stdout.lower() or "pseudo-terminal" in stdout.lower():
            results.append(Finding(
                tool="commix",
                target="",
                finding_type="rce",
                title="Remote Code Execution Achieved",
                description="Successfully achieved command execution on target",
                severity=Severity.CRITICAL,
                evidence=stdout[:500]
            ))
        
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Commix - Command injection testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python commix.py -u "https://example.com/ping?ip=127.0.0.1"
  python commix.py -u "https://example.com/exec" --data "cmd=ls" --batch
  python commix.py -r request.txt --level 2 --os-shell
  python commix.py -u "https://example.com/api" --os-cmd "id"
        """
    )
    
    # Target
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Target URL")
    target_group.add_argument("-r", "--request-file", help="HTTP request file")
    
    # Request options
    parser.add_argument("--data", help="POST data")
    parser.add_argument("--cookie", dest="cookies", help="Cookies")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Headers")
    parser.add_argument("--user-agent", help="User agent")
    parser.add_argument("--random-agent", action="store_true", help="Random user agent")
    parser.add_argument("--proxy", help="Proxy URL")
    
    # Detection options
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=1, help="Test level")
    parser.add_argument("-p", "--param", help="Parameter to test")
    parser.add_argument("--technique", help="Injection technique (classic, eval-based, time-based, file-based)")
    parser.add_argument("--os", choices=["unix", "windows"], help="Target OS")
    parser.add_argument("--tamper", help="Tamper script")
    
    # Exploitation options
    parser.add_argument("--os-cmd", help="Execute single OS command")
    parser.add_argument("--os-shell", action="store_true", help="Interactive OS shell")
    parser.add_argument("--file-read", help="Read file from server")
    parser.add_argument("--file-write", help="File to write to server")
    parser.add_argument("--file-dest", help="Server path for file write")
    
    # General options
    parser.add_argument("-o", "--output-dir", help="Output directory")
    parser.add_argument("--batch", action="store_true", default=True, help="Non-interactive mode")
    parser.add_argument("--skip", help="Skip specific tests")
    parser.add_argument("--timeout", type=int, help="Connection timeout")
    parser.add_argument("--retries", type=int, help="Retries on failure")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    wrapper = CommixWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        request_file=args.request_file,
        data=args.data,
        cookies=args.cookies,
        headers=args.headers,
        user_agent=args.user_agent,
        random_agent=args.random_agent,
        proxy=args.proxy,
        level=args.level,
        param=args.param,
        technique=args.technique,
        os=args.os,
        tamper=args.tamper,
        os_cmd=args.os_cmd,
        os_shell=args.os_shell,
        file_read=args.file_read,
        file_write=args.file_write,
        file_dest=args.file_dest,
        output_dir=args.output_dir,
        batch=args.batch,
        skip=args.skip,
        timeout=args.timeout,
        retries=args.retries,
        verbose=args.verbose
    )
    
    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] COMMAND INJECTION FOUND!")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  {finding.description}")
        else:
            print("\n[+] No command injection vulnerabilities detected")
            print("[*] Consider increasing --level for deeper testing")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
