"""
Tplmap - Server-Side Template Injection scanner
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool
from utils.output_parser import Finding, Severity


class TplmapWrapper(InjectionTool):
    """Wrapper for tplmap SSTI scanning tool"""
    
    @property
    def tool_name(self) -> str:
        return "tplmap"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build tplmap-specific arguments"""
        args = ["-u", target]
        
        # Data
        if kwargs.get("data"):
            args.extend(["-d", kwargs["data"]])
        
        # Cookie
        if kwargs.get("cookies"):
            args.extend(["-c", kwargs["cookies"]])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # User agent
        if kwargs.get("user_agent"):
            args.extend(["-A", kwargs["user_agent"]])
        
        # Proxy
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])
        
        # Level
        if kwargs.get("level"):
            args.extend(["--level", str(kwargs["level"])])
        
        # Engine (template engine to test)
        if kwargs.get("engine"):
            args.extend(["-e", kwargs["engine"]])
        
        # OS shell
        if kwargs.get("os_shell"):
            args.append("--os-shell")
        
        # OS command
        if kwargs.get("os_cmd"):
            args.extend(["--os-cmd", kwargs["os_cmd"]])
        
        # Reverse shell
        if kwargs.get("reverse_shell"):
            args.extend(["--reverse-shell", kwargs["reverse_shell"]])
        
        # Bind shell
        if kwargs.get("bind_shell"):
            args.extend(["--bind-shell", kwargs["bind_shell"]])
        
        # File read
        if kwargs.get("file_read"):
            args.extend(["--upload", kwargs["file_read"]])
        
        # File download
        if kwargs.get("file_download"):
            args.extend(["--download", kwargs["file_download"]])
        
        # Tpl code execution
        if kwargs.get("tpl_code"):
            args.extend(["--tpl-code", kwargs["tpl_code"]])
        
        # Force engine
        if kwargs.get("force"):
            args.append("--force")
        
        # Technique
        if kwargs.get("technique"):
            args.extend(["-t", kwargs["technique"]])
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse tplmap output"""
        results = []
        output = stdout + stderr
        
        # Check for confirmed SSTI
        if "confirmed" in output.lower() or "injection point found" in output.lower():
            # Try to extract engine name
            engine = "Unknown"
            engines = ["jinja2", "mako", "twig", "smarty", "freemarker", "velocity", 
                      "jade", "pug", "nunjucks", "erb", "slim", "haml", "dust"]
            for eng in engines:
                if eng in output.lower():
                    engine = eng.title()
                    break
            
            results.append(Finding(
                tool="tplmap",
                target="",
                finding_type="ssti",
                title=f"Server-Side Template Injection ({engine})",
                description=f"The target is vulnerable to SSTI via {engine} template engine",
                severity=Severity.CRITICAL,
                evidence=output[:500]
            ))
        
        # Check for RCE
        if "os shell" in output.lower() or "command execution" in output.lower():
            results.append(Finding(
                tool="tplmap",
                target="",
                finding_type="rce",
                title="Remote Code Execution via SSTI",
                description="Successfully achieved RCE through template injection",
                severity=Severity.CRITICAL,
                evidence=output[:500]
            ))
        
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Tplmap - SSTI detection and exploitation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tplmap.py -u "https://example.com/page?name=test"
  python tplmap.py -u "https://example.com/api" -d "template={{7*7}}"
  python tplmap.py -u "https://example.com/page?id=1" -e jinja2 --os-shell
  python tplmap.py -u "https://example.com/render" --os-cmd "id"
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL with injection point")
    
    # Request options
    parser.add_argument("-d", "--data", help="POST data")
    parser.add_argument("-c", "--cookie", dest="cookies", help="Cookies")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Headers")
    parser.add_argument("-A", "--user-agent", help="User agent")
    parser.add_argument("--proxy", help="Proxy URL")
    
    # Detection options
    parser.add_argument("--level", type=int, choices=[1, 2, 3, 4, 5], default=1, help="Test level")
    parser.add_argument("-e", "--engine", help="Template engine to test")
    parser.add_argument("-t", "--technique", help="Technique to use (render, blind)")
    parser.add_argument("--force", action="store_true", help="Force detection without confirmation")
    
    # Exploitation options
    parser.add_argument("--os-shell", action="store_true", help="Interactive OS shell")
    parser.add_argument("--os-cmd", help="Execute single OS command")
    parser.add_argument("--reverse-shell", help="Reverse shell (host:port)")
    parser.add_argument("--bind-shell", help="Bind shell port")
    parser.add_argument("--tpl-code", help="Execute template code")
    parser.add_argument("--upload", dest="file_read", help="Upload file")
    parser.add_argument("--download", dest="file_download", help="Download file")
    
    args = parser.parse_args()
    
    wrapper = TplmapWrapper()
    
    result = wrapper.run(
        target=args.url,
        data=args.data,
        cookies=args.cookies,
        headers=args.headers,
        user_agent=args.user_agent,
        proxy=args.proxy,
        level=args.level,
        engine=args.engine,
        technique=args.technique,
        force=args.force,
        os_shell=args.os_shell,
        os_cmd=args.os_cmd,
        reverse_shell=args.reverse_shell,
        bind_shell=args.bind_shell,
        file_read=args.file_read,
        file_download=args.file_download,
        tpl_code=args.tpl_code
    )
    
    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] SSTI VULNERABILITY FOUND!")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  {finding.description}")
        else:
            print("\n[+] No SSTI vulnerabilities detected")
            print("[*] Consider increasing --level for deeper testing")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
