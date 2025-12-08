"""
Dalfox - Advanced XSS scanner with DOM analysis
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool
from utils.output_parser import OutputParser


class DalfoxWrapper(InjectionTool):
    """Wrapper for dalfox XSS scanning tool"""
    
    @property
    def tool_name(self) -> str:
        return "dalfox"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build dalfox-specific arguments"""
        # Mode selection
        mode = kwargs.get("mode", "url")
        args = [mode]
        
        # Target
        if mode == "url":
            args.append(target)
        elif mode == "file":
            args.append(kwargs.get("file", target))
        elif mode == "pipe":
            pass  # Reads from stdin
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Output format
        if kwargs.get("format"):
            args.extend(["--format", kwargs["format"]])
        
        # JSON output
        if kwargs.get("json"):
            args.append("--json-output")
        
        # Parameters
        if kwargs.get("param"):
            args.extend(["-p", kwargs["param"]])
        
        # Data
        if kwargs.get("data"):
            args.extend(["-d", kwargs["data"]])
        
        # Method
        if kwargs.get("method"):
            args.extend(["--method", kwargs["method"]])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # Cookies
        if kwargs.get("cookies"):
            args.extend(["-C", kwargs["cookies"]])
        
        # User agent
        if kwargs.get("user_agent"):
            args.extend(["--user-agent", kwargs["user_agent"]])
        
        # Proxy
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])
        
        # Blind XSS callback
        if kwargs.get("blind"):
            args.extend(["--blind", kwargs["blind"]])
        
        # Custom payload
        if kwargs.get("custom_payload"):
            args.extend(["--custom-payload", kwargs["custom_payload"]])
        
        # Custom alert value
        if kwargs.get("custom_alert"):
            args.extend(["--custom-alert-value", kwargs["custom_alert"]])
        
        # Mining (DOM, dict, etc.)
        if kwargs.get("mining_dom"):
            args.append("--mining-dom")
        if kwargs.get("mining_dict"):
            args.append("--mining-dict")
        if kwargs.get("mining_all"):
            args.append("-a")
        
        # WAF evasion
        if kwargs.get("waf_evasion"):
            args.append("--waf-evasion")
        
        # Workers
        if kwargs.get("workers"):
            args.extend(["-w", str(kwargs["workers"])])
        
        # Delay
        if kwargs.get("delay"):
            args.extend(["--delay", str(kwargs["delay"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("--follow-redirects")
        
        # Ignore return codes
        if kwargs.get("ignore_return"):
            args.extend(["--ignore-return", kwargs["ignore_return"]])
        
        # Skip mining
        if kwargs.get("skip_mining"):
            args.append("--skip-mining")
        
        # Skip BAV (Basic Another Vulnerability check)
        if kwargs.get("skip_bav"):
            args.append("--skip-bav")
        
        # Only discovery (no exploitation)
        if kwargs.get("only_discovery"):
            args.append("--only-discovery")
        
        # Silence
        if kwargs.get("silence"):
            args.append("--silence")
        
        # No color
        args.append("--no-color")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse dalfox output"""
        return OutputParser.parse_dalfox(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="Dalfox - XSS scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dalfox.py -u "https://example.com/search?q=test"
  python dalfox.py -u "https://example.com/page?id=1" -p id --blind https://your.xss.ht
  python dalfox.py -f urls.txt -o xss_results.json --json
  python dalfox.py -u "https://example.com/page" --mining-dom -a
        """
    )
    
    # Mode and target
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-u", "--url", help="Target URL")
    mode_group.add_argument("-f", "--file", help="File containing URLs")
    
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=["plain", "json"], help="Output format")
    parser.add_argument("--json", action="store_true", help="JSON output")
    
    # Request options
    parser.add_argument("-p", "--param", help="Specific parameter to test")
    parser.add_argument("-d", "--data", help="POST data")
    parser.add_argument("--method", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("-C", "--cookie", dest="cookies", help="Cookies")
    parser.add_argument("--user-agent", help="User agent")
    parser.add_argument("--proxy", help="Proxy URL")
    
    # XSS options
    parser.add_argument("--blind", help="Blind XSS callback URL")
    parser.add_argument("--custom-payload", help="Custom XSS payload file")
    parser.add_argument("--custom-alert", help="Custom alert value")
    
    # Mining options
    parser.add_argument("--mining-dom", action="store_true", help="DOM mining")
    parser.add_argument("--mining-dict", action="store_true", help="Dictionary mining")
    parser.add_argument("-a", "--mining-all", action="store_true", help="Enable all mining")
    
    # Performance
    parser.add_argument("-w", "--workers", type=int, default=50, help="Number of workers")
    parser.add_argument("--delay", type=int, help="Delay between requests (ms)")
    parser.add_argument("--timeout", type=int, help="Request timeout")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    
    # Evasion
    parser.add_argument("--waf-evasion", action="store_true", help="Enable WAF evasion")
    parser.add_argument("--ignore-return", help="Ignore specific return codes")
    
    # Skip options
    parser.add_argument("--skip-mining", action="store_true", help="Skip parameter mining")
    parser.add_argument("--skip-bav", action="store_true", help="Skip basic vuln check")
    parser.add_argument("--only-discovery", action="store_true", help="Only discover, no exploit")
    
    parser.add_argument("--silence", action="store_true", help="Silent mode")
    
    args = parser.parse_args()
    
    wrapper = DalfoxWrapper()
    
    # Determine mode
    mode = "url" if args.url else "file"
    
    result = wrapper.run(
        target=args.url or args.file,
        mode=mode,
        file=args.file,
        output_file=args.output,
        format=args.format,
        json=args.json,
        param=args.param,
        data=args.data,
        method=args.method,
        headers=args.headers,
        cookies=args.cookies,
        user_agent=args.user_agent,
        proxy=args.proxy,
        blind=args.blind,
        custom_payload=args.custom_payload,
        custom_alert=args.custom_alert,
        mining_dom=args.mining_dom,
        mining_dict=args.mining_dict,
        mining_all=args.mining_all,
        waf_evasion=args.waf_evasion,
        workers=args.workers,
        delay=args.delay,
        timeout=args.timeout,
        follow_redirects=args.follow_redirects,
        ignore_return=args.ignore_return,
        skip_mining=args.skip_mining,
        skip_bav=args.skip_bav,
        only_discovery=args.only_discovery,
        silence=args.silence
    )
    
    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] XSS VULNERABILITIES FOUND: {len(findings)}")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  URL: {finding.url}")
                if finding.parameter:
                    print(f"  Parameter: {finding.parameter}")
                if finding.payload:
                    print(f"  Payload: {finding.payload[:100]}")
        else:
            print("\n[+] No XSS vulnerabilities detected")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
