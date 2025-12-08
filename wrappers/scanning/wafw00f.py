"""
Wafw00f - Web Application Firewall detection
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ScanningTool
from utils.output_parser import OutputParser


class Wafw00fWrapper(ScanningTool):
    """Wrapper for wafw00f WAF detection tool"""
    
    @property
    def tool_name(self) -> str:
        return "wafw00f"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build wafw00f-specific arguments"""
        args = []
        
        # Input
        if kwargs.get("list"):
            args.extend(["-i", kwargs["list"]])
        else:
            args.append(target)
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Output format
        if kwargs.get("output_format"):
            args.extend(["-f", kwargs["output_format"]])
        
        # Test all WAFs
        if kwargs.get("all_wafs", True):
            args.append("-a")
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # Proxy
        if kwargs.get("proxy"):
            args.extend(["-p", kwargs["proxy"]])
        
        # List all WAFs
        if kwargs.get("list_wafs"):
            args.append("-l")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> dict:
        """Parse wafw00f output"""
        return OutputParser.parse_wafw00f(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="Wafw00f - WAF detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wafw00f.py -u https://example.com
  python wafw00f.py -i urls.txt -o waf_results.json
  python wafw00f.py -u https://example.com -a -v
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-i", "--input", dest="list", help="File containing URLs")
    group.add_argument("-l", "--list-wafs", action="store_true", help="List all detectable WAFs")
    
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", dest="output_format", choices=["json", "csv", "txt"], help="Output format")
    parser.add_argument("-a", "--all", dest="all_wafs", action="store_true", default=True, help="Test all WAF signatures")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    
    args = parser.parse_args()
    
    wrapper = Wafw00fWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        output_file=args.output,
        list=args.list,
        output_format=args.output_format,
        all_wafs=args.all_wafs,
        verbose=args.verbose,
        headers=args.headers,
        proxy=args.proxy,
        list_wafs=args.list_wafs
    )
    
    if result["success"]:
        waf_info = result["results"]
        
        if waf_info.get("waf_detected"):
            print(f"\n[!] WAF DETECTED: {waf_info.get('waf_name', 'Unknown')}")
            if waf_info.get("waf_vendor"):
                print(f"    Vendor: {waf_info.get('waf_vendor')}")
            print("\n[!] Consider:")
            print("    - Using WAF bypass techniques")
            print("    - Rate limiting your scans")
            print("    - Using evasion payloads")
        else:
            print("\n[+] No WAF detected")
            print("[+] Target may be unprotected or using custom WAF rules")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
