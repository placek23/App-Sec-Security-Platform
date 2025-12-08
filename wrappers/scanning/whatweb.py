"""
WhatWeb - Web technology fingerprinting
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ScanningTool


class WhatwebWrapper(ScanningTool):
    """Wrapper for whatweb fingerprinting tool"""
    
    @property
    def tool_name(self) -> str:
        return "whatweb"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build whatweb-specific arguments"""
        args = []
        
        # Input
        if kwargs.get("list"):
            args.extend(["-i", kwargs["list"]])
        else:
            args.append(target)
        
        # Aggression level (1-4)
        if kwargs.get("aggression"):
            args.extend(["-a", str(kwargs["aggression"])])
        
        # Output
        if kwargs.get("output"):
            args.extend(["--log-json", kwargs["output"]])
        
        # Verbose
        if kwargs.get("verbose"):
            args.extend(["-v"])
        
        # User agent
        if kwargs.get("user_agent"):
            args.extend(["-U", kwargs["user_agent"]])
        
        # Cookies
        if kwargs.get("cookies"):
            args.extend(["-c", kwargs["cookies"]])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # Proxy
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])
        
        # Max threads
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("-r")
        
        # Max redirects
        if kwargs.get("max_redirects"):
            args.extend(["--max-redirects", str(kwargs["max_redirects"])])
        
        # No color
        args.append("--color=never")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse whatweb output"""
        results = []
        for line in stdout.strip().split('\n'):
            if not line or line.startswith('ERROR'):
                continue
            
            # Extract URL and technologies
            parts = line.split(' [')
            if parts:
                url = parts[0].strip()
                technologies = []
                
                for part in parts[1:]:
                    tech = part.rstrip(']').strip()
                    if tech:
                        technologies.append(tech)
                
                results.append({
                    'url': url,
                    'technologies': technologies,
                    'source': 'whatweb'
                })
        
        return results


def main():
    parser = argparse.ArgumentParser(
        description="WhatWeb - Web technology fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python whatweb.py -u https://example.com
  python whatweb.py -u https://example.com -a 3 -o tech.json
  python whatweb.py -i urls.txt -t 10 -v
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-i", "--input", dest="list", help="File containing URLs")
    
    parser.add_argument("-o", "--output", help="Output file path (JSON)")
    parser.add_argument("-a", "--aggression", type=int, choices=[1, 2, 3, 4], default=1, 
                       help="Aggression level (1=stealthy, 4=heavy)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-U", "--user-agent", help="Custom user agent")
    parser.add_argument("-c", "--cookies", help="Cookies")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-r", "--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--max-redirects", type=int, help="Max redirects to follow")
    
    args = parser.parse_args()
    
    wrapper = WhatwebWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        output_file=args.output,
        list=args.list,
        aggression=args.aggression,
        verbose=args.verbose,
        user_agent=args.user_agent,
        cookies=args.cookies,
        headers=args.headers,
        proxy=args.proxy,
        threads=args.threads,
        follow_redirects=args.follow_redirects,
        max_redirects=args.max_redirects
    )
    
    if result["success"]:
        print(f"\n[+] Fingerprinted {len(result['results'])} targets")
        for item in result["results"]:
            print(f"\n  URL: {item.get('url', '')}")
            techs = item.get('technologies', [])
            if techs:
                print(f"  Technologies: {', '.join(techs[:10])}")
                if len(techs) > 10:
                    print(f"  ... and {len(techs) - 10} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
