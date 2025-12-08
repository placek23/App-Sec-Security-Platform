"""
Feroxbuster - Recursive content discovery tool
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool


class FeroxbusterWrapper(DiscoveryTool):
    """Wrapper for feroxbuster content discovery tool"""
    
    @property
    def tool_name(self) -> str:
        return "feroxbuster"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build feroxbuster-specific arguments"""
        args = ["-u", target]
        
        # Wordlist
        if kwargs.get("wordlist"):
            args.extend(["-w", kwargs["wordlist"]])
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Output format
        if kwargs.get("output_format"):
            args.extend(["--output", kwargs["output_format"]])
        
        # Threads
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        
        # Depth
        if kwargs.get("depth"):
            args.extend(["-d", str(kwargs["depth"])])
        
        # Extensions
        if kwargs.get("extensions"):
            args.extend(["-x", kwargs["extensions"]])
        
        # Status codes
        if kwargs.get("status_codes"):
            args.extend(["-s", kwargs["status_codes"]])
        
        # Filter status codes
        if kwargs.get("filter_status"):
            for code in kwargs["filter_status"].split(","):
                args.extend(["-C", code.strip()])
        
        # Filter size
        if kwargs.get("filter_size"):
            for size in kwargs["filter_size"].split(","):
                args.extend(["-S", size.strip()])
        
        # Filter words
        if kwargs.get("filter_words"):
            for words in kwargs["filter_words"].split(","):
                args.extend(["-W", words.strip()])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # Cookies
        if kwargs.get("cookies"):
            args.extend(["-b", kwargs["cookies"]])
        
        # User agent
        if kwargs.get("user_agent"):
            args.extend(["-a", kwargs["user_agent"]])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])
        
        # Auto-tune
        if kwargs.get("auto_tune", True):
            args.append("--auto-tune")
        
        # No recursion
        if kwargs.get("no_recursion"):
            args.append("-n")
        
        # Force recursion
        if kwargs.get("force_recursion"):
            args.append("-f")
        
        # Insecure (ignore SSL)
        if kwargs.get("insecure"):
            args.append("-k")
        
        # Follow redirects
        if kwargs.get("redirects"):
            args.append("-r")
        
        # Quiet mode
        if kwargs.get("quiet"):
            args.append("-q")
        
        # Silent mode
        if kwargs.get("silent"):
            args.append("--silent")
        
        # Rate limit
        if kwargs.get("rate_limit"):
            args.extend(["-L", str(kwargs["rate_limit"])])
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse feroxbuster output"""
        results = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('[') or line.startswith('─'):
                continue
            # Parse status code and URL
            parts = line.split()
            if len(parts) >= 2:
                try:
                    status = int(parts[0])
                    url = parts[-1]
                    results.append({
                        'url': url,
                        'status_code': status,
                        'source': 'feroxbuster'
                    })
                except ValueError:
                    continue
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Feroxbuster - Recursive content discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python feroxbuster.py -u https://example.com -w wordlist.txt
  python feroxbuster.py -u https://example.com -w dirs.txt -x php,html -d 3
  python feroxbuster.py -u https://example.com -w dirs.txt -C 404,403 -o results.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Wordlist path")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Recursion depth")
    parser.add_argument("-x", "--extensions", help="Extensions (e.g., php,html,js)")
    parser.add_argument("-s", "--status-codes", help="Status codes to match")
    parser.add_argument("-C", "--filter-status", help="Status codes to filter")
    parser.add_argument("-S", "--filter-size", help="Response sizes to filter")
    parser.add_argument("-W", "--filter-words", help="Word counts to filter")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Headers")
    parser.add_argument("-b", "--cookies", help="Cookies")
    parser.add_argument("-a", "--user-agent", help="User agent")
    parser.add_argument("--timeout", type=int, help="Request timeout")
    parser.add_argument("--auto-tune", action="store_true", default=True, help="Auto-tune settings")
    parser.add_argument("-n", "--no-recursion", action="store_true", help="Disable recursion")
    parser.add_argument("-f", "--force-recursion", action="store_true", help="Force recursion")
    parser.add_argument("-k", "--insecure", action="store_true", help="Ignore SSL errors")
    parser.add_argument("-r", "--redirects", action="store_true", help="Follow redirects")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--silent", action="store_true", help="Silent mode")
    parser.add_argument("-L", "--rate-limit", type=int, help="Rate limit per second")
    
    args = parser.parse_args()
    
    wrapper = FeroxbusterWrapper()
    
    result = wrapper.run(
        target=args.url,
        output_file=args.output,
        wordlist=args.wordlist,
        threads=args.threads,
        depth=args.depth,
        extensions=args.extensions,
        status_codes=args.status_codes,
        filter_status=args.filter_status,
        filter_size=args.filter_size,
        filter_words=args.filter_words,
        headers=args.headers,
        cookies=args.cookies,
        user_agent=args.user_agent,
        timeout=args.timeout,
        auto_tune=args.auto_tune,
        no_recursion=args.no_recursion,
        force_recursion=args.force_recursion,
        insecure=args.insecure,
        redirects=args.redirects,
        quiet=args.quiet,
        silent=args.silent,
        rate_limit=args.rate_limit
    )
    
    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} endpoints")
        for ep in result["results"][:15]:
            print(f"  [{ep.get('status_code', '?')}] {ep.get('url', '')}")
        if len(result["results"]) > 15:
            print(f"  ... and {len(result['results']) - 15} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
