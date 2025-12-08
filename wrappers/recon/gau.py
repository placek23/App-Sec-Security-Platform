"""
GAU - Get All URLs from Wayback Machine, Common Crawl, etc.
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ReconTool
from utils.output_parser import OutputParser


class GauWrapper(ReconTool):
    """Wrapper for gau URL harvesting tool"""
    
    @property
    def tool_name(self) -> str:
        return "gau"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build gau-specific arguments"""
        args = []
        
        # Add target at the end (gau takes domain as positional arg)
        
        # Output
        if kwargs.get("output"):
            args.extend(["--o", kwargs["output"]])
        
        # Providers
        if kwargs.get("providers"):
            args.extend(["--providers", kwargs["providers"]])
        
        # Blacklist extensions
        if kwargs.get("blacklist"):
            args.extend(["--blacklist", kwargs["blacklist"]])
        
        # Fetch subdomains
        if kwargs.get("subs"):
            args.append("--subs")
        
        # Threads
        if kwargs.get("threads"):
            args.extend(["--threads", str(kwargs["threads"])])
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("--verbose")
        
        # Retries
        if kwargs.get("retries"):
            args.extend(["--retries", str(kwargs["retries"])])
        
        # JSON output
        if kwargs.get("json"):
            args.append("--json")
        
        # From date
        if kwargs.get("from_date"):
            args.extend(["--from", kwargs["from_date"]])
        
        # To date
        if kwargs.get("to_date"):
            args.extend(["--to", kwargs["to_date"]])
        
        # Add target domain at the end
        args.append(target)
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse gau output"""
        return OutputParser.parse_gau(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="GAU - Get All URLs from web archives",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gau.py example.com
  python gau.py example.com --subs -o urls.txt
  python gau.py example.com --providers wayback,commoncrawl
  python gau.py example.com --blacklist png,jpg,gif --from 202301
        """
    )
    
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--providers", help="Providers (wayback,commoncrawl,otx,urlscan)")
    parser.add_argument("--blacklist", help="Extensions to blacklist (e.g., png,jpg,gif)")
    parser.add_argument("--subs", action="store_true", help="Include subdomains")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--retries", type=int, help="Number of retries")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--from", dest="from_date", help="From date (YYYYMM)")
    parser.add_argument("--to", dest="to_date", help="To date (YYYYMM)")
    
    args = parser.parse_args()
    
    wrapper = GauWrapper()
    
    result = wrapper.run(
        target=args.domain,
        output_file=args.output,
        providers=args.providers,
        blacklist=args.blacklist,
        subs=args.subs,
        threads=args.threads,
        verbose=args.verbose,
        retries=args.retries,
        json=args.json,
        from_date=args.from_date,
        to_date=args.to_date
    )
    
    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} URLs")
        
        # Show URLs with parameters
        urls_with_params = [ep for ep in result["results"] if ep.parameters]
        print(f"[+] URLs with parameters: {len(urls_with_params)}")
        
        for ep in result["results"][:10]:
            params = f" [{', '.join(ep.parameters)}]" if ep.parameters else ""
            print(f"  {ep.url[:80]}{params}")
        if len(result["results"]) > 10:
            print(f"  ... and {len(result['results']) - 10} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
