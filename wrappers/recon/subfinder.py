"""
Subfinder - Fast passive subdomain enumeration tool
"""
import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ReconTool
from utils.output_parser import OutputParser


class SubfinderWrapper(ReconTool):
    """Wrapper for subfinder subdomain enumeration tool"""
    
    @property
    def tool_name(self) -> str:
        return "subfinder"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build subfinder-specific arguments"""
        args = ["-d", target]
        
        # Output file
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Use all sources
        if kwargs.get("all_sources", True):
            args.append("-all")
        
        # Recursive enumeration
        if kwargs.get("recursive"):
            args.append("-recursive")
        
        # Custom resolvers
        if kwargs.get("resolvers"):
            args.extend(["-r", kwargs["resolvers"]])
        
        # Rate limiting
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        
        # Only active sources
        if kwargs.get("active"):
            args.append("-active")
        
        # Exclude sources
        if kwargs.get("exclude_sources"):
            args.extend(["-es", kwargs["exclude_sources"]])
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse subfinder output"""
        return OutputParser.parse_subfinder(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="Subfinder - Fast passive subdomain enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subfinder.py -d example.com
  python subfinder.py -d example.com -o subdomains.txt --all
  python subfinder.py -d example.com --recursive --active
        """
    )
    
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--all", action="store_true", help="Use all sources")
    parser.add_argument("--recursive", action="store_true", help="Recursive enumeration")
    parser.add_argument("--active", action="store_true", help="Include active sources")
    parser.add_argument("-r", "--resolvers", help="Custom resolvers file")
    parser.add_argument("--rate-limit", type=int, help="Rate limit per second")
    parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    parser.add_argument("--exclude-sources", help="Exclude specific sources")
    
    args = parser.parse_args()
    
    # Create wrapper and run
    wrapper = SubfinderWrapper()
    
    result = wrapper.run(
        target=args.domain,
        output_file=args.output,
        all_sources=args.all,
        recursive=args.recursive,
        active=args.active,
        resolvers=args.resolvers,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        exclude_sources=args.exclude_sources
    )
    
    # Print results
    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} subdomains")
        for subdomain in result["results"]:
            print(f"  {subdomain.domain}")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
