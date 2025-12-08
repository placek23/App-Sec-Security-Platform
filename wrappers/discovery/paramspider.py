"""
ParamSpider - Mining parameters from web archives
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool


class ParamspiderWrapper(DiscoveryTool):
    """Wrapper for paramspider parameter mining tool"""
    
    @property
    def tool_name(self) -> str:
        return "paramspider"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build paramspider-specific arguments"""
        args = ["-d", target]
        
        # Output directory
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Level of crawling
        if kwargs.get("level"):
            args.extend(["--level", kwargs["level"]])
        
        # Exclude subdomains
        if kwargs.get("exclude"):
            args.extend(["--exclude", kwargs["exclude"]])
        
        # Placeholder
        if kwargs.get("placeholder"):
            args.extend(["--placeholder", kwargs["placeholder"]])
        
        # Quiet mode
        if kwargs.get("quiet"):
            args.append("-q")
        
        # Include subdomains
        if kwargs.get("subs"):
            args.append("-s")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse paramspider output"""
        results = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                # Extract parameters from URL
                params = []
                if '?' in line:
                    param_str = line.split('?')[1].split('#')[0]
                    params = [p.split('=')[0] for p in param_str.split('&') if '=' in p]
                results.append({
                    'url': line,
                    'parameters': params,
                    'source': 'paramspider'
                })
        return results


def main():
    parser = argparse.ArgumentParser(
        description="ParamSpider - Mining parameters from web archives",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python paramspider.py -d example.com
  python paramspider.py -d example.com --level high -o params/
  python paramspider.py -d example.com -s --exclude cdn,static
        """
    )
    
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--level", choices=["low", "medium", "high"], default="high", help="Crawl level")
    parser.add_argument("--exclude", help="Subdomains to exclude (comma-separated)")
    parser.add_argument("--placeholder", default="FUZZ", help="Placeholder for parameter value")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-s", "--subs", action="store_true", help="Include subdomains")
    
    args = parser.parse_args()
    
    wrapper = ParamspiderWrapper()
    
    result = wrapper.run(
        target=args.domain,
        output_file=args.output,
        level=args.level,
        exclude=args.exclude,
        placeholder=args.placeholder,
        quiet=args.quiet,
        subs=args.subs
    )
    
    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} URLs with parameters")
        
        # Collect all unique parameters
        all_params = set()
        for item in result["results"]:
            all_params.update(item.get('parameters', []))
        
        print(f"[+] Unique parameters: {len(all_params)}")
        for param in list(all_params)[:20]:
            print(f"  - {param}")
        if len(all_params) > 20:
            print(f"  ... and {len(all_params) - 20} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
