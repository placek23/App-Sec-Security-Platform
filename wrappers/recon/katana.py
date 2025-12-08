"""
Katana - JavaScript-aware web crawling and endpoint discovery
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ReconTool
from utils.output_parser import OutputParser


class KatanaWrapper(ReconTool):
    """Wrapper for katana crawling tool"""
    
    @property
    def tool_name(self) -> str:
        return "katana"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build katana-specific arguments"""
        args = []
        
        # Input
        if kwargs.get("list"):
            args.extend(["-list", kwargs["list"]])
        else:
            args.extend(["-u", target])
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Crawl depth
        if kwargs.get("depth"):
            args.extend(["-d", str(kwargs["depth"])])
        
        # JavaScript crawling
        if kwargs.get("js_crawl", True):
            args.append("-jc")
        
        # Known files
        if kwargs.get("known_files"):
            args.extend(["-kf", kwargs["known_files"]])
        
        # Field extraction
        if kwargs.get("field"):
            args.extend(["-f", kwargs["field"]])
        
        # Headless mode
        if kwargs.get("headless"):
            args.append("-headless")
        
        # Scope
        if kwargs.get("scope"):
            args.extend(["-fs", kwargs["scope"]])
        if kwargs.get("out_of_scope"):
            args.extend(["-cs", kwargs["out_of_scope"]])
        
        # Extensions to filter
        if kwargs.get("extension_filter"):
            args.extend(["-ef", kwargs["extension_filter"]])
        
        # Rate limiting
        if kwargs.get("concurrency"):
            args.extend(["-c", str(kwargs["concurrency"])])
        if kwargs.get("delay"):
            args.extend(["-delay", kwargs["delay"]])
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        
        # Form filling
        if kwargs.get("form_fill"):
            args.append("-form-fill")
        
        # Automatic form submission
        if kwargs.get("aff"):
            args.append("-aff")
        
        # Strategy
        if kwargs.get("strategy"):
            args.extend(["-strategy", kwargs["strategy"]])
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse katana output"""
        return OutputParser.parse_katana(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="Katana - JS-aware web crawling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python katana.py -u https://example.com
  python katana.py -u https://example.com -d 3 --js-crawl
  python katana.py -l urls.txt -o endpoints.txt
  python katana.py -u example.com --headless --form-fill
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-l", "--list", help="File containing URLs")
    
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("--js-crawl", action="store_true", default=True, help="JavaScript crawling")
    parser.add_argument("--known-files", help="Known files to check (all, robotstxt, sitemapxml)")
    parser.add_argument("-f", "--field", help="Field to extract (url, path, fqdn, etc.)")
    parser.add_argument("--headless", action="store_true", help="Headless browser mode")
    parser.add_argument("--scope", help="Crawl scope regex")
    parser.add_argument("--out-of-scope", help="Out of scope regex")
    parser.add_argument("--extension-filter", help="Extensions to filter")
    parser.add_argument("-c", "--concurrency", type=int, help="Concurrent requests")
    parser.add_argument("--delay", help="Delay between requests (e.g., 100ms)")
    parser.add_argument("--rate-limit", type=int, help="Rate limit per second")
    parser.add_argument("--timeout", type=int, help="Request timeout")
    parser.add_argument("--form-fill", action="store_true", help="Enable form filling")
    parser.add_argument("--aff", action="store_true", help="Automatic form submission")
    parser.add_argument("--strategy", choices=["depth-first", "breadth-first"], help="Crawl strategy")
    
    args = parser.parse_args()
    
    wrapper = KatanaWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        output_file=args.output,
        list=args.list,
        depth=args.depth,
        js_crawl=args.js_crawl,
        known_files=args.known_files,
        field=args.field,
        headless=args.headless,
        scope=args.scope,
        out_of_scope=args.out_of_scope,
        extension_filter=args.extension_filter,
        concurrency=args.concurrency,
        delay=args.delay,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        form_fill=args.form_fill,
        aff=args.aff,
        strategy=args.strategy
    )
    
    if result["success"]:
        print(f"\n[+] Discovered {len(result['results'])} endpoints")
        for ep in result["results"][:15]:
            print(f"  {ep.url}")
        if len(result["results"]) > 15:
            print(f"  ... and {len(result['results']) - 15} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
