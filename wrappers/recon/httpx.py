"""
HTTPx - Fast HTTP probing and technology detection
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ReconTool
from utils.output_parser import OutputParser


class HttpxWrapper(ReconTool):
    """Wrapper for httpx HTTP probing tool"""
    
    @property
    def tool_name(self) -> str:
        return "httpx"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build httpx-specific arguments"""
        args = []
        
        # Input: single URL or list
        if kwargs.get("list"):
            args.extend(["-l", kwargs["list"]])
        else:
            args.extend(["-u", target])
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # JSON output
        if kwargs.get("json", True):
            args.append("-json")
        
        # Probes
        if kwargs.get("status_code", True):
            args.append("-status-code")
        if kwargs.get("title", True):
            args.append("-title")
        if kwargs.get("tech_detect", True):
            args.append("-tech-detect")
        if kwargs.get("content_length"):
            args.append("-content-length")
        if kwargs.get("web_server"):
            args.append("-web-server")
        if kwargs.get("ip"):
            args.append("-ip")
        if kwargs.get("cname"):
            args.append("-cname")
        if kwargs.get("cdn"):
            args.append("-cdn")
        if kwargs.get("favicon"):
            args.append("-favicon")
        
        # Filters
        if kwargs.get("match_code"):
            args.extend(["-mc", kwargs["match_code"]])
        if kwargs.get("filter_code"):
            args.extend(["-fc", kwargs["filter_code"]])
        
        # Rate limiting
        if kwargs.get("threads"):
            args.extend(["-threads", str(kwargs["threads"])])
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("-follow-redirects")
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        
        # Screenshot
        if kwargs.get("screenshot"):
            args.append("-screenshot")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse httpx output"""
        return OutputParser.parse_httpx(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="HTTPx - Fast HTTP probing and tech detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python httpx.py -u https://example.com
  python httpx.py -l subdomains.txt -o live.json
  python httpx.py -l hosts.txt --tech-detect --status-code
  python httpx.py -u example.com --follow-redirects --screenshot
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-l", "--list", help="File containing list of URLs")
    
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--json", action="store_true", default=True, help="JSON output")
    parser.add_argument("--status-code", action="store_true", default=True, help="Show status code")
    parser.add_argument("--title", action="store_true", default=True, help="Show page title")
    parser.add_argument("--tech-detect", action="store_true", default=True, help="Technology detection")
    parser.add_argument("--content-length", action="store_true", help="Show content length")
    parser.add_argument("--web-server", action="store_true", help="Show web server")
    parser.add_argument("--ip", action="store_true", help="Show IP address")
    parser.add_argument("--cname", action="store_true", help="Show CNAME")
    parser.add_argument("--cdn", action="store_true", help="CDN detection")
    parser.add_argument("--favicon", action="store_true", help="Favicon hash")
    parser.add_argument("--mc", "--match-code", dest="match_code", help="Match status codes (e.g., 200,301)")
    parser.add_argument("--fc", "--filter-code", dest="filter_code", help="Filter status codes")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads")
    parser.add_argument("--rate-limit", type=int, help="Rate limit per second")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    parser.add_argument("--screenshot", action="store_true", help="Take screenshots")
    
    args = parser.parse_args()
    
    wrapper = HttpxWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        output_file=args.output,
        list=args.list,
        json=args.json,
        status_code=args.status_code,
        title=args.title,
        tech_detect=args.tech_detect,
        content_length=args.content_length,
        web_server=args.web_server,
        ip=args.ip,
        cname=args.cname,
        cdn=args.cdn,
        favicon=args.favicon,
        match_code=args.match_code,
        filter_code=args.filter_code,
        threads=args.threads,
        rate_limit=args.rate_limit,
        follow_redirects=args.follow_redirects,
        timeout=args.timeout,
        screenshot=args.screenshot
    )
    
    if result["success"]:
        print(f"\n[+] Probed {len(result['results'])} hosts")
        for host in result["results"][:10]:
            status = f"[{host.status_code}]" if host.status_code else ""
            tech = f" | {', '.join(host.technologies[:3])}" if host.technologies else ""
            print(f"  {status} {host.domain}{tech}")
        if len(result["results"]) > 10:
            print(f"  ... and {len(result['results']) - 10} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
