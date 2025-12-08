"""
FFuf - Fast web fuzzer for directories, files, and parameters
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool
from utils.output_parser import OutputParser


class FfufWrapper(DiscoveryTool):
    """Wrapper for ffuf web fuzzing tool"""
    
    @property
    def tool_name(self) -> str:
        return "ffuf"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build ffuf-specific arguments"""
        args = ["-u", target]
        
        # Wordlist
        if kwargs.get("wordlist"):
            args.extend(["-w", kwargs["wordlist"]])
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
            args.extend(["-of", kwargs.get("output_format", "json")])
        
        # Method
        if kwargs.get("method"):
            args.extend(["-X", kwargs["method"]])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # Cookies
        if kwargs.get("cookies"):
            args.extend(["-b", kwargs["cookies"]])
        
        # Data (POST body)
        if kwargs.get("data"):
            args.extend(["-d", kwargs["data"]])
        
        # Match options
        if kwargs.get("match_code"):
            args.extend(["-mc", kwargs["match_code"]])
        if kwargs.get("match_size"):
            args.extend(["-ms", kwargs["match_size"]])
        if kwargs.get("match_words"):
            args.extend(["-mw", kwargs["match_words"]])
        if kwargs.get("match_lines"):
            args.extend(["-ml", kwargs["match_lines"]])
        if kwargs.get("match_regex"):
            args.extend(["-mr", kwargs["match_regex"]])
        
        # Filter options
        if kwargs.get("filter_code"):
            args.extend(["-fc", kwargs["filter_code"]])
        if kwargs.get("filter_size"):
            args.extend(["-fs", kwargs["filter_size"]])
        if kwargs.get("filter_words"):
            args.extend(["-fw", kwargs["filter_words"]])
        if kwargs.get("filter_lines"):
            args.extend(["-fl", kwargs["filter_lines"]])
        if kwargs.get("filter_regex"):
            args.extend(["-fr", kwargs["filter_regex"]])
        
        # Auto-calibration
        if kwargs.get("auto_calibrate", True):
            args.append("-ac")
        
        # Threads
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        
        # Rate limiting
        if kwargs.get("rate"):
            args.extend(["-rate", str(kwargs["rate"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        
        # Recursion
        if kwargs.get("recursion"):
            args.append("-recursion")
            if kwargs.get("recursion_depth"):
                args.extend(["-recursion-depth", str(kwargs["recursion_depth"])])
        
        # Extensions
        if kwargs.get("extensions"):
            args.extend(["-e", kwargs["extensions"]])
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("-r")
        
        # Silent mode
        if kwargs.get("silent"):
            args.append("-s")
        
        # Colorless
        args.append("-c")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse ffuf output"""
        return OutputParser.parse_ffuf(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="FFuf - Fast web fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ffuf.py -u https://example.com/FUZZ -w wordlist.txt
  python ffuf.py -u https://example.com/FUZZ -w dirs.txt -mc 200,301 -o results.json
  python ffuf.py -u https://example.com/api/FUZZ -w params.txt -X POST -d "id=1"
  python ffuf.py -u https://example.com/FUZZ -w dirs.txt --recursion -e .php,.html
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL with FUZZ keyword")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist path")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-X", "--method", help="HTTP method")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Headers")
    parser.add_argument("-b", "--cookies", help="Cookies")
    parser.add_argument("-d", "--data", help="POST data")
    parser.add_argument("-mc", "--match-code", help="Match status codes")
    parser.add_argument("-ms", "--match-size", help="Match response size")
    parser.add_argument("-mw", "--match-words", help="Match word count")
    parser.add_argument("-ml", "--match-lines", help="Match line count")
    parser.add_argument("-mr", "--match-regex", help="Match regex")
    parser.add_argument("-fc", "--filter-code", help="Filter status codes")
    parser.add_argument("-fs", "--filter-size", help="Filter response size")
    parser.add_argument("-fw", "--filter-words", help="Filter word count")
    parser.add_argument("-fl", "--filter-lines", help="Filter line count")
    parser.add_argument("-fr", "--filter-regex", help="Filter regex")
    parser.add_argument("-ac", "--auto-calibrate", action="store_true", default=True, help="Auto calibration")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--rate", type=int, help="Rate limit per second")
    parser.add_argument("--timeout", type=int, help="Request timeout")
    parser.add_argument("--recursion", action="store_true", help="Enable recursion")
    parser.add_argument("--recursion-depth", type=int, help="Recursion depth")
    parser.add_argument("-e", "--extensions", help="Extensions to append (e.g., .php,.html)")
    parser.add_argument("-r", "--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode")
    
    args = parser.parse_args()
    
    wrapper = FfufWrapper()
    
    result = wrapper.run(
        target=args.url,
        output_file=args.output,
        wordlist=args.wordlist,
        method=args.method,
        headers=args.headers,
        cookies=args.cookies,
        data=args.data,
        match_code=args.match_code,
        match_size=args.match_size,
        match_words=args.match_words,
        match_lines=args.match_lines,
        match_regex=args.match_regex,
        filter_code=args.filter_code,
        filter_size=args.filter_size,
        filter_words=args.filter_words,
        filter_lines=args.filter_lines,
        filter_regex=args.filter_regex,
        auto_calibrate=args.auto_calibrate,
        threads=args.threads,
        rate=args.rate,
        timeout=args.timeout,
        recursion=args.recursion,
        recursion_depth=args.recursion_depth,
        extensions=args.extensions,
        follow_redirects=args.follow_redirects,
        silent=args.silent
    )
    
    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} endpoints")
        for ep in result["results"][:15]:
            status = f"[{ep.status_code}]" if ep.status_code else ""
            print(f"  {status} {ep.url}")
        if len(result["results"]) > 15:
            print(f"  ... and {len(result['results']) - 15} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
