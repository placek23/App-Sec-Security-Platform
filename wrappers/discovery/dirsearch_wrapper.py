"""
Dirsearch - Web path discovery scanner
"""
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool


class DirsearchWrapper(DiscoveryTool):
    """Wrapper for dirsearch web path discovery tool"""

    @property
    def tool_name(self) -> str:
        return "dirsearch"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build dirsearch-specific arguments"""
        args = ["-u", target]

        # Wordlist
        if kwargs.get("wordlist"):
            args.extend(["-w", kwargs["wordlist"]])

        # Extensions
        if kwargs.get("extensions"):
            args.extend(["-e", kwargs["extensions"]])

        # Threads
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])

        # Recursive scanning
        if kwargs.get("recursive"):
            args.append("-r")
            if kwargs.get("recursion_depth"):
                args.extend(["--recursion-depth", str(kwargs["recursion_depth"])])

        # Include status codes
        if kwargs.get("include_status"):
            args.extend(["-i", kwargs["include_status"]])

        # Exclude status codes
        if kwargs.get("exclude_status"):
            args.extend(["-x", kwargs["exclude_status"]])

        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("--follow-redirects")

        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])

        # Delay between requests
        if kwargs.get("delay"):
            args.extend(["--delay", str(kwargs["delay"])])

        # Random user agents
        if kwargs.get("random_agents"):
            args.append("--random-agent")

        # Custom user agent
        if kwargs.get("user_agent"):
            args.extend(["--user-agent", kwargs["user_agent"]])

        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])

        # Cookie
        if kwargs.get("cookies"):
            args.extend(["--cookie", kwargs["cookies"]])

        # Proxy
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])

        # Output format and file
        if kwargs.get("output"):
            args.extend(["--format", kwargs.get("output_format", "json")])
            args.extend(["-o", kwargs["output"]])

        # Force extensions
        if kwargs.get("force_extensions"):
            args.append("-f")

        # Prefixes
        if kwargs.get("prefixes"):
            args.extend(["--prefixes", kwargs["prefixes"]])

        # Suffixes
        if kwargs.get("suffixes"):
            args.extend(["--suffixes", kwargs["suffixes"]])

        # Subdirs
        if kwargs.get("subdirs"):
            args.extend(["--subdirs", kwargs["subdirs"]])

        # Exclude sizes
        if kwargs.get("exclude_sizes"):
            args.extend(["--exclude-sizes", kwargs["exclude_sizes"]])

        # Exclude texts
        if kwargs.get("exclude_texts"):
            args.extend(["--exclude-texts", kwargs["exclude_texts"]])

        # Exclude regex
        if kwargs.get("exclude_regex"):
            args.extend(["--exclude-regex", kwargs["exclude_regex"]])

        # Quiet mode
        if kwargs.get("quiet"):
            args.append("-q")

        # Full URL
        if kwargs.get("full_url"):
            args.append("--full-url")

        return args

    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse dirsearch output"""
        results = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            # Try to parse JSON output if available
            if line.startswith('{'):
                try:
                    data = json.loads(line)
                    results.append(data)
                    continue
                except json.JSONDecodeError:
                    pass
            # Parse text output: [200] https://example.com/admin
            if line and line.startswith('[') and ']' in line:
                try:
                    bracket_end = line.index(']')
                    status_code = int(line[1:bracket_end])
                    url = line[bracket_end + 1:].strip()
                    results.append({
                        "url": url,
                        "status_code": status_code
                    })
                except (ValueError, IndexError):
                    pass
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Dirsearch - Web path discovery scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dirsearch_wrapper.py -u https://example.com
  python dirsearch_wrapper.py -u https://example.com -e php,html -r
  python dirsearch_wrapper.py -u https://example.com -w custom.txt -t 50 -o results.json
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Wordlist path")
    parser.add_argument("-e", "--extensions", help="Extensions (e.g., php,html,js)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of threads")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursive scanning")
    parser.add_argument("--recursion-depth", type=int, help="Maximum recursion depth")
    parser.add_argument("-i", "--include-status", help="Include status codes")
    parser.add_argument("-x", "--exclude-status", help="Exclude status codes")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--timeout", type=int, help="Connection timeout")
    parser.add_argument("--delay", type=float, help="Delay between requests")
    parser.add_argument("--random-agent", action="store_true", dest="random_agents", help="Random user agents")
    parser.add_argument("--user-agent", help="Custom user agent")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("--cookie", dest="cookies", help="Cookie string")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", dest="output_format", default="json", help="Output format")
    parser.add_argument("-f", "--force-extensions", action="store_true", help="Force extensions")
    parser.add_argument("--prefixes", help="URL prefixes")
    parser.add_argument("--suffixes", help="URL suffixes")
    parser.add_argument("--subdirs", help="Subdirectories to scan")
    parser.add_argument("--exclude-sizes", help="Exclude response sizes")
    parser.add_argument("--exclude-texts", help="Exclude response texts")
    parser.add_argument("--exclude-regex", help="Exclude responses matching regex")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--full-url", action="store_true", help="Show full URL")

    args = parser.parse_args()

    wrapper = DirsearchWrapper()

    result = wrapper.run(
        target=args.url,
        output_file=args.output,
        wordlist=args.wordlist,
        extensions=args.extensions,
        threads=args.threads,
        recursive=args.recursive,
        recursion_depth=args.recursion_depth,
        include_status=args.include_status,
        exclude_status=args.exclude_status,
        follow_redirects=args.follow_redirects,
        timeout=args.timeout,
        delay=args.delay,
        random_agents=args.random_agents,
        user_agent=args.user_agent,
        headers=args.headers,
        cookies=args.cookies,
        proxy=args.proxy,
        output_format=args.output_format,
        force_extensions=args.force_extensions,
        prefixes=args.prefixes,
        suffixes=args.suffixes,
        subdirs=args.subdirs,
        exclude_sizes=args.exclude_sizes,
        exclude_texts=args.exclude_texts,
        exclude_regex=args.exclude_regex,
        quiet=args.quiet,
        full_url=args.full_url
    )

    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} paths")
        for entry in result["results"][:20]:
            status = f"[{entry.get('status_code', '?')}]"
            print(f"  {status} {entry.get('url', '')}")
        if len(result["results"]) > 20:
            print(f"  ... and {len(result['results']) - 20} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
