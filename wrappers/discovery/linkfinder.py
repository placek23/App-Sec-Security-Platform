"""
LinkFinder - JavaScript endpoint discovery tool
Finds endpoints in JavaScript files
"""
import sys
import re
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool


class LinkFinderWrapper(DiscoveryTool):
    """Wrapper for LinkFinder JavaScript endpoint discovery"""

    DEFAULT_TOOL_PATH = "~/tools/LinkFinder/linkfinder.py"

    @property
    def tool_name(self) -> str:
        return "python3"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build LinkFinder-specific arguments"""
        tool_path = kwargs.get("tool_path", self.DEFAULT_TOOL_PATH)
        # Expand user path
        tool_path = str(Path(tool_path).expanduser())

        args = [tool_path, "-i", target]

        # Output mode
        output_mode = kwargs.get("output_mode", "cli")
        args.extend(["-o", output_mode])

        # Domain filter
        if kwargs.get("domain"):
            args.extend(["-d", kwargs["domain"]])

        # Cookies
        if kwargs.get("cookies"):
            args.extend(["-c", kwargs["cookies"]])

        # Regex filter
        if kwargs.get("regex"):
            args.extend(["-r", kwargs["regex"]])

        # Burp input file
        if kwargs.get("burp"):
            args.extend(["-b", kwargs["burp"]])

        # Output file for html mode
        if kwargs.get("output") and output_mode == "html":
            args.extend(["-o", kwargs["output"]])

        return args

    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse LinkFinder output"""
        results = []
        seen = set()

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('[') and line not in seen:
                # LinkFinder outputs endpoints line by line
                seen.add(line)
                # Categorize the endpoint
                endpoint_type = self._categorize_endpoint(line)
                results.append({
                    "endpoint": line,
                    "type": endpoint_type
                })

        return results

    def _categorize_endpoint(self, endpoint: str) -> str:
        """Categorize endpoint by type"""
        if endpoint.startswith('http://') or endpoint.startswith('https://'):
            return "absolute_url"
        elif endpoint.startswith('//'):
            return "protocol_relative"
        elif endpoint.startswith('/'):
            return "absolute_path"
        elif '.js' in endpoint.lower():
            return "javascript"
        elif any(ext in endpoint.lower() for ext in ['.php', '.asp', '.aspx', '.jsp']):
            return "dynamic_page"
        elif any(api in endpoint.lower() for api in ['/api/', '/v1/', '/v2/', '/graphql']):
            return "api_endpoint"
        else:
            return "relative_path"


def main():
    parser = argparse.ArgumentParser(
        description="LinkFinder - JavaScript endpoint discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python linkfinder.py -i https://example.com/app.js
  python linkfinder.py -i https://example.com/app.js -d example.com
  python linkfinder.py -i /path/to/file.js -o html
  python linkfinder.py -i https://example.com -b burp_export.xml
        """
    )

    parser.add_argument("-i", "--input", required=True, dest="target",
                        help="Target URL or local JavaScript file")
    parser.add_argument("-o", "--output-mode", default="cli", choices=["cli", "html"],
                        help="Output mode (cli or html)")
    parser.add_argument("-d", "--domain", help="Domain to filter results")
    parser.add_argument("-c", "--cookies", help="Cookies to use")
    parser.add_argument("-r", "--regex", help="Regex to filter results")
    parser.add_argument("-b", "--burp", help="Burp export file")
    parser.add_argument("--output", help="Output file for html mode")
    parser.add_argument("--tool-path", default=LinkFinderWrapper.DEFAULT_TOOL_PATH,
                        help="Path to LinkFinder script")

    args = parser.parse_args()

    wrapper = LinkFinderWrapper()

    result = wrapper.run(
        target=args.target,
        output_mode=args.output_mode,
        domain=args.domain,
        cookies=args.cookies,
        regex=args.regex,
        burp=args.burp,
        output=args.output,
        tool_path=args.tool_path
    )

    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} endpoints")

        # Group by type
        by_type = {}
        for ep in result["results"]:
            ep_type = ep.get("type", "unknown")
            if ep_type not in by_type:
                by_type[ep_type] = []
            by_type[ep_type].append(ep["endpoint"])

        for ep_type, endpoints in by_type.items():
            print(f"\n  [{ep_type}] ({len(endpoints)} found)")
            for ep in endpoints[:10]:
                print(f"    {ep}")
            if len(endpoints) > 10:
                print(f"    ... and {len(endpoints) - 10} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
