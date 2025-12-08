"""
SecretFinder - Find secrets in JavaScript files
Discovers API keys, tokens, credentials and other sensitive data
"""
import sys
import re
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool


class SecretFinderWrapper(DiscoveryTool):
    """Wrapper for SecretFinder secret discovery tool"""

    DEFAULT_TOOL_PATH = "~/tools/SecretFinder/SecretFinder.py"

    # Common secret patterns for fallback parsing
    SECRET_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
        'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
        'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'github_token': r'ghp_[0-9a-zA-Z]{36}',
        'github_oauth': r'gho_[0-9a-zA-Z]{36}',
        'slack_token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        'stripe_live': r'sk_live_[0-9a-zA-Z]{24}',
        'stripe_test': r'sk_test_[0-9a-zA-Z]{24}',
        'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'private_key': r'-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----',
        'heroku_api': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
        'mailgun_api': r'key-[0-9a-zA-Z]{32}',
        'twilio': r'SK[0-9a-fA-F]{32}',
        'password_field': r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'api_key_generic': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'bearer_token': r'[Bb]earer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        'authorization': r'["\']?[Aa]uthorization["\']?\s*[:=]\s*["\'][^"\']+["\']',
    }

    @property
    def tool_name(self) -> str:
        return "python3"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build SecretFinder-specific arguments"""
        tool_path = kwargs.get("tool_path", self.DEFAULT_TOOL_PATH)
        # Expand user path
        tool_path = str(Path(tool_path).expanduser())

        args = [tool_path, "-i", target]

        # Output mode
        output_mode = kwargs.get("output_mode", "cli")
        args.extend(["-o", output_mode])

        # Custom regex
        if kwargs.get("regex"):
            args.extend(["-r", kwargs["regex"]])

        # Output file for html mode
        if kwargs.get("output") and output_mode == "html":
            args.extend(["-o", kwargs["output"]])

        return args

    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse SecretFinder output"""
        results = []
        seen = set()

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line and line not in seen:
                seen.add(line)
                # Try to categorize the secret
                secret_type = self._identify_secret_type(line)
                results.append({
                    "secret": line,
                    "type": secret_type,
                    "severity": self._get_severity(secret_type)
                })

        return results

    def _identify_secret_type(self, secret: str) -> str:
        """Identify the type of secret based on patterns"""
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            if re.search(pattern, secret, re.IGNORECASE):
                return secret_type
        return "unknown"

    def _get_severity(self, secret_type: str) -> str:
        """Get severity level for secret type"""
        critical = ['aws_access_key', 'aws_secret_key', 'private_key', 'stripe_live']
        high = ['github_token', 'slack_token', 'jwt_token', 'bearer_token', 'heroku_api']
        medium = ['google_api', 'firebase', 'stripe_test', 'mailgun_api', 'twilio']
        low = ['password_field', 'api_key_generic', 'authorization']

        if secret_type in critical:
            return "critical"
        elif secret_type in high:
            return "high"
        elif secret_type in medium:
            return "medium"
        elif secret_type in low:
            return "low"
        return "info"

    def scan_content(self, content: str) -> list:
        """Scan content directly for secrets (without using external tool)"""
        results = []
        seen = set()

        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in seen:
                    seen.add(match)
                    results.append({
                        "secret": match[:100] + "..." if len(match) > 100 else match,
                        "type": secret_type,
                        "severity": self._get_severity(secret_type)
                    })

        return results


def main():
    parser = argparse.ArgumentParser(
        description="SecretFinder - Find secrets in JavaScript files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python secretfinder.py -i https://example.com/app.js
  python secretfinder.py -i /path/to/file.js
  python secretfinder.py -i https://example.com/app.js -o html --output results.html
  python secretfinder.py -i https://example.com/app.js -r "custom_pattern"
        """
    )

    parser.add_argument("-i", "--input", required=True, dest="target",
                        help="Target URL or local JavaScript file")
    parser.add_argument("-o", "--output-mode", default="cli", choices=["cli", "html"],
                        help="Output mode (cli or html)")
    parser.add_argument("-r", "--regex", help="Custom regex pattern")
    parser.add_argument("--output", help="Output file for html mode")
    parser.add_argument("--tool-path", default=SecretFinderWrapper.DEFAULT_TOOL_PATH,
                        help="Path to SecretFinder script")

    args = parser.parse_args()

    wrapper = SecretFinderWrapper()

    result = wrapper.run(
        target=args.target,
        output_mode=args.output_mode,
        regex=args.regex,
        output=args.output,
        tool_path=args.tool_path
    )

    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} potential secrets")

        # Group by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        for secret in result["results"]:
            severity = secret.get("severity", "info")
            by_severity[severity].append(secret)

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            secrets = by_severity[severity]
            if secrets:
                print(f"\n  [{severity.upper()}] ({len(secrets)} found)")
                for s in secrets[:5]:
                    secret_preview = s['secret'][:50] + "..." if len(s['secret']) > 50 else s['secret']
                    print(f"    [{s['type']}] {secret_preview}")
                if len(secrets) > 5:
                    print(f"    ... and {len(secrets) - 5} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
