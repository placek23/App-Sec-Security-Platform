#!/usr/bin/env python3
"""
OSINT Search - Open Source Intelligence gathering
Searches public sources for leaked credentials, exposed code, and sensitive data
"""
import sys
import json
import argparse
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import quote
import requests

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class OSINTSearch:
    """
    OSINT (Open Source Intelligence) search tool.

    Completely passive - searches public databases and search engines.

    Features:
    - GitHub code search (for exposed secrets)
    - Google dork generation
    - Pastebin/paste site search
    - Shodan queries (host info)
    - Public data breach check
    - Social media presence
    """

    # GitHub search URL (web scraping, no API key needed for basic search)
    GITHUB_SEARCH = "https://github.com/search"

    # Google dork templates
    GOOGLE_DORKS = {
        'sensitive_files': [
            'site:{domain} ext:sql',
            'site:{domain} ext:log',
            'site:{domain} ext:conf',
            'site:{domain} ext:env',
            'site:{domain} ext:bak',
            'site:{domain} ext:xml',
            'site:{domain} filetype:pdf',
        ],
        'exposed_data': [
            'site:{domain} "password"',
            'site:{domain} "api_key"',
            'site:{domain} "apikey"',
            'site:{domain} "secret"',
            'site:{domain} "token"',
            'site:{domain} "aws_access"',
            'site:{domain} "BEGIN RSA PRIVATE KEY"',
        ],
        'admin_panels': [
            'site:{domain} inurl:admin',
            'site:{domain} inurl:login',
            'site:{domain} inurl:dashboard',
            'site:{domain} intitle:"admin"',
            'site:{domain} intitle:"login"',
        ],
        'exposed_directories': [
            'site:{domain} intitle:"Index of"',
            'site:{domain} intitle:"Directory listing"',
            'site:{domain} "parent directory"',
        ],
        'error_pages': [
            'site:{domain} "SQL syntax error"',
            'site:{domain} "mysql_fetch"',
            'site:{domain} "Warning: mysql"',
            'site:{domain} "ORA-" error',
            'site:{domain} "syntax error" php',
        ],
        'subdomains': [
            'site:*.{domain}',
            'site:{domain} -www',
        ]
    }

    # GitHub dork templates
    GITHUB_DORKS = {
        'credentials': [
            '"{domain}" password',
            '"{domain}" api_key',
            '"{domain}" apikey',
            '"{domain}" secret',
            '"{domain}" token',
            '"{domain}" aws_access_key',
            '"{domain}" private_key',
        ],
        'config_files': [
            '"{domain}" filename:.env',
            '"{domain}" filename:config',
            '"{domain}" filename:.htaccess',
            '"{domain}" filename:wp-config',
            '"{domain}" filename:settings.py',
            '"{domain}" filename:database.yml',
        ],
        'internal_data': [
            '"{domain}" internal',
            '"{domain}" confidential',
            '"{domain}" secret',
            '"{domain}" private',
        ]
    }

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.results = {
            'google_dorks': {},
            'github_dorks': {},
            'paste_results': [],
            'shodan_info': {},
            'social_media': {},
            'metadata': {}
        }

    def generate_google_dorks(self, domain: str) -> Dict[str, List[str]]:
        """Generate Google dorks for a domain."""
        dorks = {}
        for category, templates in self.GOOGLE_DORKS.items():
            dorks[category] = [t.format(domain=domain) for t in templates]
        self.results['google_dorks'] = dorks
        return dorks

    def generate_github_dorks(self, domain: str) -> Dict[str, List[str]]:
        """Generate GitHub search queries for a domain."""
        dorks = {}
        for category, templates in self.GITHUB_DORKS.items():
            dorks[category] = [t.format(domain=domain) for t in templates]
        self.results['github_dorks'] = dorks
        return dorks

    def search_github_code(self, query: str) -> List[Dict]:
        """
        Search GitHub for code containing query.
        Note: Web search is rate-limited. For extensive use, use GitHub API with token.
        """
        results = []
        search_url = f"{self.GITHUB_SEARCH}?q={quote(query)}&type=code"

        # Note: This returns the search URL, not actual results
        # Actual scraping would require handling GitHub's anti-bot measures
        results.append({
            'query': query,
            'search_url': search_url,
            'note': 'Visit URL manually or use GitHub API for results'
        })

        return results

    def search_pastebin(self, domain: str) -> List[Dict]:
        """
        Search paste sites for domain mentions.
        Uses public paste search APIs where available.
        """
        results = []

        # Pastebin search (scraping limited, but we can generate search URLs)
        searches = [
            ('Google Pastebin', f'site:pastebin.com "{domain}"'),
            ('Google Ghostbin', f'site:ghostbin.com "{domain}"'),
            ('Google Hastebin', f'site:hastebin.com "{domain}"'),
            ('Pastebin Search', f'https://pastebin.com/search?q={quote(domain)}'),
        ]

        for name, query in searches:
            results.append({
                'source': name,
                'search': query if query.startswith('http') else f'https://www.google.com/search?q={quote(query)}'
            })

        self.results['paste_results'] = results
        return results

    def query_shodan_host(self, ip: str, api_key: str = None) -> Dict:
        """
        Query Shodan for host information.
        Without API key, uses limited public endpoints.
        """
        if api_key:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        else:
            # InternetDB - free alternative
            url = f"https://internetdb.shodan.io/{ip}"

        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return {'error': str(e)}

        return {}

    def check_email_breach(self, email: str) -> Dict:
        """
        Check if email appears in known breaches.
        Uses Have I Been Pwned API (rate limited without API key).
        """
        # Note: HIBP API requires API key for most queries
        # This generates the lookup URL instead
        return {
            'email': email,
            'hibp_url': f'https://haveibeenpwned.com/account/{quote(email)}',
            'note': 'Visit URL or use HIBP API with key for breach data'
        }

    def search_social_media(self, target: str) -> Dict[str, str]:
        """Generate social media search URLs for a target."""
        social = {
            'twitter': f'https://twitter.com/search?q={quote(target)}',
            'linkedin_company': f'https://www.linkedin.com/search/results/companies/?keywords={quote(target)}',
            'linkedin_people': f'https://www.linkedin.com/search/results/people/?keywords={quote(target)}',
            'facebook': f'https://www.facebook.com/search/top?q={quote(target)}',
            'reddit': f'https://www.reddit.com/search/?q={quote(target)}',
            'youtube': f'https://www.youtube.com/results?search_query={quote(target)}',
        }
        self.results['social_media'] = social
        return social

    def find_email_pattern(self, domain: str) -> List[str]:
        """
        Generate common email patterns for a domain.
        Useful for social engineering awareness.
        """
        patterns = [
            f'firstname.lastname@{domain}',
            f'firstnamelastname@{domain}',
            f'f.lastname@{domain}',
            f'firstname.l@{domain}',
            f'firstname@{domain}',
            f'lastname@{domain}',
            f'first.last@{domain}',
        ]
        return patterns

    def generate_search_urls(self, domain: str) -> Dict[str, str]:
        """Generate various search engine URLs for the domain."""
        searches = {
            'google': f'https://www.google.com/search?q=site:{domain}',
            'bing': f'https://www.bing.com/search?q=site:{domain}',
            'duckduckgo': f'https://duckduckgo.com/?q=site:{domain}',
            'yandex': f'https://yandex.com/search/?text=site:{domain}',
            'archive_org': f'https://web.archive.org/web/*/{domain}',
            'urlscan': f'https://urlscan.io/search/#domain:{domain}',
            'virustotal': f'https://www.virustotal.com/gui/domain/{domain}',
            'securitytrails': f'https://securitytrails.com/domain/{domain}',
            'dnsdumpster': f'https://dnsdumpster.com/',
            'censys': f'https://search.censys.io/search?resource=hosts&q={domain}',
        }
        return searches

    def full_osint(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive OSINT gathering."""
        print(f"\n{'='*60}")
        print(f"OSINT Search: {domain}")
        print(f"{'='*60}\n")

        # Generate Google dorks
        print("[*] Generating Google dorks...")
        google_dorks = self.generate_google_dorks(domain)
        total_dorks = sum(len(v) for v in google_dorks.values())
        print(f"    Generated {total_dorks} Google dorks")

        # Generate GitHub dorks
        print("\n[*] Generating GitHub search queries...")
        github_dorks = self.generate_github_dorks(domain)
        total_github = sum(len(v) for v in github_dorks.values())
        print(f"    Generated {total_github} GitHub queries")

        # Paste site searches
        print("\n[*] Generating paste site searches...")
        paste_results = self.search_pastebin(domain)
        print(f"    Generated {len(paste_results)} paste searches")

        # Social media searches
        print("\n[*] Generating social media searches...")
        social = self.search_social_media(domain)
        print(f"    Generated {len(social)} social media searches")

        # Search engine URLs
        print("\n[*] Generating search engine URLs...")
        search_urls = self.generate_search_urls(domain)
        self.results['search_urls'] = search_urls

        # Email patterns
        email_patterns = self.find_email_pattern(domain)
        self.results['email_patterns'] = email_patterns

        # Metadata
        self.results['metadata'] = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'scan_type': 'passive',
            'total_google_dorks': total_dorks,
            'total_github_queries': total_github
        }

        return self.results

    def save_results(self, output_file: str):
        """Save results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[+] Results saved to {output_file}")

    def save_dorks(self, output_file: str, dork_type: str = 'google'):
        """Save dorks to text file."""
        if dork_type == 'google':
            dorks = self.results.get('google_dorks', {})
        else:
            dorks = self.results.get('github_dorks', {})

        with open(output_file, 'w') as f:
            for category, queries in dorks.items():
                f.write(f"# {category}\n")
                for query in queries:
                    f.write(f"{query}\n")
                f.write("\n")

        print(f"[+] Dorks saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Search Tool (Passive)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_search.py -d example.com
  python osint_search.py -d example.com --google-dorks
  python osint_search.py -d example.com --github-dorks -o github.txt
  python osint_search.py -d example.com -o results.json
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--google-dorks", action="store_true",
                        help="Output Google dorks only")
    parser.add_argument("--github-dorks", action="store_true",
                        help="Output GitHub dorks only")
    parser.add_argument("--email", help="Check email in breaches")
    parser.add_argument("--ip", help="Query Shodan for IP")
    parser.add_argument("--shodan-key", help="Shodan API key")

    args = parser.parse_args()

    osint = OSINTSearch()

    if args.google_dorks:
        dorks = osint.generate_google_dorks(args.domain)
        print(f"\n[+] Google Dorks for {args.domain}:\n")
        for category, queries in dorks.items():
            print(f"\n# {category.upper()}")
            for query in queries:
                print(f"  {query}")
        if args.output:
            osint.save_dorks(args.output, 'google')

    elif args.github_dorks:
        dorks = osint.generate_github_dorks(args.domain)
        print(f"\n[+] GitHub Dorks for {args.domain}:\n")
        for category, queries in dorks.items():
            print(f"\n# {category.upper()}")
            for query in queries:
                print(f"  {query}")
                print(f"    URL: https://github.com/search?q={quote(query)}&type=code")
        if args.output:
            osint.save_dorks(args.output, 'github')

    elif args.email:
        result = osint.check_email_breach(args.email)
        print(f"\n[*] Email breach check for {args.email}")
        print(f"    Check URL: {result['hibp_url']}")

    elif args.ip:
        print(f"\n[*] Querying Shodan for {args.ip}...")
        result = osint.query_shodan_host(args.ip, args.shodan_key)
        if result and 'error' not in result:
            print(f"    Ports: {result.get('ports', [])}")
            print(f"    Hostnames: {result.get('hostnames', [])}")
            print(f"    Tags: {result.get('tags', [])}")
            print(f"    Vulns: {result.get('vulns', [])}")
        else:
            print(f"    Error or no data: {result}")

    else:
        results = osint.full_osint(args.domain)

        # Print summary
        print(f"\n{'='*60}")
        print("Summary")
        print(f"{'='*60}")

        print(f"\n  Search Engine URLs:")
        for name, url in results.get('search_urls', {}).items():
            print(f"    {name}: {url[:60]}...")

        print(f"\n  Google Dork Categories:")
        for category, dorks in results.get('google_dorks', {}).items():
            print(f"    {category}: {len(dorks)} dorks")

        print(f"\n  Common Email Patterns:")
        for pattern in results.get('email_patterns', [])[:5]:
            print(f"    {pattern}")

        if args.output:
            osint.save_results(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
