#!/usr/bin/env python3
"""
WHOIS Lookup - Passive domain registration information
Queries public WHOIS databases for domain information
"""
import sys
import json
import socket
import argparse
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
import requests

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class WhoisLookup:
    """
    Passive WHOIS lookup tool.

    Queries public WHOIS databases - no direct target interaction.

    Features:
    - Domain registration information
    - Registrar details
    - Name server information
    - Registration dates
    - Related domain discovery
    """

    # WHOIS servers for different TLDs
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'me': 'whois.nic.me',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'eu': 'whois.eu',
        'ru': 'whois.tcinet.ru',
        'cn': 'whois.cnnic.cn',
        'jp': 'whois.jprs.jp',
        'au': 'whois.auda.org.au',
        'ca': 'whois.cira.ca',
        'fr': 'whois.nic.fr',
        'nl': 'whois.domain-registry.nl',
        'be': 'whois.dns.be',
        'ch': 'whois.nic.ch',
        'at': 'whois.nic.at',
        'pl': 'whois.dns.pl',
        'br': 'whois.registro.br',
        'in': 'whois.registry.in',
        'default': 'whois.iana.org'
    }

    # Public WHOIS APIs (no direct WHOIS connection needed)
    WHOIS_APIS = {
        'whoisxml': 'https://www.whoisxmlapi.com/whoisserver/WhoisService',
        'jsonwhois': 'https://jsonwhois.com/api/v1/whois',
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results = {}

    def get_whois_server(self, domain: str) -> str:
        """Get appropriate WHOIS server for domain TLD."""
        tld = domain.split('.')[-1].lower()
        return self.WHOIS_SERVERS.get(tld, self.WHOIS_SERVERS['default'])

    def query_whois_direct(self, domain: str) -> Optional[str]:
        """Query WHOIS server directly via socket."""
        server = self.get_whois_server(domain)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))
            sock.send(f"{domain}\r\n".encode())

            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"  [!] WHOIS query error: {e}")
            return None

    def query_whois_api(self, domain: str) -> Optional[Dict]:
        """Query WHOIS via public API (no API key needed)."""
        # Using a free WHOIS API
        url = f"https://api.whoapi.com/?domain={domain}&r=whois&apikey=free"

        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        # Fallback to another free API
        try:
            url = f"https://whois.freeaiapi.xyz/?name={domain}"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return None

    def parse_whois_response(self, raw_whois: str) -> Dict[str, Any]:
        """Parse raw WHOIS response into structured data."""
        parsed = {
            'raw': raw_whois,
            'domain_name': None,
            'registrar': None,
            'registrar_url': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'registrant': {},
            'admin': {},
            'tech': {},
            'dnssec': None
        }

        if not raw_whois:
            return parsed

        lines = raw_whois.split('\n')

        # Common WHOIS field patterns
        patterns = {
            'domain_name': r'Domain Name:\s*(.+)',
            'registrar': r'Registrar:\s*(.+)',
            'registrar_url': r'Registrar URL:\s*(.+)',
            'creation_date': r'Creat(?:ion|ed) Date:\s*(.+)',
            'expiration_date': r'(?:Expir(?:y|ation)|Registry Expiry) Date:\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)',
            'name_server': r'Name Server:\s*(.+)',
            'status': r'(?:Domain )?Status:\s*(.+)',
            'dnssec': r'DNSSEC:\s*(.+)',
        }

        # Registrant patterns
        registrant_patterns = {
            'name': r'Registrant Name:\s*(.+)',
            'organization': r'Registrant Organization:\s*(.+)',
            'email': r'Registrant Email:\s*(.+)',
            'country': r'Registrant Country:\s*(.+)',
        }

        for line in lines:
            line = line.strip()

            for field, pattern in patterns.items():
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if field == 'name_server':
                        parsed['name_servers'].append(value.lower())
                    elif field == 'status':
                        parsed['status'].append(value.split()[0])  # Remove URLs
                    else:
                        parsed[field] = value

            for field, pattern in registrant_patterns.items():
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    parsed['registrant'][field] = match.group(1).strip()

        return parsed

    def lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for a domain."""
        print(f"[*] Looking up WHOIS for {domain}...")

        # Try direct WHOIS query first
        raw_whois = self.query_whois_direct(domain)

        if raw_whois:
            parsed = self.parse_whois_response(raw_whois)
        else:
            # Fallback to API
            print("  [*] Trying WHOIS API fallback...")
            api_result = self.query_whois_api(domain)
            if api_result:
                parsed = {
                    'raw': str(api_result),
                    'api_response': api_result
                }
            else:
                parsed = {'error': 'Unable to retrieve WHOIS data'}

        parsed['query_domain'] = domain
        parsed['query_time'] = datetime.now().isoformat()

        self.results[domain] = parsed
        return parsed

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for an IP address."""
        print(f"[*] Looking up IP WHOIS for {ip}...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(('whois.arin.net', 43))
            sock.send(f"n {ip}\r\n".encode())

            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()

            raw = response.decode('utf-8', errors='ignore')

            # Parse IP WHOIS
            result = {
                'ip': ip,
                'raw': raw,
                'netname': None,
                'netrange': None,
                'organization': None,
                'country': None,
            }

            for line in raw.split('\n'):
                if 'NetName:' in line:
                    result['netname'] = line.split(':')[1].strip()
                elif 'NetRange:' in line:
                    result['netrange'] = line.split(':')[1].strip()
                elif 'Organization:' in line:
                    result['organization'] = line.split(':')[1].strip()
                elif 'Country:' in line:
                    result['country'] = line.split(':')[1].strip()

            return result
        except Exception as e:
            return {'ip': ip, 'error': str(e)}

    def find_related_domains(self, registrant_email: str) -> List[str]:
        """
        Find domains registered with the same email.
        Uses reverse WHOIS lookup (requires API in production).
        """
        # Note: This typically requires a paid API
        # Here we just return a placeholder
        print(f"  [*] Reverse WHOIS lookup requires API access")
        return []

    def check_domain_age(self, whois_data: Dict) -> Optional[int]:
        """Calculate domain age in days."""
        creation_date = whois_data.get('creation_date')
        if creation_date:
            try:
                # Try various date formats
                for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%d-%b-%Y']:
                    try:
                        created = datetime.strptime(creation_date[:19], fmt)
                        return (datetime.now() - created).days
                    except ValueError:
                        continue
            except Exception:
                pass
        return None

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Comprehensive domain analysis via WHOIS."""
        result = self.lookup(domain)

        # Add analysis
        result['analysis'] = {
            'domain_age_days': self.check_domain_age(result),
            'has_privacy_protection': self._check_privacy(result),
            'nameserver_count': len(result.get('name_servers', [])),
            'status_flags': result.get('status', []),
        }

        return result

    def _check_privacy(self, whois_data: Dict) -> bool:
        """Check if domain has WHOIS privacy protection."""
        privacy_indicators = [
            'privacy', 'protect', 'proxy', 'guard', 'redacted',
            'whoisguard', 'privacyprotect', 'domainsbyproxy'
        ]

        raw = whois_data.get('raw', '').lower()
        registrant = str(whois_data.get('registrant', {})).lower()

        return any(ind in raw or ind in registrant for ind in privacy_indicators)

    def save_results(self, output_file: str):
        """Save results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[+] Results saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="WHOIS Lookup Tool (Passive)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python whois_lookup.py -d example.com
  python whois_lookup.py -d example.com -o whois.json
  python whois_lookup.py --ip 8.8.8.8
  python whois_lookup.py -d example.com --raw
        """
    )

    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("--ip", help="Target IP address")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--raw", action="store_true", help="Show raw WHOIS response")
    parser.add_argument("--timeout", type=int, default=10, help="Query timeout")

    args = parser.parse_args()

    if not args.domain and not args.ip:
        parser.error("Either --domain or --ip is required")

    whois = WhoisLookup(timeout=args.timeout)

    if args.ip:
        result = whois.lookup_ip(args.ip)
        print(f"\n{'='*60}")
        print(f"IP WHOIS: {args.ip}")
        print(f"{'='*60}")
        print(f"  Network Name: {result.get('netname', 'N/A')}")
        print(f"  Net Range: {result.get('netrange', 'N/A')}")
        print(f"  Organization: {result.get('organization', 'N/A')}")
        print(f"  Country: {result.get('country', 'N/A')}")

        if args.raw:
            print(f"\n{'='*60}")
            print("Raw WHOIS Response")
            print(f"{'='*60}")
            print(result.get('raw', ''))
    else:
        result = whois.analyze_domain(args.domain)

        print(f"\n{'='*60}")
        print(f"Domain WHOIS: {args.domain}")
        print(f"{'='*60}")
        print(f"  Domain: {result.get('domain_name', 'N/A')}")
        print(f"  Registrar: {result.get('registrar', 'N/A')}")
        print(f"  Created: {result.get('creation_date', 'N/A')}")
        print(f"  Expires: {result.get('expiration_date', 'N/A')}")
        print(f"  Updated: {result.get('updated_date', 'N/A')}")

        if result.get('name_servers'):
            print(f"\n  Name Servers:")
            for ns in result['name_servers'][:5]:
                print(f"    - {ns}")

        if result.get('status'):
            print(f"\n  Status:")
            for status in result['status'][:5]:
                print(f"    - {status}")

        analysis = result.get('analysis', {})
        print(f"\n  Analysis:")
        print(f"    Domain Age: {analysis.get('domain_age_days', 'N/A')} days")
        print(f"    Privacy Protection: {'Yes' if analysis.get('has_privacy_protection') else 'No'}")
        print(f"    DNSSEC: {result.get('dnssec', 'N/A')}")

        if args.raw:
            print(f"\n{'='*60}")
            print("Raw WHOIS Response")
            print(f"{'='*60}")
            print(result.get('raw', '')[:3000])

    if args.output:
        whois.save_results(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
