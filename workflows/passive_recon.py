#!/usr/bin/env python3
"""
Passive Reconnaissance Workflow
Combines all passive OSINT tools for comprehensive reconnaissance
WITHOUT any direct target interaction
"""
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.passive.dns_enum import DNSEnumerator
from wrappers.passive.cert_transparency import CertTransparency
from wrappers.passive.whois_lookup import WhoisLookup
from wrappers.passive.wayback import WaybackMachine
from wrappers.passive.osint_search import OSINTSearch
from wrappers.passive.tech_fingerprint import TechFingerprinter


class PassiveReconWorkflow:
    """
    Comprehensive passive reconnaissance workflow.

    This workflow performs ONLY passive reconnaissance:
    - No direct connections to target servers (except tech fingerprinting)
    - No active scanning or probing
    - All data from public sources
    - Safe for pre-engagement research

    Tools combined:
    - DNS Enumeration (via public DNS servers)
    - Certificate Transparency logs
    - WHOIS lookups
    - Wayback Machine historical data
    - OSINT searches (Google/GitHub dorks)
    - Technology Fingerprinting (single request, like browser visit)
    """

    def __init__(self, domain: str, output_dir: str = None):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(output_dir or f"./output/passive_{self.timestamp}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.results = {
            'domain': domain,
            'timestamp': self.timestamp,
            'scan_type': 'PASSIVE - No direct target interaction',
            'dns': {},
            'certificates': {},
            'whois': {},
            'wayback': {},
            'osint': {},
            'technologies': {},
            'combined': {
                'all_subdomains': set(),
                'all_urls': set(),
                'all_parameters': set(),
                'email_patterns': [],
                'security_findings': [],
                'detected_technologies': []
            },
            'summary': {}
        }

    def run_dns_enumeration(self) -> Dict[str, Any]:
        """Run passive DNS enumeration."""
        print("\n" + "="*60)
        print("[1/6] DNS Enumeration (Passive)")
        print("="*60)

        enumerator = DNSEnumerator()
        dns_results = enumerator.full_enumeration(self.domain)

        self.results['dns'] = dns_results

        # Add subdomains to combined results
        for sub in dns_results.get('subdomains', []):
            self.results['combined']['all_subdomains'].add(sub)

        # Check for security issues
        security = dns_results.get('security', {})
        if not security.get('spf'):
            self.results['combined']['security_findings'].append({
                'type': 'missing_spf',
                'severity': 'medium',
                'description': 'No SPF record found - email spoofing possible'
            })
        if not security.get('dmarc'):
            self.results['combined']['security_findings'].append({
                'type': 'missing_dmarc',
                'severity': 'medium',
                'description': 'No DMARC record found - email security weakened'
            })

        # Save intermediate results
        enumerator.save_results(str(self.output_dir / 'dns_results.json'))

        return dns_results

    def run_certificate_transparency(self) -> Dict[str, Any]:
        """Run Certificate Transparency log analysis."""
        print("\n" + "="*60)
        print("[2/6] Certificate Transparency Analysis")
        print("="*60)

        ct = CertTransparency()
        ct_results = ct.full_analysis(self.domain)

        self.results['certificates'] = ct_results

        # Add subdomains to combined results
        for sub in ct_results.get('subdomains', []):
            self.results['combined']['all_subdomains'].add(sub)

        # Check for expiring certificates
        expiring = ct_results.get('expiring_soon', [])
        if expiring:
            self.results['combined']['security_findings'].append({
                'type': 'expiring_certificates',
                'severity': 'info',
                'description': f'{len(expiring)} certificates expiring within 30 days',
                'details': expiring[:5]
            })

        # Save intermediate results
        ct.save_results(str(self.output_dir / 'cert_results.json'))
        ct.save_subdomains(str(self.output_dir / 'ct_subdomains.txt'))

        return ct_results

    def run_whois_lookup(self) -> Dict[str, Any]:
        """Run WHOIS lookup."""
        print("\n" + "="*60)
        print("[3/6] WHOIS Lookup")
        print("="*60)

        whois = WhoisLookup()
        whois_results = whois.analyze_domain(self.domain)

        self.results['whois'] = whois_results

        # Check for WHOIS findings
        analysis = whois_results.get('analysis', {})
        domain_age = analysis.get('domain_age_days')
        if domain_age and domain_age < 365:
            self.results['combined']['security_findings'].append({
                'type': 'new_domain',
                'severity': 'info',
                'description': f'Domain is relatively new ({domain_age} days old)'
            })

        # Save intermediate results
        whois.save_results(str(self.output_dir / 'whois_results.json'))

        return whois_results

    def run_wayback_analysis(self, limit: int = 5000) -> Dict[str, Any]:
        """Run Wayback Machine analysis."""
        print("\n" + "="*60)
        print("[4/6] Wayback Machine Analysis")
        print("="*60)

        wayback = WaybackMachine()
        wayback_results = wayback.full_analysis(self.domain, limit)

        self.results['wayback'] = wayback_results

        # Add URLs and parameters to combined results
        for url in wayback_results.get('urls', []):
            self.results['combined']['all_urls'].add(url)

        for param in wayback_results.get('parameters', []):
            self.results['combined']['all_parameters'].add(param)

        # Add subdomains
        for sub in wayback_results.get('subdomains', []):
            self.results['combined']['all_subdomains'].add(sub)

        # Check for interesting files
        files = wayback_results.get('files', {})
        for category in ['backup', 'config', 'source']:
            if files.get(category):
                self.results['combined']['security_findings'].append({
                    'type': f'archived_{category}_files',
                    'severity': 'medium' if category != 'source' else 'high',
                    'description': f'Found {len(files[category])} archived {category} files',
                    'samples': files[category][:5]
                })

        # Save intermediate results
        wayback.save_results(str(self.output_dir / 'wayback_results.json'))
        wayback.save_urls(str(self.output_dir / 'wayback_urls.txt'))

        return wayback_results

    def run_osint_search(self) -> Dict[str, Any]:
        """Run OSINT search and dork generation."""
        print("\n" + "="*60)
        print("[5/6] OSINT Search & Dork Generation")
        print("="*60)

        osint = OSINTSearch()
        osint_results = osint.full_osint(self.domain)

        self.results['osint'] = osint_results
        self.results['combined']['email_patterns'] = osint_results.get('email_patterns', [])

        # Save intermediate results
        osint.save_results(str(self.output_dir / 'osint_results.json'))
        osint.save_dorks(str(self.output_dir / 'google_dorks.txt'), 'google')
        osint.save_dorks(str(self.output_dir / 'github_dorks.txt'), 'github')

        return osint_results

    def run_tech_fingerprinting(self, target_url: str = None) -> Dict[str, Any]:
        """Run technology fingerprinting on the main domain.

        This makes a single HTTP request (like a browser visit) to detect:
        - Web servers and frameworks
        - JavaScript libraries and frameworks
        - CMS and e-commerce platforms
        - Analytics and tracking
        - CDN and security services
        """
        print("\n" + "="*60)
        print("[6/6] Technology Fingerprinting")
        print("="*60)

        # Default to HTTPS on the main domain
        if target_url is None:
            target_url = f"https://{self.domain}"

        fingerprinter = TechFingerprinter()
        tech_results = fingerprinter.fingerprint(target_url)

        self.results['technologies'] = tech_results

        # Add detected technologies to combined results
        tech_list = fingerprinter.get_tech_list()
        self.results['combined']['detected_technologies'] = tech_list

        # Add security-relevant findings
        security_findings = fingerprinter.get_security_relevant()
        for finding in security_findings:
            self.results['combined']['security_findings'].append({
                'type': 'technology',
                'severity': finding.get('severity', 'info'),
                'description': finding.get('note', ''),
                'technology': finding.get('technology', '')
            })

        # Save intermediate results
        fingerprinter.save_results(str(self.output_dir / 'tech_fingerprint.json'))

        return tech_results

    def generate_summary(self) -> Dict[str, Any]:
        """Generate workflow summary."""
        summary = {
            'domain': self.domain,
            'scan_time': self.timestamp,
            'scan_type': 'PASSIVE',
            'statistics': {
                'total_subdomains': len(self.results['combined']['all_subdomains']),
                'total_urls': len(self.results['combined']['all_urls']),
                'total_parameters': len(self.results['combined']['all_parameters']),
                'technologies_detected': len(self.results['combined']['detected_technologies']),
                'security_findings': len(self.results['combined']['security_findings']),
            },
            'detected_technologies': self.results['combined']['detected_technologies'],
            'top_findings': self.results['combined']['security_findings'][:10]
        }

        self.results['summary'] = summary
        return summary

    def save_combined_results(self):
        """Save all combined results."""
        # Convert sets to lists for JSON serialization
        combined = {
            'all_subdomains': sorted(list(self.results['combined']['all_subdomains'])),
            'all_urls': sorted(list(self.results['combined']['all_urls']))[:1000],  # Limit for readability
            'all_parameters': sorted(list(self.results['combined']['all_parameters'])),
            'email_patterns': self.results['combined']['email_patterns'],
            'security_findings': self.results['combined']['security_findings']
        }

        # Save combined subdomains
        with open(self.output_dir / 'all_subdomains.txt', 'w') as f:
            f.write('\n'.join(combined['all_subdomains']))

        # Save combined parameters
        with open(self.output_dir / 'all_parameters.txt', 'w') as f:
            f.write('\n'.join(combined['all_parameters']))

        # Save full results
        self.results['combined'] = combined
        with open(self.output_dir / 'full_results.json', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        print(f"\n[+] All results saved to {self.output_dir}/")

    def run_full_recon(self, skip_wayback: bool = False, skip_fingerprint: bool = False) -> Dict[str, Any]:
        """Run the complete passive reconnaissance workflow.

        Args:
            skip_wayback: Skip Wayback Machine analysis
            skip_fingerprint: Skip technology fingerprinting (single request to target)
        """
        print("\n" + "#"*60)
        print("#" + " "*58 + "#")
        print("#    PASSIVE RECONNAISSANCE WORKFLOW" + " "*21 + "#")
        print("#    Target: " + self.domain[:44].ljust(44) + " #")
        print("#    Mode: PASSIVE - No direct target interaction" + " "*8 + "#")
        print("#" + " "*58 + "#")
        print("#"*60)

        # Run all passive tools
        self.run_dns_enumeration()
        self.run_certificate_transparency()
        self.run_whois_lookup()

        if not skip_wayback:
            self.run_wayback_analysis()
        else:
            print("\n[*] Skipping Wayback Machine analysis")

        self.run_osint_search()

        if not skip_fingerprint:
            self.run_tech_fingerprinting()
        else:
            print("\n[*] Skipping technology fingerprinting")

        # Generate summary
        summary = self.generate_summary()

        # Save all results
        self.save_combined_results()

        # Print final summary
        print("\n" + "="*60)
        print("PASSIVE RECONNAISSANCE COMPLETE")
        print("="*60)
        print(f"\n  Target: {self.domain}")
        print(f"  Scan Type: PASSIVE (Minimal target interaction)")
        print(f"\n  Results:")
        print(f"    Subdomains discovered: {summary['statistics']['total_subdomains']}")
        print(f"    Historical URLs found: {summary['statistics']['total_urls']}")
        print(f"    Parameters identified: {summary['statistics']['total_parameters']}")
        print(f"    Technologies detected: {summary['statistics']['technologies_detected']}")
        print(f"    Security findings: {summary['statistics']['security_findings']}")

        if summary.get('detected_technologies'):
            print(f"\n  Detected Technologies:")
            for tech in summary['detected_technologies'][:10]:
                print(f"    - {tech}")
            if len(summary['detected_technologies']) > 10:
                print(f"    ... and {len(summary['detected_technologies']) - 10} more")

        if summary['top_findings']:
            print(f"\n  Top Findings:")
            for finding in summary['top_findings'][:5]:
                print(f"    [{finding['severity'].upper()}] {finding['description']}")

        print(f"\n  Output Directory: {self.output_dir}")
        print(f"\n  Files Generated:")
        for f in sorted(self.output_dir.glob('*')):
            size = f.stat().st_size
            size_str = f"{size/1024:.1f}KB" if size < 1024*1024 else f"{size/(1024*1024):.1f}MB"
            print(f"    - {f.name} ({size_str})")

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="Passive Reconnaissance Workflow - Minimal Target Interaction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This workflow performs passive reconnaissance:
  - DNS enumeration via public DNS servers
  - Certificate Transparency log analysis
  - WHOIS lookups via public databases
  - Wayback Machine historical data
  - OSINT searches and dork generation
  - Technology fingerprinting (single request)

Only technology fingerprinting makes a direct request to the target.

Examples:
  python passive_recon.py -d example.com
  python passive_recon.py -d example.com -o ./recon_output
  python passive_recon.py -d example.com --skip-wayback
  python passive_recon.py -d example.com --skip-fingerprint
  python passive_recon.py -d example.com -u https://example.com/app
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-u", "--url", help="Specific URL for tech fingerprinting (default: https://domain)")
    parser.add_argument("--skip-wayback", action="store_true",
                        help="Skip Wayback Machine analysis (faster)")
    parser.add_argument("--skip-fingerprint", action="store_true",
                        help="Skip technology fingerprinting (fully passive)")

    args = parser.parse_args()

    workflow = PassiveReconWorkflow(args.domain, args.output)

    # Run with optional URL for fingerprinting
    if args.url and not args.skip_fingerprint:
        workflow.run_dns_enumeration()
        workflow.run_certificate_transparency()
        workflow.run_whois_lookup()
        if not args.skip_wayback:
            workflow.run_wayback_analysis()
        workflow.run_osint_search()
        workflow.run_tech_fingerprinting(target_url=args.url)
        workflow.generate_summary()
        workflow.save_combined_results()
    else:
        workflow.run_full_recon(
            skip_wayback=args.skip_wayback,
            skip_fingerprint=args.skip_fingerprint
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
