"""
Vulnerability Scanning Workflow
Runs: wafw00f → nuclei → whatweb
"""
import sys
import argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.scanning.wafw00f import Wafw00fWrapper
from wrappers.scanning.nuclei import NucleiWrapper
from wrappers.scanning.whatweb import WhatwebWrapper
from utils.reporter import Reporter, ReportConfig


class VulnScanWorkflow:
    """Vulnerability scanning workflow"""
    
    def __init__(self, target: str = None, urls_file: str = None, output_dir: str = None):
        self.target = target
        self.urls_file = urls_file
        self.output_dir = Path(output_dir or f"./output/vulnscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize wrappers
        self.wafw00f = Wafw00fWrapper()
        self.nuclei = NucleiWrapper()
        self.whatweb = WhatwebWrapper()
        
        # Results
        self.waf_info = {}
        self.vulnerabilities = []
        self.technologies = []
    
    def run_waf_detection(self):
        """Phase 1: WAF Detection"""
        print("\n" + "="*60)
        print("PHASE 1: WAF DETECTION")
        print("="*60)
        
        target = self.target or self._get_first_url()
        if not target:
            print("[-] No target specified")
            return {}
        
        if not target.startswith('http'):
            target = f"https://{target}"
        
        result = self.wafw00f.run(
            target=target,
            output_file=str(self.output_dir / "waf_detection.json"),
            all_wafs=True
        )
        
        self.waf_info = result.get("results", {})
        
        if self.waf_info.get("waf_detected"):
            print(f"\n[!] WAF DETECTED: {self.waf_info.get('waf_name', 'Unknown')}")
            print("[!] Adjusting scan parameters for WAF evasion...")
        else:
            print("\n[+] No WAF detected")
        
        return self.waf_info
    
    def run_nuclei_scan(self, severity: str = "low,medium,high,critical", tags: str = None):
        """Phase 2: Nuclei vulnerability scanning"""
        print("\n" + "="*60)
        print("PHASE 2: VULNERABILITY SCANNING (Nuclei)")
        print("="*60)
        
        # Determine rate limit based on WAF detection
        rate_limit = 50 if not self.waf_info.get("waf_detected") else 10
        
        if self.urls_file:
            result = self.nuclei.run(
                target="",
                list=self.urls_file,
                output_file=str(self.output_dir / "nuclei_results.json"),
                severity=severity,
                tags=tags,
                rate_limit=rate_limit,
                json=True
            )
        elif self.target:
            target = self.target if self.target.startswith('http') else f"https://{self.target}"
            result = self.nuclei.run(
                target=target,
                output_file=str(self.output_dir / "nuclei_results.json"),
                severity=severity,
                tags=tags,
                rate_limit=rate_limit,
                json=True
            )
        else:
            print("[-] No target or URLs file specified")
            return []
        
        self.vulnerabilities = result.get("results", [])
        
        # Summary by severity
        from collections import Counter
        if self.vulnerabilities:
            severities = Counter(v.severity.value for v in self.vulnerabilities)
            print(f"\n[+] Vulnerabilities found: {len(self.vulnerabilities)}")
            print(f"    Critical: {severities.get('critical', 0)}")
            print(f"    High: {severities.get('high', 0)}")
            print(f"    Medium: {severities.get('medium', 0)}")
            print(f"    Low: {severities.get('low', 0)}")
            print(f"    Info: {severities.get('info', 0)}")
        else:
            print("\n[+] No vulnerabilities detected")
        
        return self.vulnerabilities
    
    def run_tech_fingerprinting(self):
        """Phase 3: Technology fingerprinting"""
        print("\n" + "="*60)
        print("PHASE 3: TECHNOLOGY FINGERPRINTING")
        print("="*60)
        
        target = self.target or self._get_first_url()
        if not target:
            print("[-] No target specified")
            return []
        
        if not target.startswith('http'):
            target = f"https://{target}"
        
        result = self.whatweb.run(
            target=target,
            output_file=str(self.output_dir / "whatweb_results.json"),
            aggression=3
        )
        
        self.technologies = result.get("results", [])
        
        if self.technologies:
            print(f"\n[+] Technologies detected:")
            for tech in self.technologies:
                techs = tech.get('technologies', [])
                if techs:
                    print(f"    {', '.join(techs[:10])}")
        
        return self.technologies
    
    def _get_first_url(self):
        """Get first URL from urls file"""
        if self.urls_file and Path(self.urls_file).exists():
            with open(self.urls_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        return line
        return None
    
    def run_full(self, severity: str = "low,medium,high,critical", tags: str = None):
        """Run complete vulnerability scanning workflow"""
        print("\n" + "="*60)
        print(f"VULNERABILITY SCANNING WORKFLOW")
        print("="*60)
        
        start_time = datetime.now()
        
        # Phase 1: WAF Detection
        self.run_waf_detection()
        
        # Phase 2: Nuclei scanning
        self.run_nuclei_scan(severity=severity, tags=tags)
        
        # Phase 3: Tech fingerprinting
        self.run_tech_fingerprinting()
        
        # Generate report
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("\n" + "="*60)
        print("VULNERABILITY SCAN COMPLETE")
        print("="*60)
        print(f"Duration: {duration:.1f} seconds")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Output directory: {self.output_dir}")
        
        # Generate HTML report
        self._generate_report()
        
        return {
            "waf_info": self.waf_info,
            "vulnerabilities": self.vulnerabilities,
            "technologies": self.technologies,
            "duration": duration,
            "output_dir": str(self.output_dir)
        }
    
    def _generate_report(self):
        """Generate vulnerability report"""
        config = ReportConfig(
            title="Vulnerability Scan Report",
            target=self.target or self.urls_file,
            tester="AppSec Bounty Platform"
        )
        
        reporter = Reporter(config)
        
        # Add findings
        for vuln in self.vulnerabilities:
            reporter.add_findings([vuln.to_dict()])
        
        # Add metadata
        reporter.add_metadata("waf_detected", self.waf_info.get("waf_detected", False))
        reporter.add_metadata("waf_name", self.waf_info.get("waf_name"))
        reporter.add_metadata("technologies", self.technologies)
        
        # Generate report
        report_path = self.output_dir / "vulnerability_report.html"
        reporter.generate_html(str(report_path))


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanning Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vuln_scan.py --target example.com
  python vuln_scan.py --urls urls.txt --severity high,critical
  python vuln_scan.py --target example.com --tags cve,sqli,xss
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Target URL or domain")
    target_group.add_argument("-u", "--urls", dest="urls_file", help="File containing URLs")
    
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-s", "--severity", default="low,medium,high,critical", 
                       help="Severity filter (default: all)")
    parser.add_argument("--tags", help="Nuclei template tags (e.g., cve,sqli,xss)")
    parser.add_argument("--skip-waf", action="store_true", help="Skip WAF detection")
    parser.add_argument("--skip-tech", action="store_true", help="Skip technology fingerprinting")
    
    args = parser.parse_args()
    
    workflow = VulnScanWorkflow(
        target=args.target,
        urls_file=args.urls_file,
        output_dir=args.output
    )
    
    if args.skip_waf and args.skip_tech:
        # Only run nuclei
        workflow.run_nuclei_scan(severity=args.severity, tags=args.tags)
    elif args.skip_waf:
        workflow.run_nuclei_scan(severity=args.severity, tags=args.tags)
        workflow.run_tech_fingerprinting()
    elif args.skip_tech:
        workflow.run_waf_detection()
        workflow.run_nuclei_scan(severity=args.severity, tags=args.tags)
    else:
        workflow.run_full(severity=args.severity, tags=args.tags)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
