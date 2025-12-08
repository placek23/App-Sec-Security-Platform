"""
Vulnerability Scanner Agent - Focused vulnerability assessment agent
Runs targeted scanning on provided URLs or discovered assets
"""
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.scanning import NucleiWrapper, Wafw00fWrapper, WhatwebWrapper
from wrappers.injection import SqlmapWrapper, DalfoxWrapper
from utils.reporter import Reporter, ReportConfig
from utils.output_parser import Severity


@dataclass
class ScanConfig:
    """Configuration for vulnerability scanner"""
    targets: List[str]
    scan_type: str = "full"  # full, quick, injection, nuclei
    severity: str = "low,medium,high,critical"
    nuclei_tags: str = None
    rate_limit: int = 50
    output_dir: str = None


class VulnScannerAgent:
    """
    Focused vulnerability scanner agent.
    
    Scan types:
    - full: WAF detection + nuclei + injection testing
    - quick: nuclei with high/critical only
    - injection: SQLi + XSS testing only
    - nuclei: nuclei templates only
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = Path(config.output_dir or 
                               f"./output/vulnscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize tools
        self.wafw00f = Wafw00fWrapper()
        self.nuclei = NucleiWrapper()
        self.whatweb = WhatwebWrapper()
        self.sqlmap = SqlmapWrapper()
        self.dalfox = DalfoxWrapper()
        
        # Results
        self.findings = []
        self.waf_detected = False
        self.waf_name = None
    
    def log(self, message: str, level: str = "INFO"):
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", "ERROR": "[-]"}.get(level, "[*]")
        print(f"{timestamp} {prefix} {message}")
    
    def detect_waf(self):
        """Detect WAF on first target"""
        if not self.config.targets:
            return
        
        target = self.config.targets[0]
        if not target.startswith('http'):
            target = f"https://{target}"
        
        self.log(f"Checking for WAF on {target}")
        result = self.wafw00f.run(target=target, all_wafs=True)
        
        waf_info = result.get("results", {})
        if waf_info.get("waf_detected"):
            self.waf_detected = True
            self.waf_name = waf_info.get("waf_name", "Unknown")
            self.log(f"WAF DETECTED: {self.waf_name}", "WARNING")
            self.log("Adjusting rate limits for WAF evasion", "INFO")
            self.config.rate_limit = min(self.config.rate_limit, 10)
        else:
            self.log("No WAF detected", "SUCCESS")
    
    def run_nuclei(self):
        """Run nuclei scanning"""
        self.log("Starting Nuclei vulnerability scan")
        
        # Save targets to file
        targets_file = self.output_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            for target in self.config.targets:
                if not target.startswith('http'):
                    target = f"https://{target}"
                f.write(f"{target}\n")
        
        result = self.nuclei.run(
            target="",
            list=str(targets_file),
            output_file=str(self.output_dir / "nuclei_results.json"),
            severity=self.config.severity,
            tags=self.config.nuclei_tags,
            rate_limit=self.config.rate_limit,
            json=True
        )
        
        vulns = result.get("results", [])
        self.findings.extend(vulns)
        
        self.log(f"Nuclei found {len(vulns)} vulnerabilities", "SUCCESS")
        return vulns
    
    def run_injection_tests(self):
        """Run SQL injection and XSS tests"""
        # Filter targets with parameters
        injectable = [t for t in self.config.targets if '?' in t]
        
        if not injectable:
            self.log("No URLs with parameters found for injection testing", "WARNING")
            return []
        
        self.log(f"Testing {len(injectable)} URLs for injection vulnerabilities")
        
        injection_findings = []
        
        # SQLi testing (limit to first 10)
        for url in injectable[:10]:
            self.log(f"SQLi testing: {url[:60]}...")
            result = self.sqlmap.run(
                target=url,
                batch=True,
                level=2,
                risk=2
            )
            findings = result.get("results", [])
            if findings:
                self.log(f"SQL INJECTION FOUND!", "WARNING")
                injection_findings.extend(findings)
        
        # XSS testing
        if injectable:
            # Save URLs for dalfox
            xss_file = self.output_dir / "xss_targets.txt"
            with open(xss_file, 'w') as f:
                f.write('\n'.join(injectable[:20]))
            
            self.log("XSS testing with Dalfox...")
            result = self.dalfox.run(
                target=str(xss_file),
                mode="file",
                file=str(xss_file),
                output_file=str(self.output_dir / "xss_results.json"),
                mining_all=True
            )
            
            xss_findings = result.get("results", [])
            if xss_findings:
                self.log(f"XSS VULNERABILITIES FOUND: {len(xss_findings)}", "WARNING")
                injection_findings.extend(xss_findings)
        
        self.findings.extend(injection_findings)
        return injection_findings
    
    def scan(self) -> Dict[str, Any]:
        """Execute the vulnerability scan"""
        start_time = datetime.now()
        
        print("\n" + "="*60)
        print(f"🔴 VULNERABILITY SCANNER - {self.config.scan_type.upper()} MODE")
        print("="*60)
        print(f"Targets: {len(self.config.targets)}")
        print(f"Severity: {self.config.severity}")
        print("="*60 + "\n")
        
        # Always detect WAF first
        self.detect_waf()
        
        # Run appropriate scans based on type
        if self.config.scan_type == "full":
            self.run_nuclei()
            self.run_injection_tests()
        
        elif self.config.scan_type == "quick":
            # Quick scan - high/critical nuclei only
            old_severity = self.config.severity
            self.config.severity = "high,critical"
            self.run_nuclei()
            self.config.severity = old_severity
        
        elif self.config.scan_type == "injection":
            self.run_injection_tests()
        
        elif self.config.scan_type == "nuclei":
            self.run_nuclei()
        
        # Generate report
        self._generate_report()
        
        # Summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.value if hasattr(f, 'severity') else f.get('severity', 'info')
            if hasattr(sev, 'value'):
                sev = sev.value
            severity_counts[sev.lower()] = severity_counts.get(sev.lower(), 0) + 1
        
        print("\n" + "="*60)
        print("🔴 SCAN COMPLETE")
        print("="*60)
        print(f"Duration: {duration:.1f} seconds")
        print(f"WAF Detected: {self.waf_name if self.waf_detected else 'No'}")
        print(f"\nFindings by Severity:")
        print(f"  Critical: {severity_counts['critical']}")
        print(f"  High: {severity_counts['high']}")
        print(f"  Medium: {severity_counts['medium']}")
        print(f"  Low: {severity_counts['low']}")
        print(f"  Info: {severity_counts['info']}")
        print(f"  TOTAL: {len(self.findings)}")
        print(f"\nOutput: {self.output_dir}")
        print("="*60 + "\n")
        
        return {
            "targets": len(self.config.targets),
            "findings": len(self.findings),
            "severity_counts": severity_counts,
            "waf_detected": self.waf_detected,
            "waf_name": self.waf_name,
            "duration": duration,
            "output_dir": str(self.output_dir)
        }
    
    def _generate_report(self):
        """Generate vulnerability report"""
        config = ReportConfig(
            title="Vulnerability Scan Report",
            target=", ".join(self.config.targets[:3]) + ("..." if len(self.config.targets) > 3 else ""),
            tester="VulnScanner Agent"
        )
        
        reporter = Reporter(config)
        
        for finding in self.findings:
            if hasattr(finding, 'to_dict'):
                reporter.add_findings([finding.to_dict()])
            else:
                reporter.add_findings([finding])
        
        reporter.add_metadata("waf_detected", self.waf_detected)
        reporter.add_metadata("waf_name", self.waf_name)
        reporter.add_metadata("scan_type", self.config.scan_type)
        
        reporter.generate_html(str(self.output_dir / "scan_report.html"))
        reporter.generate_json(str(self.output_dir / "scan_report.json"))


def main():
    parser = argparse.ArgumentParser(
        description="🔴 Vulnerability Scanner Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Types:
  full      - Complete scan (WAF + nuclei + injection tests)
  quick     - Fast scan (nuclei high/critical only)
  injection - Injection tests only (SQLi, XSS)
  nuclei    - Nuclei templates only

Examples:
  python vuln_scanner.py -t https://example.com
  python vuln_scanner.py -f urls.txt --type quick
  python vuln_scanner.py -t "https://example.com/page?id=1" --type injection
  python vuln_scanner.py -f targets.txt --type nuclei --tags cve,sqli
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Single target URL")
    target_group.add_argument("-f", "--file", help="File with target URLs")
    
    parser.add_argument("--type", dest="scan_type", default="full",
                       choices=["full", "quick", "injection", "nuclei"],
                       help="Scan type (default: full)")
    parser.add_argument("-s", "--severity", default="low,medium,high,critical",
                       help="Severity filter (default: all)")
    parser.add_argument("--tags", help="Nuclei template tags")
    parser.add_argument("-r", "--rate", type=int, default=50,
                       help="Rate limit (default: 50)")
    parser.add_argument("-o", "--output", help="Output directory")
    
    args = parser.parse_args()
    
    # Load targets
    if args.target:
        targets = [args.target]
    else:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    
    config = ScanConfig(
        targets=targets,
        scan_type=args.scan_type,
        severity=args.severity,
        nuclei_tags=args.tags,
        rate_limit=args.rate,
        output_dir=args.output
    )
    
    scanner = VulnScannerAgent(config)
    result = scanner.scan()
    
    return 0 if result["findings"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
