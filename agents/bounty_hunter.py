"""
Bounty Hunter Agent - Autonomous bug bounty hunting agent
Orchestrates the full security assessment pipeline automatically
"""
import sys
import argparse
import json
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

sys.path.insert(0, str(Path(__file__).parent.parent))

from workflows.full_recon import FullReconWorkflow
from workflows.vuln_scan import VulnScanWorkflow
from workflows.injection_test import InjectionTestWorkflow
from wrappers.auth.subjack import SubjackWrapper
from wrappers.auth.jwt_tool import JwtToolWrapper
from wrappers.api.testssl import TestsslWrapper
from utils.reporter import Reporter, ReportConfig
from utils.output_parser import Severity


class AgentPhase(Enum):
    RECON = "reconnaissance"
    DISCOVERY = "content_discovery"
    SCANNING = "vulnerability_scanning"
    INJECTION = "injection_testing"
    AUTH = "auth_testing"
    REPORTING = "report_generation"


@dataclass
class AgentConfig:
    """Configuration for the bounty hunter agent"""
    target: str
    scope: List[str] = None
    out_of_scope: List[str] = None
    severity_threshold: str = "medium"  # Report only findings >= this severity
    auto_exploit: bool = False  # Whether to attempt exploitation
    max_time: int = 3600  # Maximum runtime in seconds
    parallel: bool = True
    output_dir: str = None
    
    def __post_init__(self):
        if self.scope is None:
            self.scope = [f"*.{self.target}"]
        if self.out_of_scope is None:
            self.out_of_scope = []


class BountyHunterAgent:
    """
    Autonomous bug bounty hunting agent.
    
    Orchestrates the complete security assessment pipeline:
    1. Reconnaissance (subdomain enumeration, probing, crawling)
    2. Vulnerability Scanning (WAF detection, nuclei, tech fingerprinting)
    3. Injection Testing (SQLi, XSS, Command Injection, SSTI)
    4. Auth & API Testing (JWT, subdomain takeover, SSL/TLS)
    5. Report Generation
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.output_dir = Path(config.output_dir or 
                               f"./output/bounty_{config.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # State
        self.current_phase = None
        self.start_time = None
        self.findings = []
        self.subdomains = []
        self.live_hosts = []
        self.endpoints = []
        self.urls_with_params = []
        
        # Phase results
        self.recon_results = {}
        self.scan_results = {}
        self.injection_results = {}
        self.auth_results = {}
        
        # Stats
        self.stats = {
            "phases_completed": [],
            "total_subdomains": 0,
            "total_live_hosts": 0,
            "total_endpoints": 0,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
    
    def log(self, message: str, level: str = "INFO"):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", "ERROR": "[-]"}.get(level, "[*]")
        print(f"{timestamp} {prefix} {message}")
    
    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within scope"""
        if not self.config.scope:
            return True
        
        # Check out of scope first
        for pattern in self.config.out_of_scope:
            if pattern.startswith("*."):
                if target.endswith(pattern[1:]):
                    return False
            elif target == pattern or target.endswith(f".{pattern}"):
                return False
        
        # Check in scope
        for pattern in self.config.scope:
            if pattern.startswith("*."):
                if target.endswith(pattern[1:]):
                    return True
            elif target == pattern or target.endswith(f".{pattern}"):
                return True
        
        return False
    
    def filter_by_severity(self, findings: List[Any]) -> List[Any]:
        """Filter findings by severity threshold"""
        severity_order = ["critical", "high", "medium", "low", "info"]
        threshold_idx = severity_order.index(self.config.severity_threshold.lower())
        
        filtered = []
        for finding in findings:
            sev = finding.severity.value if hasattr(finding, 'severity') else finding.get('severity', 'info')
            if isinstance(sev, Enum):
                sev = sev.value
            
            if severity_order.index(sev.lower()) <= threshold_idx:
                filtered.append(finding)
        
        return filtered
    
    def check_timeout(self) -> bool:
        """Check if maximum runtime has been exceeded"""
        if self.start_time is None:
            return False
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return elapsed >= self.config.max_time
    
    def run_phase_recon(self):
        """Phase 1: Reconnaissance"""
        self.current_phase = AgentPhase.RECON
        self.log("Starting RECONNAISSANCE phase", "INFO")
        
        recon = FullReconWorkflow(
            target=self.config.target,
            output_dir=str(self.output_dir / "recon"),
            parallel=self.config.parallel
        )
        
        self.recon_results = recon.run_full()
        
        # Filter results by scope
        self.subdomains = [s for s in self.recon_results.get("subdomains", []) 
                         if self.is_in_scope(s)]
        self.live_hosts = self.recon_results.get("live_hosts", [])
        self.endpoints = self.recon_results.get("endpoints", [])
        
        # Extract URLs with parameters for injection testing
        urls = self.recon_results.get("urls", [])
        self.urls_with_params = [u.url if hasattr(u, 'url') else u 
                                for u in urls 
                                if (hasattr(u, 'parameters') and u.parameters) or '?' in str(u)]
        
        # Update stats
        self.stats["total_subdomains"] = len(self.subdomains)
        self.stats["total_live_hosts"] = len(self.live_hosts)
        self.stats["total_endpoints"] = len(self.endpoints)
        self.stats["phases_completed"].append("recon")
        
        self.log(f"Reconnaissance complete: {len(self.subdomains)} subdomains, "
                f"{len(self.live_hosts)} live hosts", "SUCCESS")
    
    def run_phase_scanning(self):
        """Phase 2: Vulnerability Scanning"""
        if self.check_timeout():
            self.log("Timeout reached, skipping scanning phase", "WARNING")
            return
        
        self.current_phase = AgentPhase.SCANNING
        self.log("Starting VULNERABILITY SCANNING phase", "INFO")
        
        # Save live hosts to file for scanning
        live_hosts_file = self.output_dir / "live_hosts.txt"
        with open(live_hosts_file, 'w') as f:
            for host in self.live_hosts:
                domain = host.domain if hasattr(host, 'domain') else host
                if not domain.startswith('http'):
                    domain = f"https://{domain}"
                f.write(f"{domain}\n")
        
        scanner = VulnScanWorkflow(
            urls_file=str(live_hosts_file),
            output_dir=str(self.output_dir / "scanning")
        )
        
        self.scan_results = scanner.run_full(
            severity=self.config.severity_threshold + ",high,critical"
        )
        
        # Add findings
        vulns = self.scan_results.get("vulnerabilities", [])
        filtered_vulns = self.filter_by_severity(vulns)
        self.findings.extend(filtered_vulns)
        
        self.stats["phases_completed"].append("scanning")
        self.log(f"Scanning complete: {len(filtered_vulns)} vulnerabilities found", "SUCCESS")
    
    def run_phase_injection(self):
        """Phase 3: Injection Testing"""
        if self.check_timeout():
            self.log("Timeout reached, skipping injection phase", "WARNING")
            return
        
        if not self.urls_with_params:
            self.log("No URLs with parameters found, skipping injection testing", "WARNING")
            return
        
        self.current_phase = AgentPhase.INJECTION
        self.log("Starting INJECTION TESTING phase", "INFO")
        
        # Save URLs with params for testing
        params_file = self.output_dir / "urls_with_params.txt"
        with open(params_file, 'w') as f:
            f.write('\n'.join(self.urls_with_params[:50]))  # Limit to 50 URLs
        
        injector = InjectionTestWorkflow(
            urls_file=str(params_file),
            output_dir=str(self.output_dir / "injection")
        )
        
        self.injection_results = injector.run_full()
        
        # Add findings
        all_injection_findings = self.injection_results.get("all_findings", [])
        filtered_findings = self.filter_by_severity(all_injection_findings)
        self.findings.extend(filtered_findings)
        
        self.stats["phases_completed"].append("injection")
        self.log(f"Injection testing complete: {len(filtered_findings)} vulnerabilities found", "SUCCESS")
    
    def run_phase_auth(self):
        """Phase 4: Auth & API Testing"""
        if self.check_timeout():
            self.log("Timeout reached, skipping auth phase", "WARNING")
            return
        
        self.current_phase = AgentPhase.AUTH
        self.log("Starting AUTH & API TESTING phase", "INFO")
        
        auth_findings = []
        
        # Subdomain takeover check
        if self.subdomains:
            self.log("Checking for subdomain takeover vulnerabilities...")
            
            subs_file = self.output_dir / "subdomains.txt"
            with open(subs_file, 'w') as f:
                f.write('\n'.join(self.subdomains))
            
            subjack = SubjackWrapper()
            result = subjack.run(
                target="",
                list=str(subs_file),
                output_file=str(self.output_dir / "auth" / "subjack.json")
            )
            
            takeover_findings = result.get("results", [])
            auth_findings.extend(takeover_findings)
        
        # SSL/TLS testing on main target
        self.log("Testing SSL/TLS configuration...")
        testssl = TestsslWrapper()
        result = testssl.run(
            target=self.config.target,
            output_file=str(self.output_dir / "auth" / "testssl.json"),
            vulnerabilities=True
        )
        
        ssl_findings = result.get("results", [])
        auth_findings.extend(ssl_findings)
        
        self.auth_results = {"findings": auth_findings}
        
        # Add findings
        filtered_findings = self.filter_by_severity(auth_findings)
        self.findings.extend(filtered_findings)
        
        self.stats["phases_completed"].append("auth")
        self.log(f"Auth testing complete: {len(filtered_findings)} issues found", "SUCCESS")
    
    def run_phase_reporting(self):
        """Phase 5: Report Generation"""
        self.current_phase = AgentPhase.REPORTING
        self.log("Generating final report...", "INFO")
        
        # Count findings by severity
        for finding in self.findings:
            sev = finding.severity.value if hasattr(finding, 'severity') else finding.get('severity', 'info')
            if isinstance(sev, Enum):
                sev = sev.value
            sev = sev.lower()
            
            if sev in self.stats:
                self.stats[sev] += 1
        
        self.stats["total_findings"] = len(self.findings)
        
        # Generate HTML report
        config = ReportConfig(
            title=f"Bug Bounty Report - {self.config.target}",
            target=self.config.target,
            tester="AppSec Bounty Hunter Agent"
        )
        
        reporter = Reporter(config)
        
        # Add all findings
        for finding in self.findings:
            if hasattr(finding, 'to_dict'):
                reporter.add_findings([finding.to_dict()])
            else:
                reporter.add_findings([finding])
        
        # Add discovered assets
        for sub in self.subdomains[:100]:
            reporter.add_subdomains([{"domain": sub, "source": "recon"}])
        
        for ep in self.endpoints[:100]:
            url = ep.url if hasattr(ep, 'url') else ep
            reporter.add_endpoints([{"url": url}])
        
        # Generate reports
        reporter.generate_html(str(self.output_dir / "bounty_report.html"))
        reporter.generate_json(str(self.output_dir / "bounty_report.json"))
        reporter.generate_markdown(str(self.output_dir / "bounty_report.md"))
        
        self.stats["phases_completed"].append("reporting")
        self.log("Report generated successfully", "SUCCESS")
    
    def hunt(self):
        """
        Execute the full bug bounty hunting workflow.
        Returns a summary of findings.
        """
        self.start_time = datetime.now()
        
        print("\n" + "="*70)
        print(f"🎯 BOUNTY HUNTER AGENT - {self.config.target}")
        print("="*70)
        print(f"Scope: {', '.join(self.config.scope)}")
        print(f"Out of scope: {', '.join(self.config.out_of_scope) or 'None'}")
        print(f"Severity threshold: {self.config.severity_threshold}")
        print(f"Max runtime: {self.config.max_time} seconds")
        print("="*70 + "\n")
        
        try:
            # Phase 1: Reconnaissance
            self.run_phase_recon()
            
            # Phase 2: Vulnerability Scanning
            self.run_phase_scanning()
            
            # Phase 3: Injection Testing
            self.run_phase_injection()
            
            # Phase 4: Auth & API Testing
            self.run_phase_auth()
            
            # Phase 5: Report Generation
            self.run_phase_reporting()
            
        except KeyboardInterrupt:
            self.log("Hunt interrupted by user", "WARNING")
            self.run_phase_reporting()  # Generate partial report
        except Exception as e:
            self.log(f"Error during hunt: {e}", "ERROR")
            raise
        
        # Final summary
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        print("\n" + "="*70)
        print("🏆 HUNT COMPLETE")
        print("="*70)
        print(f"Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
        print(f"\n📊 STATISTICS:")
        print(f"   Subdomains discovered: {self.stats['total_subdomains']}")
        print(f"   Live hosts found: {self.stats['total_live_hosts']}")
        print(f"   Endpoints crawled: {self.stats['total_endpoints']}")
        print(f"\n🔴 FINDINGS BY SEVERITY:")
        print(f"   Critical: {self.stats['critical']}")
        print(f"   High: {self.stats['high']}")
        print(f"   Medium: {self.stats['medium']}")
        print(f"   Low: {self.stats['low']}")
        print(f"   Info: {self.stats['info']}")
        print(f"   TOTAL: {self.stats['total_findings']}")
        print(f"\n📁 Output directory: {self.output_dir}")
        print(f"📄 Report: {self.output_dir / 'bounty_report.html'}")
        print("="*70 + "\n")
        
        # Save summary
        summary = {
            "target": self.config.target,
            "scope": self.config.scope,
            "duration_seconds": duration,
            "stats": self.stats,
            "output_dir": str(self.output_dir),
            "timestamp": datetime.now().isoformat()
        }
        
        with open(self.output_dir / "hunt_summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary


def main():
    parser = argparse.ArgumentParser(
        description="🎯 Bounty Hunter Agent - Autonomous bug bounty hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bounty_hunter.py --target example.com
  python bounty_hunter.py --target example.com --scope "*.example.com"
  python bounty_hunter.py --target example.com --severity high --max-time 1800
  python bounty_hunter.py --target example.com --out-of-scope "admin.example.com,api.example.com"
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-s", "--scope", action="append", help="In-scope patterns (can be multiple)")
    parser.add_argument("--out-of-scope", action="append", dest="out_of_scope", 
                       help="Out-of-scope patterns (can be multiple)")
    parser.add_argument("--severity", default="medium", 
                       choices=["critical", "high", "medium", "low", "info"],
                       help="Minimum severity to report (default: medium)")
    parser.add_argument("--max-time", type=int, default=3600,
                       help="Maximum runtime in seconds (default: 3600)")
    parser.add_argument("--no-parallel", action="store_true", help="Disable parallel execution")
    parser.add_argument("-o", "--output", help="Output directory")
    
    args = parser.parse_args()
    
    config = AgentConfig(
        target=args.target,
        scope=args.scope,
        out_of_scope=args.out_of_scope,
        severity_threshold=args.severity,
        max_time=args.max_time,
        parallel=not args.no_parallel,
        output_dir=args.output
    )
    
    agent = BountyHunterAgent(config)
    
    try:
        summary = agent.hunt()
        return 0 if summary["stats"]["total_findings"] == 0 else 1
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
