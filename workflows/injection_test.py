"""
Injection Testing Workflow
Runs: sqlmap → dalfox → commix → tplmap
"""
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.injection.sqlmap import SqlmapWrapper
from wrappers.injection.dalfox import DalfoxWrapper
from wrappers.injection.commix import CommixWrapper
from wrappers.injection.tplmap import TplmapWrapper
from utils.reporter import Reporter, ReportConfig
from utils.output_parser import Severity


class InjectionTestWorkflow:
    """Injection testing workflow for SQLi, XSS, Command Injection, and SSTI"""
    
    def __init__(self, target: str = None, urls_file: str = None, params_file: str = None, 
                 output_dir: str = None):
        self.target = target
        self.urls_file = urls_file
        self.params_file = params_file
        self.output_dir = Path(output_dir or f"./output/injection_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize wrappers
        self.sqlmap = SqlmapWrapper()
        self.dalfox = DalfoxWrapper()
        self.commix = CommixWrapper()
        self.tplmap = TplmapWrapper()
        
        # Results
        self.sqli_results = []
        self.xss_results = []
        self.cmdi_results = []
        self.ssti_results = []
        self.all_findings = []
    
    def _get_test_urls(self) -> List[str]:
        """Get URLs to test from file or single target"""
        urls = []
        
        if self.urls_file and Path(self.urls_file).exists():
            with open(self.urls_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and '?' in line]
        elif self.target:
            urls = [self.target]
        
        return urls
    
    def run_sqli_testing(self, level: int = 2, risk: int = 2):
        """Phase 1: SQL Injection testing with sqlmap"""
        print("\n" + "="*60)
        print("PHASE 1: SQL INJECTION TESTING")
        print("="*60)
        
        urls = self._get_test_urls()
        if not urls:
            print("[-] No URLs with parameters to test")
            return []
        
        print(f"[*] Testing {len(urls)} URLs for SQL injection")
        
        for i, url in enumerate(urls[:10], 1):  # Limit to 10 URLs
            print(f"\n[{i}/{min(len(urls), 10)}] Testing: {url[:80]}...")
            
            result = self.sqlmap.run(
                target=url,
                output_dir=str(self.output_dir / "sqlmap"),
                level=level,
                risk=risk,
                batch=True
            )
            
            findings = result.get("results", [])
            if findings:
                print(f"    [!] SQL INJECTION FOUND!")
                self.sqli_results.extend(findings)
                self.all_findings.extend(findings)
        
        print(f"\n[+] SQL Injection testing complete")
        print(f"    Vulnerabilities found: {len(self.sqli_results)}")
        
        return self.sqli_results
    
    def run_xss_testing(self):
        """Phase 2: XSS testing with dalfox"""
        print("\n" + "="*60)
        print("PHASE 2: XSS TESTING")
        print("="*60)
        
        if self.urls_file and Path(self.urls_file).exists():
            # Test multiple URLs from file
            result = self.dalfox.run(
                target=self.urls_file,
                mode="file",
                file=self.urls_file,
                output_file=str(self.output_dir / "dalfox_results.json"),
                json=True,
                mining_all=True,
                workers=20
            )
        elif self.target:
            result = self.dalfox.run(
                target=self.target,
                mode="url",
                output_file=str(self.output_dir / "dalfox_results.json"),
                json=True,
                mining_all=True
            )
        else:
            print("[-] No target specified for XSS testing")
            return []
        
        self.xss_results = result.get("results", [])
        self.all_findings.extend(self.xss_results)
        
        print(f"\n[+] XSS testing complete")
        print(f"    Vulnerabilities found: {len(self.xss_results)}")
        
        return self.xss_results
    
    def run_cmdi_testing(self, level: int = 2):
        """Phase 3: Command injection testing with commix"""
        print("\n" + "="*60)
        print("PHASE 3: COMMAND INJECTION TESTING")
        print("="*60)
        
        urls = self._get_test_urls()
        if not urls:
            print("[-] No URLs with parameters to test")
            return []
        
        # Filter URLs that might be vulnerable to command injection
        # (URLs with parameters that could take system commands)
        suspicious_params = ['cmd', 'exec', 'command', 'ping', 'query', 'jump', 'code', 
                           'reg', 'do', 'func', 'arg', 'option', 'load', 'process', 
                           'step', 'read', 'function', 'req', 'feature', 'exe', 
                           'module', 'payload', 'run', 'print', 'host', 'ip']
        
        cmdi_candidates = []
        for url in urls:
            url_lower = url.lower()
            if any(param in url_lower for param in suspicious_params):
                cmdi_candidates.append(url)
        
        if not cmdi_candidates:
            cmdi_candidates = urls[:5]  # Test first 5 if no obvious candidates
        
        print(f"[*] Testing {len(cmdi_candidates)} URLs for command injection")
        
        for i, url in enumerate(cmdi_candidates[:5], 1):  # Limit to 5
            print(f"\n[{i}/{min(len(cmdi_candidates), 5)}] Testing: {url[:80]}...")
            
            result = self.commix.run(
                target=url,
                output_dir=str(self.output_dir / "commix"),
                level=level,
                batch=True
            )
            
            findings = result.get("results", [])
            if findings:
                print(f"    [!] COMMAND INJECTION FOUND!")
                self.cmdi_results.extend(findings)
                self.all_findings.extend(findings)
        
        print(f"\n[+] Command injection testing complete")
        print(f"    Vulnerabilities found: {len(self.cmdi_results)}")
        
        return self.cmdi_results
    
    def run_ssti_testing(self, level: int = 2):
        """Phase 4: SSTI testing with tplmap"""
        print("\n" + "="*60)
        print("PHASE 4: SSTI TESTING")
        print("="*60)
        
        urls = self._get_test_urls()
        if not urls:
            print("[-] No URLs with parameters to test")
            return []
        
        # Filter URLs that might be vulnerable to SSTI
        # (URLs with template-related parameters)
        suspicious_params = ['template', 'page', 'id', 'name', 'render', 'view', 
                           'content', 'text', 'message', 'title', 'body', 'html',
                           'preview', 'email', 'subject']
        
        ssti_candidates = []
        for url in urls:
            url_lower = url.lower()
            if any(param in url_lower for param in suspicious_params):
                ssti_candidates.append(url)
        
        if not ssti_candidates:
            ssti_candidates = urls[:5]
        
        print(f"[*] Testing {len(ssti_candidates)} URLs for SSTI")
        
        for i, url in enumerate(ssti_candidates[:5], 1):  # Limit to 5
            print(f"\n[{i}/{min(len(ssti_candidates), 5)}] Testing: {url[:80]}...")
            
            result = self.tplmap.run(
                target=url,
                level=level
            )
            
            findings = result.get("results", [])
            if findings:
                print(f"    [!] SSTI FOUND!")
                self.ssti_results.extend(findings)
                self.all_findings.extend(findings)
        
        print(f"\n[+] SSTI testing complete")
        print(f"    Vulnerabilities found: {len(self.ssti_results)}")
        
        return self.ssti_results
    
    def run_full(self, sqli_level: int = 2, sqli_risk: int = 2, cmdi_level: int = 2):
        """Run complete injection testing workflow"""
        print("\n" + "="*60)
        print("INJECTION TESTING WORKFLOW")
        print("="*60)
        
        start_time = datetime.now()
        
        # Phase 1: SQL Injection
        self.run_sqli_testing(level=sqli_level, risk=sqli_risk)
        
        # Phase 2: XSS
        self.run_xss_testing()
        
        # Phase 3: Command Injection
        self.run_cmdi_testing(level=cmdi_level)
        
        # Phase 4: SSTI
        self.run_ssti_testing()
        
        # Summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("\n" + "="*60)
        print("INJECTION TESTING COMPLETE")
        print("="*60)
        print(f"Duration: {duration:.1f} seconds")
        print(f"\nResults:")
        print(f"  - SQL Injection: {len(self.sqli_results)}")
        print(f"  - XSS: {len(self.xss_results)}")
        print(f"  - Command Injection: {len(self.cmdi_results)}")
        print(f"  - SSTI: {len(self.ssti_results)}")
        print(f"  - TOTAL: {len(self.all_findings)}")
        print(f"\nOutput directory: {self.output_dir}")
        
        # Generate report
        self._generate_report()
        
        return {
            "sqli": self.sqli_results,
            "xss": self.xss_results,
            "cmdi": self.cmdi_results,
            "ssti": self.ssti_results,
            "all_findings": self.all_findings,
            "duration": duration,
            "output_dir": str(self.output_dir)
        }
    
    def _generate_report(self):
        """Generate injection testing report"""
        config = ReportConfig(
            title="Injection Testing Report",
            target=self.target or self.urls_file,
            tester="AppSec Bounty Platform"
        )
        
        reporter = Reporter(config)
        
        # Add all findings
        for finding in self.all_findings:
            if hasattr(finding, 'to_dict'):
                reporter.add_findings([finding.to_dict()])
            else:
                reporter.add_findings([finding])
        
        # Generate report
        report_path = self.output_dir / "injection_report.html"
        reporter.generate_html(str(report_path))


def main():
    parser = argparse.ArgumentParser(
        description="Injection Testing Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python injection_test.py --target "https://example.com/page?id=1"
  python injection_test.py --urls urls_with_params.txt
  python injection_test.py --target "https://example.com/search?q=test" --sqli-only
  python injection_test.py --urls params.txt --xss-only
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Target URL with parameter")
    target_group.add_argument("-u", "--urls", dest="urls_file", help="File containing URLs")
    
    parser.add_argument("-o", "--output", help="Output directory")
    
    # Test selection
    parser.add_argument("--sqli-only", action="store_true", help="Only run SQL injection tests")
    parser.add_argument("--xss-only", action="store_true", help="Only run XSS tests")
    parser.add_argument("--cmdi-only", action="store_true", help="Only run command injection tests")
    parser.add_argument("--ssti-only", action="store_true", help="Only run SSTI tests")
    
    # Test parameters
    parser.add_argument("--sqli-level", type=int, default=2, choices=[1, 2, 3, 4, 5],
                       help="SQLMap test level (default: 2)")
    parser.add_argument("--sqli-risk", type=int, default=2, choices=[1, 2, 3],
                       help="SQLMap risk level (default: 2)")
    
    args = parser.parse_args()
    
    workflow = InjectionTestWorkflow(
        target=args.target,
        urls_file=args.urls_file,
        output_dir=args.output
    )
    
    # Run selected tests
    if args.sqli_only:
        workflow.run_sqli_testing(level=args.sqli_level, risk=args.sqli_risk)
    elif args.xss_only:
        workflow.run_xss_testing()
    elif args.cmdi_only:
        workflow.run_cmdi_testing()
    elif args.ssti_only:
        workflow.run_ssti_testing()
    else:
        workflow.run_full(sqli_level=args.sqli_level, sqli_risk=args.sqli_risk)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
