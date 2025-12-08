"""
Full Reconnaissance Workflow
Runs complete reconnaissance pipeline: subfinder → amass → httpx → katana → gau
"""
import sys
import argparse
import asyncio
import concurrent.futures
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.recon.subfinder import SubfinderWrapper
from wrappers.recon.amass import AmassWrapper
from wrappers.recon.httpx import HttpxWrapper
from wrappers.recon.katana import KatanaWrapper
from wrappers.recon.gau import GauWrapper
from utils.output_parser import OutputParser
from utils.reporter import Reporter, ReportConfig


class FullReconWorkflow:
    """Complete reconnaissance workflow"""
    
    def __init__(self, target: str, output_dir: str = None, parallel: bool = True):
        self.target = target
        self.output_dir = Path(output_dir or f"./output/recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.parallel = parallel
        
        # Initialize wrappers
        self.subfinder = SubfinderWrapper()
        self.amass = AmassWrapper()
        self.httpx = HttpxWrapper()
        self.katana = KatanaWrapper()
        self.gau = GauWrapper()
        
        # Results storage
        self.subdomains = []
        self.live_hosts = []
        self.endpoints = []
        self.urls = []
    
    def run_subdomain_discovery(self):
        """Phase 1: Subdomain discovery with subfinder and amass"""
        print("\n" + "="*60)
        print("PHASE 1: SUBDOMAIN DISCOVERY")
        print("="*60)
        
        all_subdomains = set()
        
        if self.parallel:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = {
                    executor.submit(self._run_subfinder): "subfinder",
                    executor.submit(self._run_amass): "amass"
                }
                
                for future in concurrent.futures.as_completed(futures):
                    tool = futures[future]
                    try:
                        results = future.result()
                        for sub in results:
                            all_subdomains.add(sub.domain if hasattr(sub, 'domain') else sub)
                        print(f"[+] {tool}: Found {len(results)} subdomains")
                    except Exception as e:
                        print(f"[-] {tool} failed: {e}")
        else:
            # Sequential execution
            subfinder_results = self._run_subfinder()
            amass_results = self._run_amass()
            
            for sub in subfinder_results + amass_results:
                all_subdomains.add(sub.domain if hasattr(sub, 'domain') else sub)
        
        self.subdomains = list(all_subdomains)
        
        # Save subdomains to file
        subdomains_file = self.output_dir / "subdomains.txt"
        with open(subdomains_file, 'w') as f:
            f.write('\n'.join(sorted(self.subdomains)))
        
        print(f"\n[+] Total unique subdomains: {len(self.subdomains)}")
        print(f"[+] Saved to: {subdomains_file}")
        
        return self.subdomains
    
    def _run_subfinder(self):
        """Run subfinder"""
        result = self.subfinder.run(
            target=self.target,
            output_file=str(self.output_dir / "subfinder_raw.txt"),
            all_sources=True
        )
        return result.get("results", [])
    
    def _run_amass(self):
        """Run amass"""
        result = self.amass.run(
            target=self.target,
            output_file=str(self.output_dir / "amass_raw.txt"),
            passive=True
        )
        return result.get("results", [])
    
    def run_http_probing(self):
        """Phase 2: HTTP probing with httpx"""
        print("\n" + "="*60)
        print("PHASE 2: HTTP PROBING")
        print("="*60)
        
        if not self.subdomains:
            print("[-] No subdomains to probe. Run subdomain discovery first.")
            return []
        
        # Create input file for httpx
        input_file = self.output_dir / "subdomains.txt"
        
        result = self.httpx.run(
            target="",
            list=str(input_file),
            output_file=str(self.output_dir / "live_hosts.json"),
            status_code=True,
            title=True,
            tech_detect=True
        )
        
        self.live_hosts = result.get("results", [])
        
        # Save live hosts
        live_file = self.output_dir / "live_hosts.txt"
        with open(live_file, 'w') as f:
            for host in self.live_hosts:
                domain = host.domain if hasattr(host, 'domain') else host
                f.write(f"{domain}\n")
        
        print(f"\n[+] Live hosts: {len(self.live_hosts)}")
        print(f"[+] Saved to: {live_file}")
        
        return self.live_hosts
    
    def run_crawling(self):
        """Phase 3: Web crawling with katana"""
        print("\n" + "="*60)
        print("PHASE 3: WEB CRAWLING")
        print("="*60)
        
        if not self.live_hosts:
            print("[-] No live hosts to crawl. Run HTTP probing first.")
            return []
        
        all_endpoints = set()
        
        # Crawl top live hosts (limit to prevent long runs)
        hosts_to_crawl = self.live_hosts[:20] if len(self.live_hosts) > 20 else self.live_hosts
        
        for host in hosts_to_crawl:
            domain = host.domain if hasattr(host, 'domain') else host
            if not domain.startswith('http'):
                domain = f"https://{domain}"
            
            print(f"[*] Crawling: {domain}")
            result = self.katana.run(
                target=domain,
                depth=2,
                js_crawl=True
            )
            
            for ep in result.get("results", []):
                url = ep.url if hasattr(ep, 'url') else ep
                all_endpoints.add(url)
        
        self.endpoints = list(all_endpoints)
        
        # Save endpoints
        endpoints_file = self.output_dir / "endpoints.txt"
        with open(endpoints_file, 'w') as f:
            f.write('\n'.join(sorted(self.endpoints)))
        
        print(f"\n[+] Discovered endpoints: {len(self.endpoints)}")
        print(f"[+] Saved to: {endpoints_file}")
        
        return self.endpoints
    
    def run_url_harvesting(self):
        """Phase 4: URL harvesting with gau"""
        print("\n" + "="*60)
        print("PHASE 4: URL HARVESTING (Archive)")
        print("="*60)
        
        result = self.gau.run(
            target=self.target,
            output_file=str(self.output_dir / "gau_urls.txt"),
            subs=True
        )
        
        self.urls = result.get("results", [])
        
        # Extract URLs with parameters for later testing
        urls_with_params = [ep for ep in self.urls if hasattr(ep, 'parameters') and ep.parameters]
        
        params_file = self.output_dir / "urls_with_params.txt"
        with open(params_file, 'w') as f:
            for ep in urls_with_params:
                f.write(f"{ep.url}\n")
        
        print(f"\n[+] Archived URLs: {len(self.urls)}")
        print(f"[+] URLs with parameters: {len(urls_with_params)}")
        print(f"[+] Saved to: {params_file}")
        
        return self.urls
    
    def run_full(self):
        """Run complete reconnaissance workflow"""
        print("\n" + "="*60)
        print(f"FULL RECONNAISSANCE WORKFLOW - {self.target}")
        print("="*60)
        
        start_time = datetime.now()
        
        # Phase 1: Subdomain discovery
        self.run_subdomain_discovery()
        
        # Phase 2: HTTP probing
        self.run_http_probing()
        
        # Phase 3: Web crawling
        self.run_crawling()
        
        # Phase 4: URL harvesting
        self.run_url_harvesting()
        
        # Generate summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("\n" + "="*60)
        print("RECONNAISSANCE COMPLETE")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Duration: {duration:.1f} seconds")
        print(f"\nResults:")
        print(f"  - Subdomains: {len(self.subdomains)}")
        print(f"  - Live hosts: {len(self.live_hosts)}")
        print(f"  - Endpoints: {len(self.endpoints)}")
        print(f"  - Archived URLs: {len(self.urls)}")
        print(f"\nOutput directory: {self.output_dir}")
        
        # Create summary file
        summary_file = self.output_dir / "summary.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Reconnaissance Summary - {self.target}\n")
            f.write(f"{'='*50}\n")
            f.write(f"Date: {datetime.now().isoformat()}\n")
            f.write(f"Duration: {duration:.1f} seconds\n\n")
            f.write(f"Results:\n")
            f.write(f"  - Subdomains: {len(self.subdomains)}\n")
            f.write(f"  - Live hosts: {len(self.live_hosts)}\n")
            f.write(f"  - Endpoints: {len(self.endpoints)}\n")
            f.write(f"  - Archived URLs: {len(self.urls)}\n")
        
        return {
            "target": self.target,
            "subdomains": self.subdomains,
            "live_hosts": self.live_hosts,
            "endpoints": self.endpoints,
            "urls": self.urls,
            "duration": duration,
            "output_dir": str(self.output_dir)
        }


def main():
    parser = argparse.ArgumentParser(
        description="Full Reconnaissance Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python full_recon.py --target example.com
  python full_recon.py --target example.com --output ./recon_results
  python full_recon.py --target example.com --no-parallel
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--no-parallel", action="store_true", help="Run tools sequentially")
    parser.add_argument("--subdomain-only", action="store_true", help="Only run subdomain discovery")
    parser.add_argument("--probe-only", action="store_true", help="Only run HTTP probing (requires subdomains.txt)")
    
    args = parser.parse_args()
    
    workflow = FullReconWorkflow(
        target=args.target,
        output_dir=args.output,
        parallel=not args.no_parallel
    )
    
    if args.subdomain_only:
        workflow.run_subdomain_discovery()
    elif args.probe_only:
        # Load existing subdomains
        subdomains_file = Path(args.output or ".") / "subdomains.txt"
        if subdomains_file.exists():
            with open(subdomains_file, 'r') as f:
                workflow.subdomains = [line.strip() for line in f if line.strip()]
            workflow.run_http_probing()
        else:
            print(f"[-] Subdomains file not found: {subdomains_file}")
            return 1
    else:
        workflow.run_full()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
