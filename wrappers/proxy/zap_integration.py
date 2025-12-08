"""
OWASP ZAP integration wrapper.

Provides programmatic control of OWASP ZAP for:
- Spidering targets
- Active vulnerability scanning
- Alert management
- Report generation
"""

import time
import os
from typing import Optional, List, Dict, Any
from pathlib import Path

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False


class ZAPIntegration:
    """OWASP ZAP integration for automated security testing."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        proxy_host: str = '127.0.0.1',
        proxy_port: int = 8080,
        output_dir: str = './output/zap'
    ):
        """
        Initialize ZAP integration.

        Args:
            api_key: ZAP API key (can be set in ZAP or retrieved from config)
            proxy_host: ZAP proxy host
            proxy_port: ZAP proxy port
            output_dir: Directory for storing reports
        """
        if not ZAP_AVAILABLE:
            raise ImportError(
                "python-owasp-zap-v2.4 is required. "
                "Install with: pip install python-owasp-zap-v2.4"
            )

        self.api_key = api_key or os.environ.get('ZAP_API_KEY', '')
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.zap: Optional[ZAPv2] = None
        self._connected = False

    def connect(self) -> str:
        """
        Connect to running ZAP instance.

        Returns:
            ZAP version string

        Raises:
            ConnectionError: If unable to connect to ZAP
        """
        try:
            self.zap = ZAPv2(
                apikey=self.api_key,
                proxies={
                    'http': f'http://{self.proxy_host}:{self.proxy_port}',
                    'https': f'http://{self.proxy_host}:{self.proxy_port}'
                }
            )
            version = self.zap.core.version
            self._connected = True
            print(f"[+] Connected to ZAP version: {version}")
            return version
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to ZAP at {self.proxy_host}:{self.proxy_port}. "
                f"Ensure ZAP is running with API enabled. Error: {e}"
            )

    def _ensure_connected(self):
        """Ensure ZAP connection is established."""
        if not self._connected or self.zap is None:
            raise RuntimeError("Not connected to ZAP. Call connect() first.")

    def access_url(self, url: str) -> Dict[str, Any]:
        """
        Access a URL through ZAP proxy.

        Args:
            url: Target URL to access

        Returns:
            Response details
        """
        self._ensure_connected()
        try:
            self.zap.core.access_url(url)
            return {'success': True, 'url': url}
        except Exception as e:
            return {'success': False, 'url': url, 'error': str(e)}

    def spider_target(
        self,
        target: str,
        max_depth: int = 5,
        max_children: int = 0,
        recurse: bool = True,
        context_name: str = None,
        subtree_only: bool = False
    ) -> Dict[str, Any]:
        """
        Spider a target URL to discover content.

        Args:
            target: Target URL to spider
            max_depth: Maximum crawl depth
            max_children: Maximum children per node (0 = unlimited)
            recurse: Whether to recurse into links
            context_name: Optional ZAP context name
            subtree_only: Only spider subtree of the target URL

        Returns:
            Spider results including discovered URLs
        """
        self._ensure_connected()

        print(f"[*] Starting spider on {target}")

        # Start spider scan
        scan_id = self.zap.spider.scan(
            url=target,
            maxchildren=max_children,
            recurse=recurse,
            contextname=context_name,
            subtreeonly=subtree_only
        )

        # Wait for spider to complete
        while True:
            progress = int(self.zap.spider.status(scan_id))
            print(f"[*] Spider progress: {progress}%")
            if progress >= 100:
                break
            time.sleep(2)

        # Get results
        results = self.zap.spider.results(scan_id)
        urls_found = self.zap.spider.all_urls

        print(f"[+] Spider complete. Found {len(urls_found)} URLs")

        return {
            'scan_id': scan_id,
            'target': target,
            'urls_found': len(urls_found),
            'urls': urls_found,
            'results': results
        }

    def ajax_spider(
        self,
        target: str,
        in_scope_only: bool = True,
        max_duration: int = 0,
        max_crawl_depth: int = 10
    ) -> Dict[str, Any]:
        """
        Run AJAX spider for JavaScript-heavy applications.

        Args:
            target: Target URL
            in_scope_only: Only spider in-scope URLs
            max_duration: Maximum duration in minutes (0 = unlimited)
            max_crawl_depth: Maximum crawl depth

        Returns:
            AJAX spider results
        """
        self._ensure_connected()

        print(f"[*] Starting AJAX spider on {target}")

        # Configure and start AJAX spider
        self.zap.ajaxSpider.set_option_max_crawl_depth(max_crawl_depth)
        if max_duration > 0:
            self.zap.ajaxSpider.set_option_max_duration(max_duration)

        self.zap.ajaxSpider.scan(target, inscope=in_scope_only)

        # Wait for AJAX spider to complete
        while self.zap.ajaxSpider.status == 'running':
            print(f"[*] AJAX Spider running... Results: {self.zap.ajaxSpider.number_of_results}")
            time.sleep(5)

        results = self.zap.ajaxSpider.results()

        print(f"[+] AJAX Spider complete. Found {len(results)} results")

        return {
            'target': target,
            'results_count': len(results),
            'results': results
        }

    def active_scan(
        self,
        target: str,
        recurse: bool = True,
        in_scope_only: bool = True,
        scan_policy: str = None,
        context_id: str = None
    ) -> Dict[str, Any]:
        """
        Run active vulnerability scan on target.

        Args:
            target: Target URL to scan
            recurse: Recurse into discovered URLs
            in_scope_only: Only scan in-scope URLs
            scan_policy: Custom scan policy name
            context_id: ZAP context ID

        Returns:
            Scan results with alerts
        """
        self._ensure_connected()

        print(f"[*] Starting active scan on {target}")

        # Start active scan
        scan_id = self.zap.ascan.scan(
            url=target,
            recurse=recurse,
            inscopeonly=in_scope_only,
            scanpolicyname=scan_policy,
            contextid=context_id
        )

        # Wait for scan to complete
        while True:
            progress = int(self.zap.ascan.status(scan_id))
            print(f"[*] Active scan progress: {progress}%")
            if progress >= 100:
                break
            time.sleep(5)

        # Get alerts
        alerts = self.zap.core.alerts(baseurl=target)

        print(f"[+] Active scan complete. Found {len(alerts)} alerts")

        return {
            'scan_id': scan_id,
            'target': target,
            'alerts_count': len(alerts),
            'alerts': alerts
        }

    def passive_scan_wait(self, timeout: int = 300) -> bool:
        """
        Wait for passive scanner to complete.

        Args:
            timeout: Maximum wait time in seconds

        Returns:
            True if completed, False if timed out
        """
        self._ensure_connected()

        print("[*] Waiting for passive scanner to complete...")
        start_time = time.time()

        while True:
            records_to_scan = int(self.zap.pscan.records_to_scan)
            if records_to_scan == 0:
                print("[+] Passive scan complete")
                return True

            if time.time() - start_time > timeout:
                print(f"[!] Passive scan timed out with {records_to_scan} records remaining")
                return False

            print(f"[*] Records remaining: {records_to_scan}")
            time.sleep(2)

    def get_alerts(
        self,
        base_url: str = None,
        risk: str = None,
        start: int = 0,
        count: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get all alerts, optionally filtered.

        Args:
            base_url: Filter by base URL
            risk: Filter by risk level (High, Medium, Low, Informational)
            start: Start index for pagination
            count: Number of alerts to return (0 = all)

        Returns:
            List of alerts
        """
        self._ensure_connected()

        alerts = self.zap.core.alerts(
            baseurl=base_url,
            start=start,
            count=count,
            riskid=risk
        )

        return alerts

    def get_alerts_summary(self, base_url: str = None) -> Dict[str, int]:
        """
        Get summary of alerts by risk level.

        Args:
            base_url: Optional base URL filter

        Returns:
            Dictionary with counts by risk level
        """
        self._ensure_connected()

        alerts = self.get_alerts(base_url=base_url)

        summary = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }

        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            if risk in summary:
                summary[risk] += 1

        return summary

    def export_report(
        self,
        output_file: str = None,
        format: str = 'html',
        title: str = 'ZAP Security Report'
    ) -> str:
        """
        Export scan report.

        Args:
            output_file: Output file path (auto-generated if None)
            format: Report format (html, json, xml, md)
            title: Report title

        Returns:
            Path to generated report
        """
        self._ensure_connected()

        if output_file is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"zap_report_{timestamp}.{format}"

        if format == 'html':
            report = self.zap.core.htmlreport()
        elif format == 'json':
            report = self.zap.core.jsonreport()
        elif format == 'xml':
            report = self.zap.core.xmlreport()
        elif format == 'md':
            report = self.zap.core.mdreport()
        else:
            raise ValueError(f"Unsupported format: {format}. Use html, json, xml, or md")

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)

        print(f"[+] Report saved to: {output_file}")
        return str(output_file)

    def set_context(self, name: str, in_scope_patterns: List[str] = None) -> str:
        """
        Create and configure a ZAP context.

        Args:
            name: Context name
            in_scope_patterns: List of regex patterns for in-scope URLs

        Returns:
            Context ID
        """
        self._ensure_connected()

        context_id = self.zap.context.new_context(name)

        if in_scope_patterns:
            for pattern in in_scope_patterns:
                self.zap.context.include_in_context(name, pattern)

        print(f"[+] Created context '{name}' with ID: {context_id}")
        return context_id

    def set_authentication(
        self,
        context_name: str,
        auth_method: str,
        login_url: str = None,
        login_request_data: str = None,
        username_field: str = None,
        password_field: str = None
    ):
        """
        Configure authentication for a context.

        Args:
            context_name: Name of the context
            auth_method: Authentication method (formBasedAuthentication, scriptBasedAuthentication, etc.)
            login_url: Login form URL
            login_request_data: POST data template for login
            username_field: Username parameter name
            password_field: Password parameter name
        """
        self._ensure_connected()

        context_id = self.zap.context.context(context_name)['id']

        if auth_method == 'formBasedAuthentication':
            self.zap.authentication.set_authentication_method(
                context_id,
                'formBasedAuthentication',
                f'loginUrl={login_url}&loginRequestData={login_request_data}'
            )

        print(f"[+] Configured {auth_method} for context '{context_name}'")

    def add_user(
        self,
        context_name: str,
        username: str,
        password: str
    ) -> str:
        """
        Add a user to a context.

        Args:
            context_name: Context name
            username: Username
            password: Password

        Returns:
            User ID
        """
        self._ensure_connected()

        context_id = self.zap.context.context(context_name)['id']
        user_id = self.zap.users.new_user(context_id, username)

        # Set credentials
        auth_credentials = f'username={username}&password={password}'
        self.zap.users.set_authentication_credentials(
            context_id,
            user_id,
            auth_credentials
        )

        self.zap.users.set_user_enabled(context_id, user_id, True)

        print(f"[+] Added user '{username}' to context '{context_name}'")
        return user_id

    def full_scan(
        self,
        target: str,
        spider: bool = True,
        ajax_spider: bool = False,
        active_scan: bool = True,
        report_format: str = 'html'
    ) -> Dict[str, Any]:
        """
        Run a full security scan on target.

        Args:
            target: Target URL
            spider: Run traditional spider
            ajax_spider: Run AJAX spider
            active_scan: Run active scan
            report_format: Report format

        Returns:
            Complete scan results
        """
        results = {
            'target': target,
            'spider': None,
            'ajax_spider': None,
            'active_scan': None,
            'alerts_summary': None,
            'report': None
        }

        # Access target first
        self.access_url(target)

        # Spider
        if spider:
            results['spider'] = self.spider_target(target)

        # AJAX Spider
        if ajax_spider:
            results['ajax_spider'] = self.ajax_spider(target)

        # Wait for passive scan
        self.passive_scan_wait()

        # Active scan
        if active_scan:
            results['active_scan'] = self.active_scan(target)

        # Get summary
        results['alerts_summary'] = self.get_alerts_summary(target)

        # Generate report
        results['report'] = self.export_report(format=report_format)

        return results

    def shutdown(self):
        """Shutdown ZAP instance (if started programmatically)."""
        if self._connected and self.zap:
            try:
                self.zap.core.shutdown()
                print("[+] ZAP shutdown initiated")
            except Exception as e:
                print(f"[!] Error shutting down ZAP: {e}")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='OWASP ZAP Integration')
    parser.add_argument('--target', '-t', required=True, help='Target URL')
    parser.add_argument('--api-key', '-k', help='ZAP API key')
    parser.add_argument('--host', default='127.0.0.1', help='ZAP proxy host')
    parser.add_argument('--port', type=int, default=8080, help='ZAP proxy port')
    parser.add_argument('--spider', action='store_true', help='Run spider')
    parser.add_argument('--ajax', action='store_true', help='Run AJAX spider')
    parser.add_argument('--scan', action='store_true', help='Run active scan')
    parser.add_argument('--full', action='store_true', help='Run full scan')
    parser.add_argument('--output', '-o', default='./output/zap', help='Output directory')

    args = parser.parse_args()

    zap = ZAPIntegration(
        api_key=args.api_key,
        proxy_host=args.host,
        proxy_port=args.port,
        output_dir=args.output
    )

    try:
        zap.connect()

        if args.full:
            results = zap.full_scan(args.target)
        else:
            if args.spider:
                zap.spider_target(args.target)
            if args.ajax:
                zap.ajax_spider(args.target)
            if args.scan:
                zap.active_scan(args.target)

            # Generate report
            zap.export_report()

        print("\n[+] Alerts Summary:")
        for risk, count in zap.get_alerts_summary(args.target).items():
            print(f"  {risk}: {count}")

    except Exception as e:
        print(f"[!] Error: {e}")
