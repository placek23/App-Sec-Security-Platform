"""
Reporter - Generate reports from security scan results
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ReportConfig:
    """Report configuration"""
    title: str = "Security Assessment Report"
    target: str = ""
    tester: str = "AppSec Bounty Platform"
    output_format: str = "html"
    include_raw: bool = False


class Reporter:
    """Generate security assessment reports"""
    
    def __init__(self, config: ReportConfig = None):
        self.config = config or ReportConfig()
        self.findings = []
        self.subdomains = []
        self.endpoints = []
        self.metadata = {}
    
    def add_findings(self, findings: List[Dict[str, Any]]):
        """Add findings to the report"""
        self.findings.extend(findings)
    
    def add_subdomains(self, subdomains: List[Dict[str, Any]]):
        """Add discovered subdomains"""
        self.subdomains.extend(subdomains)
    
    def add_endpoints(self, endpoints: List[Dict[str, Any]]):
        """Add discovered endpoints"""
        self.endpoints.extend(endpoints)
    
    def add_metadata(self, key: str, value: Any):
        """Add metadata to the report"""
        self.metadata[key] = value
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate report summary"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in self.findings:
            sev = finding.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        return {
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'total_subdomains': len(self.subdomains),
            'total_endpoints': len(self.endpoints),
            'scan_date': datetime.now().isoformat(),
            'target': self.config.target
        }
    
    def generate_html(self, output_path: str):
        """Generate HTML report"""
        summary = self.generate_summary()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 40px 20px;
            border-bottom: 3px solid #e94560;
        }}
        h1 {{ color: #e94560; font-size: 2.5em; margin-bottom: 10px; }}
        h2 {{ color: #e94560; margin: 30px 0 15px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h3 {{ color: #0f3460; margin: 20px 0 10px; }}
        .meta {{ color: #888; font-size: 0.9em; }}
        .summary-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 30px 0;
        }}
        .summary-card {{ 
            background: #1a1a2e;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border: 1px solid #333;
        }}
        .summary-card.critical {{ border-color: #ff0054; }}
        .summary-card.high {{ border-color: #ff6b6b; }}
        .summary-card.medium {{ border-color: #feca57; }}
        .summary-card.low {{ border-color: #48dbfb; }}
        .summary-card.info {{ border-color: #1dd1a1; }}
        .summary-card .count {{ font-size: 3em; font-weight: bold; }}
        .summary-card.critical .count {{ color: #ff0054; }}
        .summary-card.high .count {{ color: #ff6b6b; }}
        .summary-card.medium .count {{ color: #feca57; }}
        .summary-card.low .count {{ color: #48dbfb; }}
        .summary-card.info .count {{ color: #1dd1a1; }}
        .finding {{ 
            background: #1a1a2e;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
            border-left: 4px solid #333;
        }}
        .finding.critical {{ border-left-color: #ff0054; }}
        .finding.high {{ border-left-color: #ff6b6b; }}
        .finding.medium {{ border-left-color: #feca57; }}
        .finding.low {{ border-left-color: #48dbfb; }}
        .finding.info {{ border-left-color: #1dd1a1; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
        .finding-title {{ font-size: 1.2em; font-weight: bold; color: #fff; }}
        .severity-badge {{ 
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: #ff0054; color: white; }}
        .severity-badge.high {{ background: #ff6b6b; color: white; }}
        .severity-badge.medium {{ background: #feca57; color: black; }}
        .severity-badge.low {{ background: #48dbfb; color: black; }}
        .severity-badge.info {{ background: #1dd1a1; color: black; }}
        .finding-details {{ margin-top: 15px; }}
        .finding-details dt {{ color: #888; font-size: 0.9em; margin-top: 10px; }}
        .finding-details dd {{ color: #e0e0e0; margin-left: 0; }}
        code {{ 
            background: #0a0a0a;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
            color: #e94560;
        }}
        pre {{ 
            background: #0a0a0a;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85em;
        }}
        table {{ 
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{ 
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        th {{ background: #1a1a2e; color: #e94560; }}
        tr:hover {{ background: #1a1a2e; }}
        .no-findings {{ 
            text-align: center;
            padding: 40px;
            color: #1dd1a1;
            font-size: 1.2em;
        }}
        footer {{ 
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #333;
            margin-top: 50px;
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🛡️ {self.config.title}</h1>
            <p class="meta">Target: <code>{self.config.target}</code></p>
            <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p class="meta">By: {self.config.tester}</p>
        </div>
    </header>
    
    <div class="container">
        <h2>📊 Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">{summary['severity_breakdown']['critical']}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{summary['severity_breakdown']['high']}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{summary['severity_breakdown']['medium']}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{summary['severity_breakdown']['low']}</div>
                <div>Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{summary['severity_breakdown']['info']}</div>
                <div>Info</div>
            </div>
        </div>
        
        <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
        <p><strong>Subdomains Discovered:</strong> {summary['total_subdomains']}</p>
        <p><strong>Endpoints Discovered:</strong> {summary['total_endpoints']}</p>
        
        <h2>🔍 Findings</h2>
        {self._generate_findings_html()}
        
        <h2>🌐 Discovered Subdomains</h2>
        {self._generate_subdomains_html()}
        
        <h2>📍 Discovered Endpoints</h2>
        {self._generate_endpoints_html()}
    </div>
    
    <footer>
        <p>Generated by AppSec Bounty Platform</p>
        <p>⚠️ This report contains sensitive security information. Handle appropriately.</p>
    </footer>
</body>
</html>"""
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        print(f"[+] HTML report generated: {output_path}")
    
    def _generate_findings_html(self) -> str:
        """Generate HTML for findings section"""
        if not self.findings:
            return '<div class="no-findings">✅ No vulnerabilities found</div>'
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            self.findings, 
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )
        
        html = ""
        for finding in sorted_findings:
            severity = finding.get('severity', 'info').lower()
            html += f"""
        <div class="finding {severity}">
            <div class="finding-header">
                <span class="finding-title">{finding.get('title', 'Unknown')}</span>
                <span class="severity-badge {severity}">{severity}</span>
            </div>
            <dl class="finding-details">
                <dt>Tool</dt>
                <dd>{finding.get('tool', 'Unknown')}</dd>
                <dt>Type</dt>
                <dd>{finding.get('finding_type', 'Unknown')}</dd>
                <dt>Description</dt>
                <dd>{finding.get('description', 'No description')}</dd>
                {f'<dt>URL</dt><dd><code>{finding.get("url")}</code></dd>' if finding.get('url') else ''}
                {f'<dt>Parameter</dt><dd><code>{finding.get("parameter")}</code></dd>' if finding.get('parameter') else ''}
                {f'<dt>Evidence</dt><dd><pre>{finding.get("evidence")}</pre></dd>' if finding.get('evidence') else ''}
            </dl>
        </div>"""
        
        return html
    
    def _generate_subdomains_html(self) -> str:
        """Generate HTML for subdomains section"""
        if not self.subdomains:
            return '<p>No subdomains discovered.</p>'
        
        html = """<table>
            <tr>
                <th>Subdomain</th>
                <th>IP</th>
                <th>Status</th>
                <th>Technologies</th>
                <th>Source</th>
            </tr>"""
        
        for sub in self.subdomains[:100]:  # Limit to 100
            html += f"""
            <tr>
                <td><code>{sub.get('domain', '')}</code></td>
                <td>{sub.get('ip', '-')}</td>
                <td>{sub.get('status_code', '-')}</td>
                <td>{', '.join(sub.get('technologies', [])) or '-'}</td>
                <td>{sub.get('source', '-')}</td>
            </tr>"""
        
        html += "</table>"
        
        if len(self.subdomains) > 100:
            html += f"<p><em>Showing 100 of {len(self.subdomains)} subdomains</em></p>"
        
        return html
    
    def _generate_endpoints_html(self) -> str:
        """Generate HTML for endpoints section"""
        if not self.endpoints:
            return '<p>No endpoints discovered.</p>'
        
        html = """<table>
            <tr>
                <th>URL</th>
                <th>Method</th>
                <th>Parameters</th>
                <th>Status</th>
            </tr>"""
        
        for ep in self.endpoints[:100]:  # Limit to 100
            params = ', '.join(ep.get('parameters', [])) if ep.get('parameters') else '-'
            html += f"""
            <tr>
                <td><code>{ep.get('url', '')[:80]}...</code></td>
                <td>{ep.get('method', 'GET')}</td>
                <td>{params}</td>
                <td>{ep.get('status_code', '-')}</td>
            </tr>"""
        
        html += "</table>"
        
        if len(self.endpoints) > 100:
            html += f"<p><em>Showing 100 of {len(self.endpoints)} endpoints</em></p>"
        
        return html
    
    def generate_json(self, output_path: str):
        """Generate JSON report"""
        report = {
            'metadata': {
                'title': self.config.title,
                'target': self.config.target,
                'tester': self.config.tester,
                'generated': datetime.now().isoformat()
            },
            'summary': self.generate_summary(),
            'findings': self.findings,
            'subdomains': self.subdomains,
            'endpoints': self.endpoints,
            'additional_metadata': self.metadata
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] JSON report generated: {output_path}")
    
    def generate_markdown(self, output_path: str):
        """Generate Markdown report"""
        summary = self.generate_summary()
        
        md = f"""# {self.config.title}

**Target:** `{self.config.target}`  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**By:** {self.config.tester}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['severity_breakdown']['critical']} |
| High | {summary['severity_breakdown']['high']} |
| Medium | {summary['severity_breakdown']['medium']} |
| Low | {summary['severity_breakdown']['low']} |
| Info | {summary['severity_breakdown']['info']} |

- **Total Findings:** {summary['total_findings']}
- **Subdomains Discovered:** {summary['total_subdomains']}
- **Endpoints Discovered:** {summary['total_endpoints']}

---

## Findings

"""
        for finding in self.findings:
            md += f"""### [{finding.get('severity', 'info').upper()}] {finding.get('title', 'Unknown')}

- **Tool:** {finding.get('tool', 'Unknown')}
- **Type:** {finding.get('finding_type', 'Unknown')}
- **Description:** {finding.get('description', 'No description')}
"""
            if finding.get('url'):
                md += f"- **URL:** `{finding.get('url')}`\n"
            if finding.get('parameter'):
                md += f"- **Parameter:** `{finding.get('parameter')}`\n"
            if finding.get('evidence'):
                md += f"- **Evidence:**\n```\n{finding.get('evidence')}\n```\n"
            md += "\n---\n\n"
        
        with open(output_path, 'w') as f:
            f.write(md)
        
        print(f"[+] Markdown report generated: {output_path}")
    
    def generate(self, output_path: str, format: str = None):
        """Generate report in specified format"""
        format = format or self.config.output_format
        
        if format == 'html':
            self.generate_html(output_path)
        elif format == 'json':
            self.generate_json(output_path)
        elif format == 'markdown' or format == 'md':
            self.generate_markdown(output_path)
        else:
            raise ValueError(f"Unknown format: {format}")


if __name__ == "__main__":
    import sys
    
    # Example usage
    config = ReportConfig(
        title="Security Assessment Report",
        target="example.com",
        tester="AppSec Bounty Platform"
    )
    
    reporter = Reporter(config)
    
    # Add sample findings
    reporter.add_findings([
        {
            'tool': 'nuclei',
            'target': 'example.com',
            'finding_type': 'vulnerability',
            'title': 'SQL Injection in Login Form',
            'description': 'The login form is vulnerable to SQL injection attacks.',
            'severity': 'critical',
            'url': 'https://example.com/login',
            'parameter': 'username',
            'evidence': "Error: You have an error in your SQL syntax"
        }
    ])
    
    output_path = sys.argv[1] if len(sys.argv) > 1 else "report.html"
    reporter.generate(output_path, 'html')
