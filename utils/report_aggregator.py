"""
Report Aggregator - Combine multiple scan results into unified reports.
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict, field

from utils.advanced_reporter import AdvancedReporter, EnhancedFinding
from utils.analytics import SecurityAnalytics


@dataclass
class TargetSummary:
    """Summary for a single target"""
    target: str
    name: str = ''
    scans_count: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_score: float = 0.0
    risk_rating: str = 'Informational'
    last_scan_date: str = ''
    subdomains_count: int = 0
    endpoints_count: int = 0


@dataclass
class AggregatedReport:
    """Aggregated report across multiple targets"""
    title: str = 'Multi-Target Security Assessment'
    generated_at: str = ''
    targets_count: int = 0
    total_scans: int = 0
    total_findings: int = 0
    overall_risk_rating: str = 'Informational'
    overall_risk_score: float = 0.0
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    finding_types: Dict[str, int] = field(default_factory=dict)
    targets: List[TargetSummary] = field(default_factory=list)
    top_vulnerabilities: List[Dict] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class ReportAggregator:
    """Aggregate reports from multiple targets and scans"""

    def __init__(self, output_dir: str = './output/reports'):
        """Initialize aggregator"""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.analytics = SecurityAnalytics()
        self._targets_data = {}
        self._all_findings = []
        self._all_scans = []
        self._all_subdomains = []
        self._all_endpoints = []

    def add_target_report(self, target: str, report_data: Dict[str, Any],
                          name: str = None):
        """Add a target's report data to the aggregation"""
        if target not in self._targets_data:
            self._targets_data[target] = {
                'name': name or target,
                'scans': [],
                'findings': [],
                'subdomains': [],
                'endpoints': []
            }

        # Add data
        if 'findings' in report_data:
            self._targets_data[target]['findings'].extend(report_data['findings'])
            self._all_findings.extend(report_data['findings'])

        if 'subdomains' in report_data:
            self._targets_data[target]['subdomains'].extend(report_data['subdomains'])
            self._all_subdomains.extend(report_data['subdomains'])

        if 'endpoints' in report_data:
            self._targets_data[target]['endpoints'].extend(report_data['endpoints'])
            self._all_endpoints.extend(report_data['endpoints'])

        if 'scan' in report_data:
            self._targets_data[target]['scans'].append(report_data['scan'])
            self._all_scans.append(report_data['scan'])
        elif 'scans' in report_data:
            self._targets_data[target]['scans'].extend(report_data['scans'])
            self._all_scans.extend(report_data['scans'])

    def add_scan_results(self, target: str, scan: Dict, findings: List[Dict],
                        subdomains: List[Dict] = None, endpoints: List[Dict] = None,
                        name: str = None):
        """Add individual scan results"""
        self.add_target_report(target, {
            'scan': scan,
            'findings': findings,
            'subdomains': subdomains or [],
            'endpoints': endpoints or []
        }, name=name)

    def load_report_file(self, filepath: str, target: str = None):
        """Load report from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        # Try to extract target from data
        if not target:
            target = (
                data.get('metadata', {}).get('target') or
                data.get('target') or
                os.path.basename(filepath).split('_')[0]
            )

        self.add_target_report(target, data)

    def load_multiple_reports(self, filepaths: List[str]):
        """Load multiple report files"""
        for filepath in filepaths:
            self.load_report_file(filepath)

    def generate_target_summary(self, target: str) -> TargetSummary:
        """Generate summary for a single target"""
        data = self._targets_data.get(target, {})
        findings = data.get('findings', [])
        scans = data.get('scans', [])

        severity_counts = defaultdict(int)
        for f in findings:
            severity = f.get('severity', 'info').lower()
            severity_counts[severity] += 1

        # Calculate risk score
        total = len(findings)
        if total > 0:
            weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
            weighted = sum(severity_counts[s] * weights.get(s, 0) for s in severity_counts)
            risk_score = round((weighted / (total * 10)) * 100, 2)
        else:
            risk_score = 0

        # Determine risk rating
        if severity_counts.get('critical', 0) > 0:
            risk_rating = 'Critical'
        elif severity_counts.get('high', 0) > 0:
            risk_rating = 'High'
        elif severity_counts.get('medium', 0) > 0:
            risk_rating = 'Medium'
        elif severity_counts.get('low', 0) > 0:
            risk_rating = 'Low'
        else:
            risk_rating = 'Informational'

        # Get last scan date
        last_scan = ''
        if scans:
            dates = [s.get('created_at', s.get('completed_at', '')) for s in scans]
            dates = [d for d in dates if d]
            if dates:
                last_scan = max(dates)

        return TargetSummary(
            target=target,
            name=data.get('name', target),
            scans_count=len(scans),
            findings_count=len(findings),
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            medium_count=severity_counts.get('medium', 0),
            low_count=severity_counts.get('low', 0),
            info_count=severity_counts.get('info', 0),
            risk_score=risk_score,
            risk_rating=risk_rating,
            last_scan_date=last_scan,
            subdomains_count=len(data.get('subdomains', [])),
            endpoints_count=len(data.get('endpoints', []))
        )

    def generate_aggregated_report(self, title: str = None) -> AggregatedReport:
        """Generate aggregated report across all targets"""
        targets_summaries = []
        for target in self._targets_data:
            targets_summaries.append(self.generate_target_summary(target))

        # Sort targets by risk
        targets_summaries.sort(key=lambda x: x.risk_score, reverse=True)

        # Calculate overall metrics
        total_severity = defaultdict(int)
        finding_types = defaultdict(int)
        tools = set()

        for f in self._all_findings:
            severity = f.get('severity', 'info').lower()
            total_severity[severity] += 1

            f_type = f.get('finding_type', f.get('type', 'unknown'))
            finding_types[f_type] += 1

            tool = f.get('tool')
            if tool:
                tools.add(tool)

        # Overall risk calculation
        total_findings = len(self._all_findings)
        if total_findings > 0:
            weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
            weighted = sum(total_severity[s] * weights.get(s, 0) for s in total_severity)
            overall_risk_score = round((weighted / (total_findings * 10)) * 100, 2)
        else:
            overall_risk_score = 0

        # Overall risk rating
        if total_severity.get('critical', 0) > 0:
            overall_risk_rating = 'Critical'
        elif total_severity.get('high', 0) > 0:
            overall_risk_rating = 'High'
        elif total_severity.get('medium', 0) > 0:
            overall_risk_rating = 'Medium'
        elif total_severity.get('low', 0) > 0:
            overall_risk_rating = 'Low'
        else:
            overall_risk_rating = 'Informational'

        # Top vulnerabilities
        top_vulns = sorted(
            finding_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Generate recommendations
        recommendations = self._generate_recommendations(total_severity, finding_types)

        return AggregatedReport(
            title=title or 'Multi-Target Security Assessment',
            generated_at=datetime.utcnow().isoformat(),
            targets_count=len(self._targets_data),
            total_scans=len(self._all_scans),
            total_findings=total_findings,
            overall_risk_rating=overall_risk_rating,
            overall_risk_score=overall_risk_score,
            severity_breakdown=dict(total_severity),
            finding_types=dict(finding_types),
            targets=targets_summaries,
            top_vulnerabilities=[{'type': t, 'count': c} for t, c in top_vulns],
            tools_used=list(tools),
            recommendations=recommendations
        )

    def _generate_recommendations(self, severity_counts: Dict,
                                  finding_types: Dict) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []

        if severity_counts.get('critical', 0) > 0:
            recommendations.append(
                f"URGENT: Address {severity_counts['critical']} critical vulnerabilities immediately"
            )

        if severity_counts.get('high', 0) > 3:
            recommendations.append(
                f"Prioritize remediation of {severity_counts['high']} high-severity issues"
            )

        # Type-specific recommendations
        type_recommendations = {
            'sqli': 'Implement parameterized queries across all database operations',
            'xss': 'Deploy Content Security Policy and implement output encoding',
            'ssrf': 'Implement URL validation and allowlisting for external requests',
            'idor': 'Review and strengthen authorization controls',
            'auth_bypass': 'Audit authentication mechanisms and implement MFA',
            'xxe': 'Disable external entity processing in XML parsers'
        }

        for vuln_type, rec in type_recommendations.items():
            if finding_types.get(vuln_type, 0) > 0:
                recommendations.append(rec)

        if not recommendations:
            recommendations.append('Continue regular security assessments to maintain security posture')

        return recommendations

    def export_json(self, filename: str = None) -> str:
        """Export aggregated report to JSON"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"aggregated_report_{timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)
        report = self.generate_aggregated_report()

        data = {
            'report': asdict(report),
            'targets_data': {
                target: {
                    'findings': self._targets_data[target]['findings'],
                    'subdomains': self._targets_data[target]['subdomains'],
                    'endpoints': self._targets_data[target]['endpoints']
                }
                for target in self._targets_data
            }
        }

        # Convert TargetSummary objects
        data['report']['targets'] = [asdict(t) for t in report.targets]

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return filepath

    def export_html(self, filename: str = None) -> str:
        """Export aggregated report to HTML"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"aggregated_report_{timestamp}.html"

        filepath = os.path.join(self.output_dir, filename)
        report = self.generate_aggregated_report()

        html = self._generate_html(report)

        with open(filepath, 'w') as f:
            f.write(html)

        return filepath

    def _generate_html(self, report: AggregatedReport) -> str:
        """Generate HTML for aggregated report"""
        # Generate target rows
        target_rows = ""
        for t in report.targets:
            rating_class = t.risk_rating.lower()
            target_rows += f"""
            <tr>
                <td><strong>{t.name}</strong><br><small>{t.target}</small></td>
                <td>{t.scans_count}</td>
                <td>{t.findings_count}</td>
                <td><span class="badge {rating_class}">{t.critical_count}</span></td>
                <td><span class="badge high">{t.high_count}</span></td>
                <td><span class="badge medium">{t.medium_count}</span></td>
                <td>{t.risk_score}%</td>
                <td><span class="risk-badge {rating_class}">{t.risk_rating}</span></td>
            </tr>"""

        # Generate recommendations
        rec_items = ""
        for rec in report.recommendations:
            rec_items += f"<li>{rec}</li>"

        # Generate top vulnerabilities
        vuln_items = ""
        for v in report.top_vulnerabilities:
            vuln_items += f"<li><strong>{v['type']}</strong>: {v['count']} occurrences</li>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.title}</title>
    <style>
        :root {{
            --primary: #1a1a2e;
            --accent: #e94560;
            --critical: #ff0054;
            --high: #ff6b6b;
            --medium: #feca57;
            --low: #48dbfb;
            --info: #1dd1a1;
            --bg: #0a0a0a;
            --card-bg: #1a1a2e;
            --text: #e0e0e0;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg); color: var(--text); line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}

        header {{ background: linear-gradient(135deg, var(--primary) 0%, #16213e 100%);
            padding: 50px 20px; text-align: center; border-bottom: 4px solid var(--accent); }}
        h1 {{ color: var(--accent); font-size: 2.5em; margin-bottom: 10px; }}
        .meta {{ color: #888; }}

        .overview {{ display: grid; grid-template-columns: repeat(4, 1fr);
            gap: 20px; margin: 30px 0; }}
        .overview-card {{ background: var(--card-bg); border-radius: 12px;
            padding: 30px; text-align: center; border: 2px solid #333; }}
        .overview-card .number {{ font-size: 3em; font-weight: bold; color: var(--accent); }}
        .overview-card .label {{ color: #888; font-size: 0.9em; text-transform: uppercase; }}

        .risk-banner {{ background: var(--card-bg); border-radius: 15px;
            padding: 40px; text-align: center; margin: 30px 0; }}
        .risk-banner .rating {{ font-size: 4em; font-weight: bold; }}
        .risk-banner .rating.critical {{ color: var(--critical); }}
        .risk-banner .rating.high {{ color: var(--high); }}
        .risk-banner .rating.medium {{ color: var(--medium); }}
        .risk-banner .rating.low {{ color: var(--low); }}
        .risk-banner .rating.informational {{ color: var(--info); }}

        h2 {{ color: var(--accent); margin: 40px 0 20px;
            padding-bottom: 10px; border-bottom: 2px solid #333; }}

        table {{ width: 100%; border-collapse: collapse; background: var(--card-bg);
            border-radius: 8px; overflow: hidden; margin: 20px 0; }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: var(--primary); color: var(--accent); text-transform: uppercase;
            font-size: 0.85em; letter-spacing: 1px; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}

        .badge {{ padding: 3px 12px; border-radius: 12px; font-size: 0.85em;
            font-weight: bold; display: inline-block; }}
        .badge.critical {{ background: var(--critical); color: white; }}
        .badge.high {{ background: var(--high); color: white; }}
        .badge.medium {{ background: var(--medium); color: black; }}
        .badge.low {{ background: var(--low); color: black; }}

        .risk-badge {{ padding: 5px 15px; border-radius: 20px; font-size: 0.8em;
            font-weight: bold; text-transform: uppercase; }}
        .risk-badge.critical {{ background: var(--critical); color: white; }}
        .risk-badge.high {{ background: var(--high); color: white; }}
        .risk-badge.medium {{ background: var(--medium); color: black; }}
        .risk-badge.low {{ background: var(--low); color: black; }}
        .risk-badge.informational {{ background: var(--info); color: black; }}

        .summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin: 30px 0; }}
        .summary-section {{ background: var(--card-bg); border-radius: 12px; padding: 25px; }}
        .summary-section h3 {{ color: var(--accent); margin-bottom: 15px; }}
        .summary-section ul {{ list-style: none; padding: 0; }}
        .summary-section li {{ padding: 8px 0; border-bottom: 1px solid #333; }}
        .summary-section li:last-child {{ border-bottom: none; }}

        .recommendations {{ background: rgba(29, 209, 161, 0.1); border: 1px solid var(--info);
            border-radius: 12px; padding: 25px; margin: 30px 0; }}
        .recommendations h3 {{ color: var(--info); margin-bottom: 15px; }}
        .recommendations ul {{ padding-left: 20px; }}
        .recommendations li {{ padding: 8px 0; }}

        footer {{ text-align: center; padding: 40px; color: #666;
            border-top: 1px solid #333; margin-top: 50px; }}

        @media (max-width: 900px) {{
            .overview {{ grid-template-columns: repeat(2, 1fr); }}
            .summary-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>{report.title}</h1>
            <p class="meta">Generated: {report.generated_at}</p>
            <p class="meta">{report.targets_count} Targets | {report.total_scans} Scans | {report.total_findings} Findings</p>
        </div>
    </header>

    <div class="container">
        <div class="risk-banner">
            <div class="rating {report.overall_risk_rating.lower()}">{report.overall_risk_rating.upper()}</div>
            <div>Overall Security Risk</div>
            <div style="margin-top: 15px; color: #888;">Risk Score: {report.overall_risk_score}%</div>
        </div>

        <div class="overview">
            <div class="overview-card">
                <div class="number">{report.targets_count}</div>
                <div class="label">Targets</div>
            </div>
            <div class="overview-card">
                <div class="number">{report.total_scans}</div>
                <div class="label">Total Scans</div>
            </div>
            <div class="overview-card">
                <div class="number">{report.total_findings}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="overview-card">
                <div class="number">{report.severity_breakdown.get('critical', 0) + report.severity_breakdown.get('high', 0)}</div>
                <div class="label">Critical/High</div>
            </div>
        </div>

        <h2>Targets Overview</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Scans</th>
                    <th>Findings</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Risk Score</th>
                    <th>Rating</th>
                </tr>
            </thead>
            <tbody>
                {target_rows}
            </tbody>
        </table>

        <div class="summary-grid">
            <div class="summary-section">
                <h3>Top Vulnerability Types</h3>
                <ul>
                    {vuln_items or '<li>No vulnerabilities found</li>'}
                </ul>
            </div>
            <div class="summary-section">
                <h3>Severity Distribution</h3>
                <ul>
                    <li><span class="badge critical">Critical</span> {report.severity_breakdown.get('critical', 0)}</li>
                    <li><span class="badge high">High</span> {report.severity_breakdown.get('high', 0)}</li>
                    <li><span class="badge medium">Medium</span> {report.severity_breakdown.get('medium', 0)}</li>
                    <li><span class="badge low">Low</span> {report.severity_breakdown.get('low', 0)}</li>
                </ul>
            </div>
        </div>

        <div class="recommendations">
            <h3>Key Recommendations</h3>
            <ul>
                {rec_items}
            </ul>
        </div>

        <h2>Tools Used</h2>
        <p>{', '.join(report.tools_used) or 'No tools recorded'}</p>
    </div>

    <footer>
        <p>Generated by <strong>AppSec Bounty Platform</strong></p>
        <p><small>This report contains sensitive security information. Handle appropriately.</small></p>
    </footer>
</body>
</html>"""

    def export_all(self, base_filename: str = None) -> Dict[str, str]:
        """Export aggregated report in all formats"""
        if base_filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_filename = f"aggregated_report_{timestamp}"

        return {
            'json': self.export_json(f"{base_filename}.json"),
            'html': self.export_html(f"{base_filename}.html")
        }


if __name__ == "__main__":
    # Example usage
    aggregator = ReportAggregator()

    # Add sample data for multiple targets
    aggregator.add_scan_results(
        target='example.com',
        name='Example Corp',
        scan={'id': 1, 'created_at': datetime.now().isoformat()},
        findings=[
            {'title': 'SQL Injection', 'severity': 'critical', 'finding_type': 'sqli', 'tool': 'sqlmap'},
            {'title': 'XSS', 'severity': 'high', 'finding_type': 'xss', 'tool': 'dalfox'}
        ],
        subdomains=[{'domain': 'api.example.com'}],
        endpoints=[{'url': 'https://example.com/api'}]
    )

    aggregator.add_scan_results(
        target='test.com',
        name='Test Site',
        scan={'id': 2, 'created_at': datetime.now().isoformat()},
        findings=[
            {'title': 'SSRF', 'severity': 'high', 'finding_type': 'ssrf', 'tool': 'ssrf_tester'},
            {'title': 'Info Disclosure', 'severity': 'medium', 'finding_type': 'info', 'tool': 'nuclei'}
        ]
    )

    # Export reports
    paths = aggregator.export_all()
    print("Generated reports:")
    for fmt, path in paths.items():
        print(f"  {fmt}: {path}")
