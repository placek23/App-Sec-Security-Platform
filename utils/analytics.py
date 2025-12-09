"""
Analytics Module - Security scan analytics, trends, and insights.
"""
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, asdict
import statistics


@dataclass
class TrendDataPoint:
    """Single data point for trend analysis"""
    date: str
    scans: int = 0
    findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    risk_score: float = 0.0


@dataclass
class AnalyticsSummary:
    """Summary of security analytics"""
    period_start: str
    period_end: str
    total_scans: int
    total_findings: int
    unique_targets: int
    severity_breakdown: Dict[str, int]
    finding_types: Dict[str, int]
    top_vulnerabilities: List[Dict]
    risk_trend: str  # "improving", "stable", "degrading"
    avg_risk_score: float
    avg_findings_per_scan: float
    most_vulnerable_targets: List[Dict]
    tools_effectiveness: Dict[str, int]


class SecurityAnalytics:
    """Comprehensive security analytics engine"""

    def __init__(self, db_manager=None):
        """Initialize analytics with optional database manager"""
        self.db_manager = db_manager
        self._cache = {}

    def analyze_scans(self, scans: List[Dict], findings: List[Dict]) -> AnalyticsSummary:
        """Perform comprehensive analysis on scans and findings"""
        if not scans:
            return self._empty_summary()

        # Calculate date range
        dates = [s.get('created_at', '') for s in scans if s.get('created_at')]
        period_start = min(dates) if dates else ''
        period_end = max(dates) if dates else ''

        # Severity breakdown
        severity_counts = defaultdict(int)
        finding_types = defaultdict(int)
        tools = defaultdict(int)
        target_findings = defaultdict(int)

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] += 1

            f_type = finding.get('finding_type') or finding.get('type', 'unknown')
            finding_types[f_type] += 1

            tool = finding.get('tool', 'unknown')
            tools[tool] += 1

        # Target vulnerability analysis
        for scan in scans:
            target_id = scan.get('target_id') or scan.get('target', 'unknown')
            target_findings[target_id] += scan.get('findings_count', 0)

        # Calculate averages
        risk_scores = [s.get('risk_score', 0) for s in scans if s.get('risk_score')]
        avg_risk = statistics.mean(risk_scores) if risk_scores else 0

        findings_counts = [s.get('findings_count', 0) for s in scans]
        avg_findings = statistics.mean(findings_counts) if findings_counts else 0

        # Risk trend analysis
        risk_trend = self._calculate_risk_trend(scans)

        # Top vulnerabilities
        top_vulns = sorted(
            finding_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Most vulnerable targets
        most_vulnerable = sorted(
            target_findings.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        return AnalyticsSummary(
            period_start=period_start,
            period_end=period_end,
            total_scans=len(scans),
            total_findings=len(findings),
            unique_targets=len(set(s.get('target_id') for s in scans if s.get('target_id'))),
            severity_breakdown=dict(severity_counts),
            finding_types=dict(finding_types),
            top_vulnerabilities=[{'type': t, 'count': c} for t, c in top_vulns],
            risk_trend=risk_trend,
            avg_risk_score=round(avg_risk, 2),
            avg_findings_per_scan=round(avg_findings, 2),
            most_vulnerable_targets=[{'target': t, 'findings': c} for t, c in most_vulnerable],
            tools_effectiveness=dict(tools)
        )

    def _empty_summary(self) -> AnalyticsSummary:
        """Return empty summary"""
        return AnalyticsSummary(
            period_start='',
            period_end='',
            total_scans=0,
            total_findings=0,
            unique_targets=0,
            severity_breakdown={},
            finding_types={},
            top_vulnerabilities=[],
            risk_trend='stable',
            avg_risk_score=0,
            avg_findings_per_scan=0,
            most_vulnerable_targets=[],
            tools_effectiveness={}
        )

    def _calculate_risk_trend(self, scans: List[Dict]) -> str:
        """Calculate risk trend over time"""
        if len(scans) < 2:
            return 'stable'

        # Sort by date
        sorted_scans = sorted(
            [s for s in scans if s.get('created_at')],
            key=lambda x: x['created_at']
        )

        if len(sorted_scans) < 2:
            return 'stable'

        # Compare first half vs second half
        mid = len(sorted_scans) // 2
        first_half = sorted_scans[:mid]
        second_half = sorted_scans[mid:]

        first_avg = statistics.mean([s.get('risk_score', 0) for s in first_half]) if first_half else 0
        second_avg = statistics.mean([s.get('risk_score', 0) for s in second_half]) if second_half else 0

        diff = second_avg - first_avg

        if diff < -5:
            return 'improving'
        elif diff > 5:
            return 'degrading'
        else:
            return 'stable'

    def generate_trend_data(self, scans: List[Dict], interval: str = 'day',
                           days: int = 30) -> List[TrendDataPoint]:
        """Generate trend data for charting"""
        since = datetime.utcnow() - timedelta(days=days)

        # Filter and group scans
        trends = {}

        for scan in scans:
            created = scan.get('created_at')
            if not created:
                continue

            # Parse date
            if isinstance(created, str):
                try:
                    dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                except ValueError:
                    continue
            else:
                dt = created

            if dt < since:
                continue

            # Group by interval
            if interval == 'day':
                key = dt.strftime('%Y-%m-%d')
            elif interval == 'week':
                key = dt.strftime('%Y-W%W')
            else:
                key = dt.strftime('%Y-%m')

            if key not in trends:
                trends[key] = TrendDataPoint(date=key)

            trends[key].scans += 1
            trends[key].findings += scan.get('findings_count', 0)
            trends[key].critical += scan.get('critical_count', 0)
            trends[key].high += scan.get('high_count', 0)
            trends[key].medium += scan.get('medium_count', 0)
            trends[key].low += scan.get('low_count', 0)
            trends[key].info += scan.get('info_count', 0)

            # Update risk score (average)
            if scan.get('risk_score'):
                current = trends[key].risk_score
                count = trends[key].scans
                trends[key].risk_score = ((current * (count - 1)) + scan['risk_score']) / count

        # Sort by date and return
        sorted_trends = sorted(trends.values(), key=lambda x: x.date)
        return sorted_trends

    def compare_periods(self, scans: List[Dict], findings: List[Dict],
                       period1_start: str, period1_end: str,
                       period2_start: str, period2_end: str) -> Dict[str, Any]:
        """Compare two time periods"""
        def parse_date(d):
            if isinstance(d, str):
                return datetime.fromisoformat(d.replace('Z', '+00:00'))
            return d

        p1_start = parse_date(period1_start)
        p1_end = parse_date(period1_end)
        p2_start = parse_date(period2_start)
        p2_end = parse_date(period2_end)

        def filter_by_period(items, start, end):
            result = []
            for item in items:
                created = item.get('created_at')
                if not created:
                    continue
                dt = parse_date(created)
                if start <= dt <= end:
                    result.append(item)
            return result

        p1_scans = filter_by_period(scans, p1_start, p1_end)
        p1_findings = filter_by_period(findings, p1_start, p1_end)
        p2_scans = filter_by_period(scans, p2_start, p2_end)
        p2_findings = filter_by_period(findings, p2_start, p2_end)

        p1_analysis = self.analyze_scans(p1_scans, p1_findings)
        p2_analysis = self.analyze_scans(p2_scans, p2_findings)

        return {
            'period1': {
                'start': period1_start,
                'end': period1_end,
                'analysis': asdict(p1_analysis)
            },
            'period2': {
                'start': period2_start,
                'end': period2_end,
                'analysis': asdict(p2_analysis)
            },
            'comparison': {
                'scans_change': p2_analysis.total_scans - p1_analysis.total_scans,
                'scans_change_pct': self._calc_change_pct(
                    p1_analysis.total_scans, p2_analysis.total_scans
                ),
                'findings_change': p2_analysis.total_findings - p1_analysis.total_findings,
                'findings_change_pct': self._calc_change_pct(
                    p1_analysis.total_findings, p2_analysis.total_findings
                ),
                'risk_score_change': round(
                    p2_analysis.avg_risk_score - p1_analysis.avg_risk_score, 2
                ),
                'critical_change': (
                    p2_analysis.severity_breakdown.get('critical', 0) -
                    p1_analysis.severity_breakdown.get('critical', 0)
                ),
                'high_change': (
                    p2_analysis.severity_breakdown.get('high', 0) -
                    p1_analysis.severity_breakdown.get('high', 0)
                )
            }
        }

    def _calc_change_pct(self, old: int, new: int) -> float:
        """Calculate percentage change"""
        if old == 0:
            return 100.0 if new > 0 else 0.0
        return round(((new - old) / old) * 100, 2)

    def get_vulnerability_insights(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate vulnerability insights and recommendations"""
        if not findings:
            return {
                'total': 0,
                'critical_action_needed': False,
                'insights': [],
                'recommendations': []
            }

        severity_counts = defaultdict(int)
        type_severity = defaultdict(lambda: defaultdict(int))
        urls_affected = defaultdict(set)

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            f_type = finding.get('finding_type', 'unknown')
            url = finding.get('url', '')

            severity_counts[severity] += 1
            type_severity[f_type][severity] += 1
            if url:
                urls_affected[f_type].add(url)

        insights = []
        recommendations = []

        # Generate insights
        if severity_counts.get('critical', 0) > 0:
            insights.append({
                'type': 'critical_alert',
                'message': f"Found {severity_counts['critical']} critical vulnerabilities requiring immediate attention",
                'priority': 'urgent'
            })

        if severity_counts.get('high', 0) > 3:
            insights.append({
                'type': 'high_volume',
                'message': f"High number of high-severity findings ({severity_counts['high']}) detected",
                'priority': 'high'
            })

        # Check for common vulnerability patterns
        common_vulns = {
            'sqli': 'SQL Injection vulnerabilities can lead to data breach. Implement parameterized queries.',
            'xss': 'XSS vulnerabilities found. Implement output encoding and Content Security Policy.',
            'ssrf': 'SSRF vulnerabilities detected. Validate and sanitize all URLs.',
            'idor': 'Broken access control found. Implement proper authorization checks.',
            'auth_bypass': 'Authentication bypass detected. Review authentication mechanisms.',
            'xxe': 'XXE vulnerabilities found. Disable external entity processing.',
        }

        for vuln_type, message in common_vulns.items():
            if vuln_type in type_severity:
                count = sum(type_severity[vuln_type].values())
                recommendations.append({
                    'vulnerability': vuln_type,
                    'count': count,
                    'affected_urls': len(urls_affected.get(vuln_type, [])),
                    'recommendation': message
                })

        return {
            'total': len(findings),
            'critical_action_needed': severity_counts.get('critical', 0) > 0,
            'severity_breakdown': dict(severity_counts),
            'vulnerability_distribution': {
                k: dict(v) for k, v in type_severity.items()
            },
            'insights': insights,
            'recommendations': sorted(
                recommendations,
                key=lambda x: x['count'],
                reverse=True
            )
        }

    def calculate_security_score(self, findings: List[Dict],
                                total_endpoints: int = 0,
                                total_subdomains: int = 0) -> Dict[str, Any]:
        """Calculate overall security score (0-100)"""
        if not findings and not total_endpoints:
            return {
                'score': 100,
                'grade': 'A+',
                'breakdown': {},
                'factors': []
            }

        # Base score starts at 100
        score = 100

        # Deduct points based on findings
        deductions = {
            'critical': 25,
            'high': 15,
            'medium': 5,
            'low': 2,
            'info': 0
        }

        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] += 1

        breakdown = {}
        factors = []

        for severity, deduction in deductions.items():
            count = severity_counts.get(severity, 0)
            total_deduction = min(count * deduction, 40)  # Cap per category
            score -= total_deduction
            breakdown[severity] = {
                'count': count,
                'deduction': total_deduction
            }
            if count > 0:
                factors.append(f"{count} {severity} severity finding(s) (-{total_deduction} points)")

        # Ensure score is between 0 and 100
        score = max(0, min(100, score))

        # Determine grade
        if score >= 95:
            grade = 'A+'
        elif score >= 90:
            grade = 'A'
        elif score >= 85:
            grade = 'A-'
        elif score >= 80:
            grade = 'B+'
        elif score >= 75:
            grade = 'B'
        elif score >= 70:
            grade = 'B-'
        elif score >= 65:
            grade = 'C+'
        elif score >= 60:
            grade = 'C'
        elif score >= 55:
            grade = 'C-'
        elif score >= 50:
            grade = 'D'
        else:
            grade = 'F'

        return {
            'score': round(score, 1),
            'grade': grade,
            'breakdown': breakdown,
            'factors': factors,
            'total_findings': len(findings),
            'scope': {
                'endpoints_tested': total_endpoints,
                'subdomains_discovered': total_subdomains
            }
        }

    def generate_report_data(self, scans: List[Dict], findings: List[Dict],
                            subdomains: List[Dict] = None,
                            endpoints: List[Dict] = None) -> Dict[str, Any]:
        """Generate complete analytics data for reporting"""
        subdomains = subdomains or []
        endpoints = endpoints or []

        # Basic analytics
        summary = self.analyze_scans(scans, findings)

        # Trend data (last 30 days)
        trends = self.generate_trend_data(scans, interval='day', days=30)

        # Vulnerability insights
        insights = self.get_vulnerability_insights(findings)

        # Security score
        score = self.calculate_security_score(
            findings,
            total_endpoints=len(endpoints),
            total_subdomains=len(subdomains)
        )

        return {
            'generated_at': datetime.utcnow().isoformat(),
            'summary': asdict(summary),
            'trends': [asdict(t) for t in trends],
            'insights': insights,
            'security_score': score,
            'charts_data': {
                'severity_pie': {
                    'labels': ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    'values': [
                        summary.severity_breakdown.get('critical', 0),
                        summary.severity_breakdown.get('high', 0),
                        summary.severity_breakdown.get('medium', 0),
                        summary.severity_breakdown.get('low', 0),
                        summary.severity_breakdown.get('info', 0)
                    ]
                },
                'trend_line': {
                    'labels': [t.date for t in trends],
                    'findings': [t.findings for t in trends],
                    'risk_scores': [t.risk_score for t in trends]
                },
                'vuln_types_bar': {
                    'labels': [v['type'] for v in summary.top_vulnerabilities[:10]],
                    'values': [v['count'] for v in summary.top_vulnerabilities[:10]]
                }
            }
        }

    def export_analytics(self, data: Dict[str, Any], output_path: str,
                        format: str = 'json') -> str:
        """Export analytics data to file"""
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return output_path


class ComparisonReport:
    """Generate comparison reports between scans or time periods"""

    def __init__(self, analytics: SecurityAnalytics = None):
        self.analytics = analytics or SecurityAnalytics()

    def compare_scans(self, scan1_data: Dict, scan2_data: Dict) -> Dict[str, Any]:
        """Compare two individual scans"""
        findings1 = scan1_data.get('findings', [])
        findings2 = scan2_data.get('findings', [])

        # Create finding hashes for comparison
        def get_finding_key(f):
            return f"{f.get('title', '')}:{f.get('url', '')}:{f.get('parameter', '')}"

        findings1_keys = {get_finding_key(f): f for f in findings1}
        findings2_keys = {get_finding_key(f): f for f in findings2}

        new_findings = [f for k, f in findings2_keys.items() if k not in findings1_keys]
        resolved_findings = [f for k, f in findings1_keys.items() if k not in findings2_keys]
        persistent_findings = [f for k, f in findings2_keys.items() if k in findings1_keys]

        return {
            'scan1': {
                'id': scan1_data.get('id'),
                'date': scan1_data.get('created_at'),
                'total_findings': len(findings1),
                'risk_score': scan1_data.get('risk_score', 0)
            },
            'scan2': {
                'id': scan2_data.get('id'),
                'date': scan2_data.get('created_at'),
                'total_findings': len(findings2),
                'risk_score': scan2_data.get('risk_score', 0)
            },
            'comparison': {
                'new_findings': len(new_findings),
                'resolved_findings': len(resolved_findings),
                'persistent_findings': len(persistent_findings),
                'net_change': len(findings2) - len(findings1),
                'risk_change': (
                    scan2_data.get('risk_score', 0) - scan1_data.get('risk_score', 0)
                )
            },
            'details': {
                'new': new_findings,
                'resolved': resolved_findings,
                'persistent': persistent_findings
            },
            'generated_at': datetime.utcnow().isoformat()
        }

    def generate_comparison_html(self, comparison: Dict) -> str:
        """Generate HTML comparison report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Scan Comparison Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; text-align: center; }}
        .comparison-grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin: 30px 0; }}
        .card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .card.new {{ border-left: 4px solid #ff6b6b; }}
        .card.resolved {{ border-left: 4px solid #1dd1a1; }}
        .card.persistent {{ border-left: 4px solid #feca57; }}
        .card .number {{ font-size: 3em; font-weight: bold; }}
        .card.new .number {{ color: #ff6b6b; }}
        .card.resolved .number {{ color: #1dd1a1; }}
        .card.persistent .number {{ color: #feca57; }}
        .findings-list {{ margin: 20px 0; }}
        .finding-item {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 3px solid #ddd; }}
        .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
        .badge.critical {{ background: #ff0054; color: white; }}
        .badge.high {{ background: #ff6b6b; color: white; }}
        .badge.medium {{ background: #feca57; color: black; }}
        .badge.low {{ background: #48dbfb; color: black; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Scan Comparison Report</h1>
        <p style="text-align: center; color: #666;">Generated: {comparison['generated_at']}</p>

        <div class="comparison-grid">
            <div class="card new">
                <div class="number">{comparison['comparison']['new_findings']}</div>
                <div>New Findings</div>
            </div>
            <div class="card resolved">
                <div class="number">{comparison['comparison']['resolved_findings']}</div>
                <div>Resolved</div>
            </div>
            <div class="card persistent">
                <div class="number">{comparison['comparison']['persistent_findings']}</div>
                <div>Persistent</div>
            </div>
        </div>

        <h2>Scan Details</h2>
        <table style="width: 100%; border-collapse: collapse;">
            <tr>
                <th style="text-align: left; padding: 10px; border-bottom: 2px solid #ddd;">Metric</th>
                <th style="text-align: center; padding: 10px; border-bottom: 2px solid #ddd;">Scan 1</th>
                <th style="text-align: center; padding: 10px; border-bottom: 2px solid #ddd;">Scan 2</th>
                <th style="text-align: center; padding: 10px; border-bottom: 2px solid #ddd;">Change</th>
            </tr>
            <tr>
                <td style="padding: 10px;">Total Findings</td>
                <td style="text-align: center;">{comparison['scan1']['total_findings']}</td>
                <td style="text-align: center;">{comparison['scan2']['total_findings']}</td>
                <td style="text-align: center;">{comparison['comparison']['net_change']:+d}</td>
            </tr>
            <tr>
                <td style="padding: 10px;">Risk Score</td>
                <td style="text-align: center;">{comparison['scan1']['risk_score']}%</td>
                <td style="text-align: center;">{comparison['scan2']['risk_score']}%</td>
                <td style="text-align: center;">{comparison['comparison']['risk_change']:+.1f}%</td>
            </tr>
        </table>
"""

        # New findings section
        if comparison['details']['new']:
            html += "<h2 style='color: #ff6b6b;'>New Findings</h2><div class='findings-list'>"
            for f in comparison['details']['new'][:10]:
                severity = f.get('severity', 'info').lower()
                html += f"""
                <div class="finding-item">
                    <span class="badge {severity}">{severity.upper()}</span>
                    <strong>{f.get('title', 'Unknown')}</strong>
                    <p>{f.get('description', '')[:200]}</p>
                </div>"""
            html += "</div>"

        # Resolved findings section
        if comparison['details']['resolved']:
            html += "<h2 style='color: #1dd1a1;'>Resolved Findings</h2><div class='findings-list'>"
            for f in comparison['details']['resolved'][:10]:
                severity = f.get('severity', 'info').lower()
                html += f"""
                <div class="finding-item">
                    <span class="badge {severity}">{severity.upper()}</span>
                    <strong>{f.get('title', 'Unknown')}</strong>
                </div>"""
            html += "</div>"

        html += """
    </div>
</body>
</html>"""

        return html


if __name__ == "__main__":
    # Example usage
    analytics = SecurityAnalytics()

    # Sample data
    sample_scans = [
        {
            'id': 1,
            'target_id': 1,
            'created_at': datetime.now().isoformat(),
            'findings_count': 5,
            'critical_count': 1,
            'high_count': 2,
            'medium_count': 1,
            'low_count': 1,
            'info_count': 0,
            'risk_score': 75.5
        }
    ]

    sample_findings = [
        {'title': 'SQL Injection', 'severity': 'critical', 'finding_type': 'sqli', 'tool': 'sqlmap'},
        {'title': 'XSS', 'severity': 'high', 'finding_type': 'xss', 'tool': 'dalfox'},
        {'title': 'SSRF', 'severity': 'high', 'finding_type': 'ssrf', 'tool': 'ssrf_tester'},
        {'title': 'Info Disclosure', 'severity': 'medium', 'finding_type': 'info_disclosure', 'tool': 'nuclei'},
        {'title': 'Missing Header', 'severity': 'low', 'finding_type': 'header', 'tool': 'nuclei'}
    ]

    # Generate analytics
    report_data = analytics.generate_report_data(sample_scans, sample_findings)
    print(json.dumps(report_data, indent=2))
