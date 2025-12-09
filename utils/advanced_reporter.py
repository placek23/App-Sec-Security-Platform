"""
Advanced Reporter - Enhanced reporting with CVSS scoring, analytics, and database integration.
"""
import os
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field

from jinja2 import Environment, FileSystemLoader, select_autoescape


@dataclass
class CVSSVector:
    """CVSS 3.1 Vector components"""
    # Base metrics
    attack_vector: str = 'N'  # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = 'L'  # L=Low, H=High
    privileges_required: str = 'N'  # N=None, L=Low, H=High
    user_interaction: str = 'N'  # N=None, R=Required
    scope: str = 'U'  # U=Unchanged, C=Changed
    confidentiality_impact: str = 'N'  # N=None, L=Low, H=High
    integrity_impact: str = 'N'  # N=None, L=Low, H=High
    availability_impact: str = 'N'  # N=None, L=Low, H=High

    def to_vector_string(self) -> str:
        """Generate CVSS 3.1 vector string"""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality_impact}/"
            f"I:{self.integrity_impact}/A:{self.availability_impact}"
        )

    def calculate_score(self) -> Tuple[float, str]:
        """Calculate CVSS 3.1 base score"""
        # Impact sub-score weights
        impact_weights = {
            'N': 0.0,
            'L': 0.22,
            'H': 0.56
        }

        # Calculate Impact Sub Score (ISS)
        iss = 1 - (
            (1 - impact_weights.get(self.confidentiality_impact, 0)) *
            (1 - impact_weights.get(self.integrity_impact, 0)) *
            (1 - impact_weights.get(self.availability_impact, 0))
        )

        # Calculate Impact
        if self.scope == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Exploitability weights
        av_weights = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        ac_weights = {'L': 0.77, 'H': 0.44}
        pr_weights_unchanged = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        pr_weights_changed = {'N': 0.85, 'L': 0.68, 'H': 0.5}
        ui_weights = {'N': 0.85, 'R': 0.62}

        pr_weights = pr_weights_changed if self.scope == 'C' else pr_weights_unchanged

        # Calculate Exploitability
        exploitability = (
            8.22 *
            av_weights.get(self.attack_vector, 0.85) *
            ac_weights.get(self.attack_complexity, 0.77) *
            pr_weights.get(self.privileges_required, 0.85) *
            ui_weights.get(self.user_interaction, 0.85)
        )

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif self.scope == 'U':
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round up to nearest 0.1
        base_score = round(base_score * 10) / 10

        # Determine severity rating
        if base_score == 0:
            rating = 'None'
        elif base_score < 4.0:
            rating = 'Low'
        elif base_score < 7.0:
            rating = 'Medium'
        elif base_score < 9.0:
            rating = 'High'
        else:
            rating = 'Critical'

        return base_score, rating


@dataclass
class EnhancedFinding:
    """Enhanced finding with CVSS and additional metadata"""
    id: str = ''
    title: str = ''
    description: str = ''
    severity: str = 'info'
    finding_type: str = ''
    tool: str = ''
    url: str = ''
    parameter: str = ''
    method: str = 'GET'
    payload: str = ''
    evidence: str = ''
    request: str = ''
    response: str = ''
    cwe_id: str = ''
    cve_id: str = ''
    cvss_vector: Optional[CVSSVector] = None
    cvss_score: float = 0.0
    cvss_rating: str = ''
    remediation: str = ''
    references: List[str] = field(default_factory=list)
    is_false_positive: bool = False
    is_verified: bool = False
    notes: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ''

    def __post_init__(self):
        if not self.id:
            self.id = self._generate_id()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if self.cvss_vector and not self.cvss_score:
            self.cvss_score, self.cvss_rating = self.cvss_vector.calculate_score()

    def _generate_id(self) -> str:
        """Generate unique finding ID"""
        content = f"{self.title}:{self.url}:{self.parameter}:{self.finding_type}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        if self.cvss_vector:
            data['cvss_vector'] = self.cvss_vector.to_vector_string()
        return data


# Common vulnerability type mappings to CWE and CVSS
VULNERABILITY_MAPPINGS = {
    'sqli': {
        'cwe': 'CWE-89',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='C', confidentiality_impact='H',
            integrity_impact='H', availability_impact='H'
        ),
        'remediation': 'Use parameterized queries or prepared statements. Implement input validation and sanitization.'
    },
    'xss': {
        'cwe': 'CWE-79',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='R',
            scope='C', confidentiality_impact='L',
            integrity_impact='L', availability_impact='N'
        ),
        'remediation': 'Implement proper output encoding. Use Content Security Policy (CSP) headers.'
    },
    'ssrf': {
        'cwe': 'CWE-918',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='C', confidentiality_impact='H',
            integrity_impact='L', availability_impact='N'
        ),
        'remediation': 'Implement strict URL validation. Use allowlists for permitted destinations.'
    },
    'xxe': {
        'cwe': 'CWE-611',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='C', confidentiality_impact='H',
            integrity_impact='L', availability_impact='L'
        ),
        'remediation': 'Disable external entity processing in XML parsers. Use JSON instead of XML where possible.'
    },
    'idor': {
        'cwe': 'CWE-639',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='L', user_interaction='N',
            scope='U', confidentiality_impact='H',
            integrity_impact='L', availability_impact='N'
        ),
        'remediation': 'Implement proper authorization checks. Use indirect references or UUIDs.'
    },
    'auth_bypass': {
        'cwe': 'CWE-287',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='U', confidentiality_impact='H',
            integrity_impact='H', availability_impact='H'
        ),
        'remediation': 'Implement robust authentication mechanisms. Use multi-factor authentication.'
    },
    'rce': {
        'cwe': 'CWE-78',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='C', confidentiality_impact='H',
            integrity_impact='H', availability_impact='H'
        ),
        'remediation': 'Avoid system command execution with user input. Use allowlists and input validation.'
    },
    'lfi': {
        'cwe': 'CWE-98',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='U', confidentiality_impact='H',
            integrity_impact='N', availability_impact='N'
        ),
        'remediation': 'Use allowlists for file paths. Avoid user input in file operations.'
    },
    'open_redirect': {
        'cwe': 'CWE-601',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='R',
            scope='C', confidentiality_impact='L',
            integrity_impact='L', availability_impact='N'
        ),
        'remediation': 'Validate and sanitize redirect URLs. Use allowlists for permitted destinations.'
    },
    'cors': {
        'cwe': 'CWE-942',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='R',
            scope='U', confidentiality_impact='L',
            integrity_impact='L', availability_impact='N'
        ),
        'remediation': 'Configure strict CORS policies. Avoid reflecting arbitrary origins.'
    },
    'jwt_weak': {
        'cwe': 'CWE-347',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='U', confidentiality_impact='H',
            integrity_impact='H', availability_impact='N'
        ),
        'remediation': 'Use strong JWT secrets. Implement proper algorithm verification.'
    },
    'info_disclosure': {
        'cwe': 'CWE-200',
        'cvss': CVSSVector(
            attack_vector='N', attack_complexity='L',
            privileges_required='N', user_interaction='N',
            scope='U', confidentiality_impact='L',
            integrity_impact='N', availability_impact='N'
        ),
        'remediation': 'Remove sensitive information from responses. Implement proper error handling.'
    }
}


class AdvancedReporter:
    """Advanced security reporter with CVSS, analytics, and multiple formats"""

    def __init__(self, output_dir: str = './output/reports', template_dir: str = None):
        """Initialize advanced reporter"""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.findings: List[EnhancedFinding] = []
        self.subdomains: List[Dict] = []
        self.endpoints: List[Dict] = []
        self.metadata: Dict[str, Any] = {
            'title': 'Security Assessment Report',
            'target': '',
            'tester': 'AppSec Bounty Platform',
            'created_at': datetime.now().isoformat()
        }

        # Setup Jinja2 environment
        if template_dir is None:
            template_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'templates', 'reports'
            )
        os.makedirs(template_dir, exist_ok=True)

        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def set_metadata(self, **kwargs):
        """Set report metadata"""
        self.metadata.update(kwargs)

    def add_finding(self, title: str, severity: str, finding_type: str = None,
                    auto_enrich: bool = True, **kwargs) -> EnhancedFinding:
        """Add a finding with optional auto-enrichment"""
        finding = EnhancedFinding(
            title=title,
            severity=severity.lower(),
            finding_type=finding_type,
            **kwargs
        )

        # Auto-enrich with CVSS and CWE if type is known
        if auto_enrich and finding_type and finding_type.lower() in VULNERABILITY_MAPPINGS:
            mapping = VULNERABILITY_MAPPINGS[finding_type.lower()]

            if not finding.cwe_id:
                finding.cwe_id = mapping['cwe']

            if not finding.cvss_vector:
                finding.cvss_vector = mapping['cvss']
                finding.cvss_score, finding.cvss_rating = finding.cvss_vector.calculate_score()

            if not finding.remediation:
                finding.remediation = mapping['remediation']

        self.findings.append(finding)
        return finding

    def add_findings_batch(self, findings: List[Dict], auto_enrich: bool = True):
        """Add multiple findings from dict format"""
        for f_data in findings:
            self.add_finding(auto_enrich=auto_enrich, **f_data)

    def add_subdomain(self, domain: str, **kwargs):
        """Add discovered subdomain"""
        self.subdomains.append({'domain': domain, **kwargs})

    def add_subdomains_batch(self, subdomains: List[Dict]):
        """Add multiple subdomains"""
        self.subdomains.extend(subdomains)

    def add_endpoint(self, url: str, **kwargs):
        """Add discovered endpoint"""
        self.endpoints.append({'url': url, **kwargs})

    def add_endpoints_batch(self, endpoints: List[Dict]):
        """Add multiple endpoints"""
        self.endpoints.extend(endpoints)

    def generate_summary(self) -> Dict[str, Any]:
        """Generate comprehensive summary statistics"""
        severity_counts = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }

        total_cvss = 0
        finding_types = {}

        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

            if finding.cvss_score:
                total_cvss += finding.cvss_score

            f_type = finding.finding_type or 'unknown'
            finding_types[f_type] = finding_types.get(f_type, 0) + 1

        total_findings = len(self.findings)
        avg_cvss = round(total_cvss / total_findings, 2) if total_findings > 0 else 0

        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts, total_findings)

        # Determine risk rating
        if severity_counts['critical'] > 0:
            risk_rating = 'Critical'
        elif severity_counts['high'] > 0:
            risk_rating = 'High'
        elif severity_counts['medium'] > 0:
            risk_rating = 'Medium'
        elif severity_counts['low'] > 0:
            risk_rating = 'Low'
        else:
            risk_rating = 'Informational'

        return {
            'total_findings': total_findings,
            'severity_breakdown': severity_counts,
            'finding_types': finding_types,
            'total_subdomains': len(self.subdomains),
            'total_endpoints': len(self.endpoints),
            'risk_score': risk_score,
            'risk_rating': risk_rating,
            'average_cvss': avg_cvss,
            'verified_findings': sum(1 for f in self.findings if f.is_verified),
            'false_positives': sum(1 for f in self.findings if f.is_false_positive),
            'generated_at': datetime.now().isoformat()
        }

    def _calculate_risk_score(self, severity_counts: Dict, total: int) -> float:
        """Calculate overall risk score (0-100)"""
        if total == 0:
            return 0

        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        weighted_sum = sum(severity_counts[s] * weights[s] for s in severity_counts)
        max_possible = total * 10

        return round((weighted_sum / max_possible) * 100, 2)

    def get_findings_by_severity(self) -> Dict[str, List[EnhancedFinding]]:
        """Group findings by severity"""
        grouped = {
            'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []
        }
        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in grouped:
                grouped[sev].append(finding)
        return grouped

    def get_findings_by_type(self) -> Dict[str, List[EnhancedFinding]]:
        """Group findings by type"""
        grouped = {}
        for finding in self.findings:
            f_type = finding.finding_type or 'other'
            if f_type not in grouped:
                grouped[f_type] = []
            grouped[f_type].append(finding)
        return grouped

    def export_json(self, filename: str = None) -> str:
        """Export report to JSON"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)

        report = {
            'metadata': self.metadata,
            'summary': self.generate_summary(),
            'findings': [f.to_dict() for f in self.findings],
            'subdomains': self.subdomains,
            'endpoints': self.endpoints
        }

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return filepath

    def export_html(self, filename: str = None, template: str = 'report.html') -> str:
        """Export report to HTML using Jinja2 template"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.html"

        filepath = os.path.join(self.output_dir, filename)

        # Try to load custom template, fall back to built-in
        try:
            tmpl = self.jinja_env.get_template(template)
        except Exception:
            # Use built-in HTML generation
            html = self._generate_builtin_html()
            with open(filepath, 'w') as f:
                f.write(html)
            return filepath

        summary = self.generate_summary()
        grouped_findings = self.get_findings_by_severity()

        html = tmpl.render(
            metadata=self.metadata,
            summary=summary,
            findings=self.findings,
            grouped_findings=grouped_findings,
            subdomains=self.subdomains,
            endpoints=self.endpoints
        )

        with open(filepath, 'w') as f:
            f.write(html)

        return filepath

    def _generate_builtin_html(self) -> str:
        """Generate HTML report with built-in template"""
        summary = self.generate_summary()

        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.get(x.severity.lower(), 5)
        )

        findings_html = ""
        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.severity.lower()
            findings_html += f'''
            <div class="finding {severity}">
                <div class="finding-header">
                    <span class="finding-title">#{i}. {finding.title}</span>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>
                <dl class="finding-details">
                    <dt>Tool</dt><dd>{finding.tool or 'Unknown'}</dd>
                    <dt>Type</dt><dd>{finding.finding_type or 'Unknown'}</dd>
                    {'<dt>CVSS Score</dt><dd>' + str(finding.cvss_score) + ' (' + finding.cvss_rating + ')</dd>' if finding.cvss_score else ''}
                    {'<dt>CWE</dt><dd>' + finding.cwe_id + '</dd>' if finding.cwe_id else ''}
                    <dt>Description</dt><dd>{finding.description or 'No description'}</dd>
                    {'<dt>URL</dt><dd><code>' + finding.url + '</code></dd>' if finding.url else ''}
                    {'<dt>Parameter</dt><dd><code>' + finding.parameter + '</code></dd>' if finding.parameter else ''}
                    {'<dt>Evidence</dt><dd><pre>' + (finding.evidence[:1000] if finding.evidence else '') + '</pre></dd>' if finding.evidence else ''}
                    {'<dt>Remediation</dt><dd>' + finding.remediation + '</dd>' if finding.remediation else ''}
                </dl>
            </div>'''

        subdomains_html = ""
        if self.subdomains:
            subdomains_html = '''<table>
                <tr><th>Subdomain</th><th>IP</th><th>Status</th><th>Source</th></tr>'''
            for sub in self.subdomains[:100]:
                subdomains_html += f'''
                <tr>
                    <td><code>{sub.get('domain', '-')}</code></td>
                    <td>{sub.get('ip', sub.get('ip_address', '-'))}</td>
                    <td>{sub.get('status_code', '-')}</td>
                    <td>{sub.get('source', '-')}</td>
                </tr>'''
            subdomains_html += '</table>'
            if len(self.subdomains) > 100:
                subdomains_html += f'<p><em>Showing 100 of {len(self.subdomains)} subdomains</em></p>'
        else:
            subdomains_html = '<p>No subdomains discovered.</p>'

        endpoints_html = ""
        if self.endpoints:
            endpoints_html = '''<table>
                <tr><th>URL</th><th>Method</th><th>Status</th></tr>'''
            for ep in self.endpoints[:100]:
                endpoints_html += f'''
                <tr>
                    <td><code>{ep.get('url', '-')[:80]}...</code></td>
                    <td>{ep.get('method', 'GET')}</td>
                    <td>{ep.get('status_code', '-')}</td>
                </tr>'''
            endpoints_html += '</table>'
            if len(self.endpoints) > 100:
                endpoints_html += f'<p><em>Showing 100 of {len(self.endpoints)} endpoints</em></p>'
        else:
            endpoints_html = '<p>No endpoints discovered.</p>'

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.metadata.get('title', 'Security Report')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 40px 20px; border-bottom: 3px solid #e94560; }}
        h1 {{ color: #e94560; font-size: 2.5em; margin-bottom: 10px; }}
        h2 {{ color: #e94560; margin: 30px 0 15px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .meta {{ color: #888; font-size: 0.9em; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; margin: 30px 0; }}
        .summary-card {{ background: #1a1a2e; border-radius: 10px; padding: 20px;
            text-align: center; border: 1px solid #333; }}
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
        .finding {{ background: #1a1a2e; border-radius: 10px; padding: 20px;
            margin: 15px 0; border-left: 4px solid #333; }}
        .finding.critical {{ border-left-color: #ff0054; }}
        .finding.high {{ border-left-color: #ff6b6b; }}
        .finding.medium {{ border-left-color: #feca57; }}
        .finding.low {{ border-left-color: #48dbfb; }}
        .finding.info {{ border-left-color: #1dd1a1; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
        .finding-title {{ font-size: 1.2em; font-weight: bold; color: #fff; }}
        .severity-badge {{ padding: 5px 15px; border-radius: 20px; font-size: 0.8em;
            font-weight: bold; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #ff0054; color: white; }}
        .severity-badge.high {{ background: #ff6b6b; color: white; }}
        .severity-badge.medium {{ background: #feca57; color: black; }}
        .severity-badge.low {{ background: #48dbfb; color: black; }}
        .severity-badge.info {{ background: #1dd1a1; color: black; }}
        .finding-details {{ margin-top: 15px; }}
        .finding-details dt {{ color: #888; font-size: 0.9em; margin-top: 10px; }}
        .finding-details dd {{ color: #e0e0e0; margin-left: 0; }}
        code {{ background: #0a0a0a; padding: 2px 8px; border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9em; color: #e94560; }}
        pre {{ background: #0a0a0a; padding: 15px; border-radius: 8px;
            overflow-x: auto; font-size: 0.85em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #1a1a2e; color: #e94560; }}
        tr:hover {{ background: #1a1a2e; }}
        .risk-score {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center; }}
        .risk-score .value {{ font-size: 3em; font-weight: bold; color: #e94560; }}
        footer {{ text-align: center; padding: 30px; color: #666;
            border-top: 1px solid #333; margin-top: 50px; }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>{self.metadata.get('title', 'Security Assessment Report')}</h1>
            <p class="meta">Target: <code>{self.metadata.get('target', 'Unknown')}</code></p>
            <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p class="meta">By: {self.metadata.get('tester', 'AppSec Bounty Platform')}</p>
        </div>
    </header>

    <div class="container">
        <h2>Executive Summary</h2>

        <div class="risk-score">
            <div class="value">{summary['risk_rating']}</div>
            <div>Overall Risk Rating</div>
            <div>Risk Score: {summary['risk_score']}% | Average CVSS: {summary['average_cvss']}</div>
        </div>

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

        <h2>Findings</h2>
        {findings_html if self.findings else '<div class="no-findings">No vulnerabilities found</div>'}

        <h2>Discovered Subdomains</h2>
        {subdomains_html}

        <h2>Discovered Endpoints</h2>
        {endpoints_html}
    </div>

    <footer>
        <p>Generated by AppSec Bounty Platform</p>
        <p>This report contains sensitive security information. Handle appropriately.</p>
    </footer>
</body>
</html>'''

    def export_markdown(self, filename: str = None) -> str:
        """Export report to Markdown"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.md"

        filepath = os.path.join(self.output_dir, filename)
        summary = self.generate_summary()

        md = f"""# {self.metadata.get('title', 'Security Assessment Report')}

**Target:** `{self.metadata.get('target', 'Unknown')}`
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**By:** {self.metadata.get('tester', 'AppSec Bounty Platform')}

---

## Executive Summary

**Overall Risk Rating:** {summary['risk_rating']}
**Risk Score:** {summary['risk_score']}%
**Average CVSS:** {summary['average_cvss']}

### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | {summary['severity_breakdown']['critical']} | {self._calc_pct(summary['severity_breakdown']['critical'], summary['total_findings'])} |
| High | {summary['severity_breakdown']['high']} | {self._calc_pct(summary['severity_breakdown']['high'], summary['total_findings'])} |
| Medium | {summary['severity_breakdown']['medium']} | {self._calc_pct(summary['severity_breakdown']['medium'], summary['total_findings'])} |
| Low | {summary['severity_breakdown']['low']} | {self._calc_pct(summary['severity_breakdown']['low'], summary['total_findings'])} |
| Info | {summary['severity_breakdown']['info']} | {self._calc_pct(summary['severity_breakdown']['info'], summary['total_findings'])} |

- **Total Findings:** {summary['total_findings']}
- **Subdomains Discovered:** {summary['total_subdomains']}
- **Endpoints Discovered:** {summary['total_endpoints']}

---

## Findings

"""

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.get(x.severity.lower(), 5)
        )

        for i, finding in enumerate(sorted_findings, 1):
            md += f"""### #{i}. [{finding.severity.upper()}] {finding.title}

- **Tool:** {finding.tool or 'Unknown'}
- **Type:** {finding.finding_type or 'Unknown'}
"""
            if finding.cvss_score:
                md += f"- **CVSS Score:** {finding.cvss_score} ({finding.cvss_rating})\n"
            if finding.cwe_id:
                md += f"- **CWE:** {finding.cwe_id}\n"
            if finding.url:
                md += f"- **URL:** `{finding.url}`\n"
            if finding.parameter:
                md += f"- **Parameter:** `{finding.parameter}`\n"

            md += f"\n**Description:** {finding.description or 'No description'}\n\n"

            if finding.evidence:
                md += f"**Evidence:**\n```\n{finding.evidence[:500]}\n```\n\n"

            if finding.remediation:
                md += f"**Remediation:** {finding.remediation}\n\n"

            md += "---\n\n"

        with open(filepath, 'w') as f:
            f.write(md)

        return filepath

    def export_pdf(self, filename: str = None) -> str:
        """Export report to PDF"""
        from utils.pdf_generator import PDFReportGenerator

        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.pdf"

        # Prepare data for PDF generator
        report_data = {
            'title': self.metadata.get('title', 'Security Assessment Report'),
            'target': self.metadata.get('target', 'Unknown'),
            'tester': self.metadata.get('tester', 'AppSec Bounty Platform'),
            'summary': self.generate_summary(),
            'findings': [f.to_dict() for f in self.findings],
            'subdomains': self.subdomains,
            'endpoints': self.endpoints
        }

        generator = PDFReportGenerator(self.output_dir)
        return generator.generate(report_data, filename)

    def export_all(self, base_filename: str = None) -> Dict[str, str]:
        """Export report in all formats"""
        if base_filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_filename = f"report_{timestamp}"

        paths = {
            'json': self.export_json(f"{base_filename}.json"),
            'html': self.export_html(f"{base_filename}.html"),
            'markdown': self.export_markdown(f"{base_filename}.md"),
        }

        try:
            paths['pdf'] = self.export_pdf(f"{base_filename}.pdf")
        except ImportError:
            pass  # PDF generation optional

        return paths

    def _calc_pct(self, count: int, total: int) -> str:
        """Calculate percentage string"""
        if total == 0:
            return "0%"
        return f"{round((count / total) * 100, 1)}%"


if __name__ == "__main__":
    # Example usage
    reporter = AdvancedReporter()
    reporter.set_metadata(
        title='Security Assessment Report',
        target='example.com',
        tester='Security Team'
    )

    # Add findings with auto-enrichment
    reporter.add_finding(
        title='SQL Injection in Login Form',
        severity='critical',
        finding_type='sqli',
        tool='sqlmap',
        url='https://example.com/login',
        parameter='username',
        description='SQL injection vulnerability allowing database access',
        evidence="Error: You have an error in your SQL syntax"
    )

    reporter.add_finding(
        title='Reflected XSS in Search',
        severity='medium',
        finding_type='xss',
        tool='dalfox',
        url='https://example.com/search',
        parameter='q'
    )

    # Add subdomains
    reporter.add_subdomain('api.example.com', ip='192.168.1.1', status_code=200)
    reporter.add_subdomain('mail.example.com', ip='192.168.1.2', status_code=200)

    # Export all formats
    paths = reporter.export_all()
    print("Generated reports:")
    for fmt, path in paths.items():
        print(f"  {fmt}: {path}")
