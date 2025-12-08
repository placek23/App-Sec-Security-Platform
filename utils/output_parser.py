"""
Output Parser - Standardize output from various security tools
"""
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Standardized finding/vulnerability structure"""
    tool: str
    target: str
    finding_type: str
    title: str
    description: str
    severity: Severity
    evidence: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    remediation: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


@dataclass
class Subdomain:
    """Subdomain discovery result"""
    domain: str
    source: str
    ip: str = ""
    status_code: int = 0
    title: str = ""
    technologies: List[str] = None
    
    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []


@dataclass
class Endpoint:
    """Discovered endpoint"""
    url: str
    method: str = "GET"
    parameters: List[str] = None
    status_code: int = 0
    content_type: str = ""
    source: str = ""
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []


class OutputParser:
    """Parse and normalize output from various security tools"""
    
    @staticmethod
    def parse_subfinder(output: str) -> List[Subdomain]:
        """Parse subfinder output"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('['):
                results.append(Subdomain(domain=line, source="subfinder"))
        return results
    
    @staticmethod
    def parse_amass(output: str) -> List[Subdomain]:
        """Parse amass output"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('['):
                # Amass outputs: domain (source)
                match = re.match(r'^([^\s]+)(?:\s+\(([^)]+)\))?', line)
                if match:
                    domain = match.group(1)
                    source = match.group(2) if match.group(2) else "amass"
                    results.append(Subdomain(domain=domain, source=source))
        return results
    
    @staticmethod
    def parse_httpx(output: str) -> List[Subdomain]:
        """Parse httpx JSON output"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(Subdomain(
                    domain=data.get('input', ''),
                    source="httpx",
                    ip=data.get('host', ''),
                    status_code=data.get('status_code', 0),
                    title=data.get('title', ''),
                    technologies=data.get('tech', [])
                ))
            except json.JSONDecodeError:
                # Plain text output
                if line.startswith('http'):
                    results.append(Subdomain(domain=line, source="httpx"))
        return results
    
    @staticmethod
    def parse_katana(output: str) -> List[Endpoint]:
        """Parse katana output"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                results.append(Endpoint(url=line, source="katana"))
        return results
    
    @staticmethod
    def parse_gau(output: str) -> List[Endpoint]:
        """Parse gau output"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                # Extract parameters from URL
                params = []
                if '?' in line:
                    param_str = line.split('?')[1].split('#')[0]
                    params = [p.split('=')[0] for p in param_str.split('&') if '=' in p]
                results.append(Endpoint(url=line, parameters=params, source="gau"))
        return results
    
    @staticmethod
    def parse_ffuf(output: str) -> List[Endpoint]:
        """Parse ffuf JSON output"""
        results = []
        try:
            data = json.loads(output)
            for result in data.get('results', []):
                results.append(Endpoint(
                    url=result.get('url', ''),
                    status_code=result.get('status', 0),
                    content_type=result.get('content-type', ''),
                    source="ffuf"
                ))
        except json.JSONDecodeError:
            # Plain text fallback
            for line in output.strip().split('\n'):
                if 'Status:' in line:
                    match = re.search(r'\[Status: (\d+).*\] (.+)', line)
                    if match:
                        results.append(Endpoint(
                            url=match.group(2),
                            status_code=int(match.group(1)),
                            source="ffuf"
                        ))
        return results
    
    @staticmethod
    def parse_nuclei(output: str) -> List[Finding]:
        """Parse nuclei JSON output"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                severity_map = {
                    'info': Severity.INFO,
                    'low': Severity.LOW,
                    'medium': Severity.MEDIUM,
                    'high': Severity.HIGH,
                    'critical': Severity.CRITICAL
                }
                results.append(Finding(
                    tool="nuclei",
                    target=data.get('host', ''),
                    finding_type=data.get('type', 'vulnerability'),
                    title=data.get('info', {}).get('name', ''),
                    description=data.get('info', {}).get('description', ''),
                    severity=severity_map.get(data.get('info', {}).get('severity', 'info'), Severity.INFO),
                    url=data.get('matched-at', ''),
                    evidence=data.get('matcher-name', ''),
                    references=data.get('info', {}).get('reference', [])
                ))
            except json.JSONDecodeError:
                continue
        return results
    
    @staticmethod
    def parse_sqlmap(output: str) -> List[Finding]:
        """Parse sqlmap output"""
        results = []
        
        # Look for injection points
        vuln_pattern = re.compile(r'Parameter: ([^\s]+).*is vulnerable')
        for match in vuln_pattern.finditer(output):
            results.append(Finding(
                tool="sqlmap",
                target="",
                finding_type="sqli",
                title="SQL Injection",
                description=f"SQL injection vulnerability found in parameter: {match.group(1)}",
                severity=Severity.HIGH,
                parameter=match.group(1)
            ))
        
        # Look for database info
        db_pattern = re.compile(r'available databases \[(\d+)\]:(.+?)(?=\n\n|\Z)', re.DOTALL)
        db_match = db_pattern.search(output)
        if db_match:
            results.append(Finding(
                tool="sqlmap",
                target="",
                finding_type="info",
                title="Database Enumeration",
                description=f"Found {db_match.group(1)} databases",
                severity=Severity.HIGH,
                evidence=db_match.group(2).strip()
            ))
        
        return results
    
    @staticmethod
    def parse_dalfox(output: str) -> List[Finding]:
        """Parse dalfox JSON output"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(Finding(
                    tool="dalfox",
                    target=data.get('url', ''),
                    finding_type="xss",
                    title="Cross-Site Scripting (XSS)",
                    description=f"XSS vulnerability found via {data.get('type', 'unknown')}",
                    severity=Severity.MEDIUM if 'reflected' in str(data).lower() else Severity.HIGH,
                    url=data.get('url', ''),
                    parameter=data.get('param', ''),
                    payload=data.get('payload', ''),
                    evidence=data.get('evidence', '')
                ))
            except json.JSONDecodeError:
                # Plain text output
                if '[V]' in line or '[POC]' in line:
                    results.append(Finding(
                        tool="dalfox",
                        target="",
                        finding_type="xss",
                        title="Cross-Site Scripting (XSS)",
                        description=line,
                        severity=Severity.MEDIUM,
                        evidence=line
                    ))
        return results
    
    @staticmethod
    def parse_wafw00f(output: str) -> Dict[str, Any]:
        """Parse wafw00f output"""
        result = {
            "waf_detected": False,
            "waf_name": None,
            "waf_vendor": None,
            "details": []
        }
        
        if "is behind" in output.lower():
            result["waf_detected"] = True
            match = re.search(r'is behind (.+?) WAF', output, re.IGNORECASE)
            if match:
                result["waf_name"] = match.group(1)
        elif "no waf" in output.lower():
            result["waf_detected"] = False
        
        return result
    
    @staticmethod
    def parse_arjun(output: str) -> List[str]:
        """Parse arjun output for discovered parameters"""
        params = []
        try:
            data = json.loads(output)
            for url, param_list in data.items():
                params.extend(param_list)
        except json.JSONDecodeError:
            # Plain text fallback
            param_pattern = re.compile(r'Valid parameter found: (\w+)')
            params = param_pattern.findall(output)
        return list(set(params))
    
    @staticmethod
    def merge_subdomains(results: List[List[Subdomain]]) -> List[Subdomain]:
        """Merge subdomain results from multiple tools"""
        seen = {}
        for result_list in results:
            for subdomain in result_list:
                if subdomain.domain not in seen:
                    seen[subdomain.domain] = subdomain
                else:
                    # Merge data
                    existing = seen[subdomain.domain]
                    if subdomain.ip and not existing.ip:
                        existing.ip = subdomain.ip
                    if subdomain.status_code and not existing.status_code:
                        existing.status_code = subdomain.status_code
                    if subdomain.technologies:
                        existing.technologies.extend(subdomain.technologies)
                        existing.technologies = list(set(existing.technologies))
        return list(seen.values())
    
    @staticmethod
    def merge_endpoints(results: List[List[Endpoint]]) -> List[Endpoint]:
        """Merge endpoint results from multiple tools"""
        seen = {}
        for result_list in results:
            for endpoint in result_list:
                if endpoint.url not in seen:
                    seen[endpoint.url] = endpoint
                else:
                    existing = seen[endpoint.url]
                    if endpoint.parameters:
                        existing.parameters.extend(endpoint.parameters)
                        existing.parameters = list(set(existing.parameters))
        return list(seen.values())
    
    @staticmethod
    def findings_to_json(findings: List[Finding]) -> str:
        """Convert findings to JSON string"""
        return json.dumps([f.to_dict() for f in findings], indent=2)
    
    @staticmethod
    def findings_by_severity(findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by severity"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        for finding in findings:
            grouped[finding.severity.value].append(finding)
        return grouped
