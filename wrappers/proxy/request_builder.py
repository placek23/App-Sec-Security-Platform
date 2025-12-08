"""
HTTP request builder and manipulator.

Provides tools for:
- Building and sending custom HTTP requests
- Request history management
- Parameter fuzzing
- Response analysis
"""

import requests
import json
import time
import urllib3
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
from datetime import datetime

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class RequestRecord:
    """Record of a single HTTP request/response."""
    timestamp: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[Any]
    status_code: int
    response_headers: Dict[str, str]
    response_body: str
    response_time: float
    cookies: Dict[str, str] = field(default_factory=dict)


class RequestBuilder:
    """HTTP request builder and manipulator for security testing."""

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = False,
        max_history: int = 1000
    ):
        """
        Initialize RequestBuilder.

        Args:
            proxy: Proxy URL (e.g., 'http://127.0.0.1:8080')
            timeout: Default request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            max_history: Maximum number of requests to keep in history
        """
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_history = max_history
        self.history: List[RequestRecord] = []

        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }

        self.session.verify = verify_ssl

    def build_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, Dict]] = None,
        json_data: Optional[Dict] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[tuple] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True
    ) -> requests.Response:
        """
        Build and send HTTP request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Request headers
            params: URL query parameters
            data: Request body (form data or raw string)
            json_data: JSON request body
            cookies: Request cookies
            auth: Basic auth tuple (username, password)
            timeout: Request timeout
            allow_redirects: Whether to follow redirects

        Returns:
            Response object
        """
        method = method.upper()
        headers = headers or {}
        timeout = timeout or self.timeout

        # Prepare request
        req = requests.Request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json_data,
            cookies=cookies,
            auth=auth
        )

        prepared = self.session.prepare_request(req)

        # Send request and measure time
        start_time = time.time()
        response = self.session.send(
            prepared,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=self.verify_ssl
        )
        response_time = time.time() - start_time

        # Record in history
        self._record_request(
            method=method,
            url=url,
            headers=dict(prepared.headers),
            body=data or json_data,
            response=response,
            response_time=response_time,
            cookies=cookies or {}
        )

        return response

    def _record_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Any,
        response: requests.Response,
        response_time: float,
        cookies: Dict[str, str]
    ):
        """Record request in history."""
        # Truncate large response bodies
        response_body = response.text[:10000] if len(response.text) > 10000 else response.text

        record = RequestRecord(
            timestamp=datetime.now().isoformat(),
            method=method,
            url=url,
            headers=headers,
            body=body,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body=response_body,
            response_time=response_time,
            cookies=cookies
        )

        self.history.append(record)

        # Trim history if too large
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]

    def get(self, url: str, **kwargs) -> requests.Response:
        """Send GET request."""
        return self.build_request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Send POST request."""
        return self.build_request('POST', url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        """Send PUT request."""
        return self.build_request('PUT', url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        """Send DELETE request."""
        return self.build_request('DELETE', url, **kwargs)

    def patch(self, url: str, **kwargs) -> requests.Response:
        """Send PATCH request."""
        return self.build_request('PATCH', url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        """Send OPTIONS request."""
        return self.build_request('OPTIONS', url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """Send HEAD request."""
        return self.build_request('HEAD', url, **kwargs)

    def replay_request(
        self,
        index: int,
        modifications: Optional[Dict[str, Any]] = None
    ) -> requests.Response:
        """
        Replay a request from history with optional modifications.

        Args:
            index: Index in history (negative indices supported)
            modifications: Dictionary of modifications to apply

        Returns:
            Response from replayed request
        """
        if not self.history:
            raise IndexError("No requests in history")

        if abs(index) > len(self.history):
            raise IndexError(f"Index {index} out of range. History has {len(self.history)} requests")

        original = self.history[index]
        modifications = modifications or {}

        # Build modified request
        return self.build_request(
            method=modifications.get('method', original.method),
            url=modifications.get('url', original.url),
            headers=modifications.get('headers', original.headers),
            data=modifications.get('data', original.body) if not isinstance(original.body, dict) else None,
            json_data=modifications.get('json_data', original.body) if isinstance(original.body, dict) else None,
            cookies=modifications.get('cookies', original.cookies)
        )

    def fuzz_parameter(
        self,
        url: str,
        param_name: str,
        payloads: List[str],
        method: str = 'GET',
        in_body: bool = False,
        headers: Optional[Dict[str, str]] = None,
        base_data: Optional[Dict[str, str]] = None,
        delay: float = 0
    ) -> List[Dict[str, Any]]:
        """
        Fuzz a specific parameter with payloads.

        Args:
            url: Target URL
            param_name: Parameter name to fuzz
            payloads: List of payloads to test
            method: HTTP method
            in_body: If True, fuzz parameter in request body
            headers: Optional headers
            base_data: Base form data (for POST)
            delay: Delay between requests in seconds

        Returns:
            List of results with payload, status code, response length, etc.
        """
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in payloads:
            try:
                if in_body:
                    # Fuzz in request body
                    data = base_data.copy() if base_data else {}
                    data[param_name] = payload
                    response = self.build_request(method, url, headers=headers, data=data)
                else:
                    # Fuzz in URL parameter
                    params_copy = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
                    params_copy[param_name] = payload

                    fuzzed_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(params_copy),
                        parsed.fragment
                    ))

                    response = self.build_request(method, fuzzed_url, headers=headers)

                results.append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'response_time': response.elapsed.total_seconds(),
                    'content_type': response.headers.get('Content-Type', ''),
                    'interesting': self._is_interesting_response(response, payload)
                })

                if delay > 0:
                    time.sleep(delay)

            except Exception as e:
                results.append({
                    'payload': payload,
                    'error': str(e)
                })

        return results

    def _is_interesting_response(self, response: requests.Response, payload: str) -> bool:
        """Check if response is potentially interesting."""
        # Check for error indicators
        error_keywords = [
            'error', 'exception', 'warning', 'syntax', 'mysql',
            'postgresql', 'sqlite', 'oracle', 'sql', 'xpath',
            'stack trace', 'traceback', 'internal server error'
        ]

        text_lower = response.text.lower()

        # Check for error keywords
        if any(keyword in text_lower for keyword in error_keywords):
            return True

        # Check if payload is reflected
        if payload in response.text:
            return True

        # Check for unusual status codes
        if response.status_code in [500, 501, 502, 503, 403, 401]:
            return True

        return False

    def compare_responses(
        self,
        response1: requests.Response,
        response2: requests.Response
    ) -> Dict[str, Any]:
        """
        Compare two responses for differences.

        Args:
            response1: First response
            response2: Second response

        Returns:
            Comparison results
        """
        return {
            'status_code_match': response1.status_code == response2.status_code,
            'status_codes': (response1.status_code, response2.status_code),
            'length_diff': len(response1.text) - len(response2.text),
            'lengths': (len(response1.text), len(response2.text)),
            'content_type_match': response1.headers.get('Content-Type') == response2.headers.get('Content-Type'),
            'headers_diff': {
                'only_in_first': set(response1.headers.keys()) - set(response2.headers.keys()),
                'only_in_second': set(response2.headers.keys()) - set(response1.headers.keys())
            }
        }

    def get_history(
        self,
        limit: int = 10,
        filter_url: str = None,
        filter_status: int = None
    ) -> List[Dict[str, Any]]:
        """
        Get request history.

        Args:
            limit: Maximum number of records to return
            filter_url: Filter by URL substring
            filter_status: Filter by status code

        Returns:
            List of request records
        """
        filtered = self.history

        if filter_url:
            filtered = [r for r in filtered if filter_url in r.url]

        if filter_status:
            filtered = [r for r in filtered if r.status_code == filter_status]

        # Return most recent first
        return [
            {
                'timestamp': r.timestamp,
                'method': r.method,
                'url': r.url,
                'status_code': r.status_code,
                'response_time': r.response_time,
                'response_length': len(r.response_body)
            }
            for r in reversed(filtered[-limit:])
        ]

    def clear_history(self):
        """Clear request history."""
        self.history = []

    def export_history(self, output_file: str, format: str = 'json') -> str:
        """
        Export request history to file.

        Args:
            output_file: Output file path
            format: Export format (json, har)

        Returns:
            Path to exported file
        """
        if format == 'json':
            data = [
                {
                    'timestamp': r.timestamp,
                    'method': r.method,
                    'url': r.url,
                    'headers': r.headers,
                    'body': r.body,
                    'status_code': r.status_code,
                    'response_headers': r.response_headers,
                    'response_body': r.response_body,
                    'response_time': r.response_time
                }
                for r in self.history
            ]
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)

        elif format == 'har':
            # Export in HAR format
            har = {
                'log': {
                    'version': '1.2',
                    'creator': {'name': 'RequestBuilder', 'version': '1.0'},
                    'entries': []
                }
            }

            for r in self.history:
                entry = {
                    'startedDateTime': r.timestamp,
                    'time': r.response_time * 1000,
                    'request': {
                        'method': r.method,
                        'url': r.url,
                        'headers': [{'name': k, 'value': v} for k, v in r.headers.items()],
                        'postData': {'text': str(r.body)} if r.body else None
                    },
                    'response': {
                        'status': r.status_code,
                        'headers': [{'name': k, 'value': v} for k, v in r.response_headers.items()],
                        'content': {
                            'size': len(r.response_body),
                            'text': r.response_body
                        }
                    }
                }
                har['log']['entries'].append(entry)

            with open(output_file, 'w') as f:
                json.dump(har, f, indent=2)

        return output_file

    def set_proxy(self, proxy: str):
        """Set proxy for all requests."""
        self.session.proxies = {
            'http': proxy,
            'https': proxy
        }

    def set_header(self, name: str, value: str):
        """Set a default header for all requests."""
        self.session.headers[name] = value

    def set_cookie(self, name: str, value: str, domain: str = ''):
        """Set a cookie for all requests."""
        self.session.cookies.set(name, value, domain=domain)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='HTTP Request Builder')
    parser.add_argument('--url', '-u', required=True, help='Target URL')
    parser.add_argument('--method', '-m', default='GET', help='HTTP method')
    parser.add_argument('--data', '-d', help='Request body')
    parser.add_argument('--header', '-H', action='append', help='Headers (Name: Value)')
    parser.add_argument('--proxy', '-p', help='Proxy URL')
    parser.add_argument('--fuzz-param', help='Parameter to fuzz')
    parser.add_argument('--wordlist', '-w', help='Wordlist for fuzzing')

    args = parser.parse_args()

    builder = RequestBuilder(proxy=args.proxy)

    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    if args.fuzz_param and args.wordlist:
        # Load wordlist
        with open(args.wordlist, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]

        results = builder.fuzz_parameter(
            args.url,
            args.fuzz_param,
            payloads,
            method=args.method,
            headers=headers
        )

        print(f"\n[+] Fuzz Results for parameter: {args.fuzz_param}")
        print("-" * 60)
        for result in results:
            if 'error' in result:
                print(f"  {result['payload']}: ERROR - {result['error']}")
            else:
                flag = " [!]" if result.get('interesting') else ""
                print(f"  {result['payload']}: {result['status_code']} ({result['response_length']} bytes){flag}")
    else:
        # Single request
        response = builder.build_request(
            args.method,
            args.url,
            headers=headers,
            data=args.data
        )

        print(f"\n[+] Response: {response.status_code}")
        print(f"[+] Length: {len(response.text)} bytes")
        print(f"[+] Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"\n{response.text[:1000]}")
