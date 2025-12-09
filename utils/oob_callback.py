"""
Out-of-Band (OOB) Callback Infrastructure

Provides OOB callback support for blind vulnerability detection using:
- Interactsh client (Project Discovery)
- Custom webhook server
- DNS callback detection
"""
import subprocess
import json
import uuid
import threading
import time
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Interaction:
    """Represents an OOB interaction"""
    timestamp: str
    protocol: str  # dns, http, smtp, etc.
    full_id: str
    unique_id: str
    raw_data: Optional[str] = None
    source_ip: Optional[str] = None


class OOBCallback:
    """Out-of-Band callback infrastructure using Interactsh."""

    def __init__(self, server_url: Optional[str] = None):
        """
        Initialize OOB callback.

        Args:
            server_url: Custom Interactsh server URL (optional)
        """
        self.server_url = server_url
        self.callback_url = None
        self.interactions: List[Interaction] = []
        self.process = None
        self.running = False
        self.collector_thread = None
        self._unique_ids: Dict[str, str] = {}  # Maps unique_id to test description

    def start(self) -> Optional[str]:
        """Start Interactsh client and get callback URL."""
        try:
            cmd = ['interactsh-client', '-json', '-v']

            if self.server_url:
                cmd.extend(['-server', self.server_url])

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # Read initial output to get callback URL
            # Interactsh outputs the URL in the first few lines
            start_time = time.time()
            while time.time() - start_time < 10:  # 10 second timeout
                line = self.process.stdout.readline()
                if line:
                    line = line.strip()
                    # Look for the callback URL pattern
                    if '.oast.' in line or '.interact.' in line or 'interactsh' in line.lower():
                        # Extract URL from line
                        url_match = re.search(r'([a-z0-9]+\.oast\.[a-z]+|[a-z0-9]+\.interact\.sh)', line)
                        if url_match:
                            self.callback_url = url_match.group(1)
                            break
                    # Try JSON parsing
                    try:
                        data = json.loads(line)
                        if 'url' in data:
                            self.callback_url = data['url']
                            break
                    except json.JSONDecodeError:
                        pass

            if not self.callback_url:
                # Try to extract from stderr
                stderr_line = self.process.stderr.readline()
                if stderr_line:
                    url_match = re.search(r'([a-z0-9]+\.oast\.[a-z]+|[a-z0-9]+\.interact\.sh)', stderr_line)
                    if url_match:
                        self.callback_url = url_match.group(1)

            if self.callback_url:
                self.running = True
                # Start background collector
                self.collector_thread = threading.Thread(target=self._collect_interactions, daemon=True)
                self.collector_thread.start()
                print(f"[+] OOB Callback URL: {self.callback_url}")
                return self.callback_url
            else:
                self.stop()
                return None

        except FileNotFoundError:
            raise RuntimeError(
                "interactsh-client not found. Install with: "
                "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start interactsh: {str(e)}")

    def _collect_interactions(self):
        """Background thread to collect interactions."""
        while self.running and self.process:
            try:
                line = self.process.stdout.readline()
                if line:
                    line = line.strip()
                    try:
                        data = json.loads(line)
                        interaction = Interaction(
                            timestamp=datetime.now().isoformat(),
                            protocol=data.get('protocol', 'unknown'),
                            full_id=data.get('full-id', ''),
                            unique_id=data.get('unique-id', ''),
                            raw_data=data.get('raw-request', ''),
                            source_ip=data.get('remote-address', '')
                        )
                        self.interactions.append(interaction)
                        print(f"[!] OOB Interaction received: {interaction.protocol} from {interaction.source_ip}")
                    except json.JSONDecodeError:
                        pass
            except Exception:
                break

    def get_unique_url(self, identifier: Optional[str] = None, description: str = '') -> str:
        """
        Get a unique callback URL for tracking specific tests.

        Args:
            identifier: Custom identifier (optional, auto-generated if not provided)
            description: Description of what this callback is for

        Returns:
            Unique callback URL with subdomain prefix
        """
        if not self.callback_url:
            raise RuntimeError("OOB callback not started. Call start() first.")

        unique_id = identifier or str(uuid.uuid4())[:8]
        self._unique_ids[unique_id] = description

        # Prepend unique ID as subdomain
        return f"http://{unique_id}.{self.callback_url}"

    def get_dns_callback(self, identifier: Optional[str] = None, description: str = '') -> str:
        """Get DNS callback hostname for DNS-based detection."""
        if not self.callback_url:
            raise RuntimeError("OOB callback not started. Call start() first.")

        unique_id = identifier or str(uuid.uuid4())[:8]
        self._unique_ids[unique_id] = description

        return f"{unique_id}.{self.callback_url}"

    def check_interactions(self, identifier: Optional[str] = None) -> List[Interaction]:
        """
        Check for interactions, optionally filtered by identifier.

        Args:
            identifier: Filter by unique identifier

        Returns:
            List of matching interactions
        """
        if identifier:
            return [i for i in self.interactions if identifier in i.full_id or identifier in i.unique_id]
        return self.interactions.copy()

    def wait_for_interaction(self, timeout: int = 30, identifier: Optional[str] = None) -> List[Interaction]:
        """
        Wait for an interaction with timeout.

        Args:
            timeout: Maximum seconds to wait
            identifier: Filter by unique identifier

        Returns:
            List of matching interactions (empty if timeout)
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            interactions = self.check_interactions(identifier)
            if interactions:
                return interactions
            time.sleep(1)
        return []

    def clear_interactions(self):
        """Clear all collected interactions."""
        self.interactions.clear()

    def stop(self):
        """Stop the callback server."""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all interactions."""
        if not self.interactions:
            return {
                'total_interactions': 0,
                'protocols': {},
                'unique_tests': {}
            }

        protocols = {}
        for interaction in self.interactions:
            protocols[interaction.protocol] = protocols.get(interaction.protocol, 0) + 1

        return {
            'total_interactions': len(self.interactions),
            'protocols': protocols,
            'unique_tests': self._unique_ids,
            'interactions': [
                {
                    'timestamp': i.timestamp,
                    'protocol': i.protocol,
                    'unique_id': i.unique_id,
                    'source_ip': i.source_ip
                }
                for i in self.interactions
            ]
        }

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


class SimpleWebhookServer:
    """
    Simple webhook server for OOB callbacks when Interactsh is not available.
    Uses Python's built-in HTTP server.
    """

    def __init__(self, port: int = 8888, host: str = '0.0.0.0'):
        self.port = port
        self.host = host
        self.server = None
        self.interactions: List[Dict[str, Any]] = []
        self.running = False
        self._thread = None

    def start(self) -> str:
        """Start the webhook server."""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import socket

        interactions = self.interactions

        class WebhookHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logging

            def do_GET(self):
                interactions.append({
                    'timestamp': datetime.now().isoformat(),
                    'method': 'GET',
                    'path': self.path,
                    'headers': dict(self.headers),
                    'client_ip': self.client_address[0]
                })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')

            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length) if content_length > 0 else b''
                interactions.append({
                    'timestamp': datetime.now().isoformat(),
                    'method': 'POST',
                    'path': self.path,
                    'headers': dict(self.headers),
                    'body': body.decode('utf-8', errors='ignore'),
                    'client_ip': self.client_address[0]
                })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')

        self.server = HTTPServer((self.host, self.port), WebhookHandler)
        self.running = True

        # Get local IP for callback URL
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = '127.0.0.1'

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

        callback_url = f"http://{local_ip}:{self.port}"
        print(f"[+] Webhook server started: {callback_url}")
        return callback_url

    def _serve(self):
        """Background thread to serve requests."""
        while self.running:
            self.server.handle_request()

    def check_interactions(self) -> List[Dict[str, Any]]:
        """Get all received interactions."""
        return self.interactions.copy()

    def wait_for_interaction(self, timeout: int = 30) -> List[Dict[str, Any]]:
        """Wait for an interaction."""
        start_time = time.time()
        initial_count = len(self.interactions)
        while time.time() - start_time < timeout:
            if len(self.interactions) > initial_count:
                return self.interactions[initial_count:]
            time.sleep(1)
        return []

    def stop(self):
        """Stop the webhook server."""
        self.running = False
        if self.server:
            self.server.shutdown()


if __name__ == '__main__':
    # Test OOB callback
    print("[*] Testing OOB Callback Infrastructure")

    try:
        with OOBCallback() as oob:
            print(f"[+] Callback URL: {oob.callback_url}")

            # Generate unique URLs for different tests
            ssrf_url = oob.get_unique_url(description='SSRF Test')
            xxe_url = oob.get_unique_url(description='XXE Test')

            print(f"[*] SSRF Callback: {ssrf_url}")
            print(f"[*] XXE Callback: {xxe_url}")

            print("[*] Waiting for interactions (30s)...")
            interactions = oob.wait_for_interaction(timeout=30)

            if interactions:
                print(f"[+] Received {len(interactions)} interaction(s)")
                for i in interactions:
                    print(f"    Protocol: {i.protocol}, Source: {i.source_ip}")
            else:
                print("[-] No interactions received")

            print("\n[*] Summary:")
            print(json.dumps(oob.get_summary(), indent=2))

    except RuntimeError as e:
        print(f"[!] {e}")
        print("[*] Falling back to simple webhook server...")

        # Fallback to simple webhook
        webhook = SimpleWebhookServer(port=9999)
        callback_url = webhook.start()

        print(f"[*] Use this URL for testing: {callback_url}")
        print("[*] Waiting for interactions (30s)...")

        interactions = webhook.wait_for_interaction(timeout=30)
        if interactions:
            print(f"[+] Received {len(interactions)} interaction(s)")
            for i in interactions:
                print(f"    {i['method']} {i['path']} from {i['client_ip']}")
        else:
            print("[-] No interactions received")

        webhook.stop()
