#!/usr/bin/env python3
"""
Technology Fingerprinting - Passive technology detection
Identifies web technologies, frameworks, and libraries from HTTP responses
Similar to Wappalyzer but runs passively with a single request
"""
import sys
import json
import argparse
import re
import hashlib
import base64
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse, urljoin
import requests

# Optional: mmh3 for favicon hashing (same as Shodan)
try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

# Optional: python-Wappalyzer for enhanced detection
try:
    from Wappalyzer import Wappalyzer, WebPage
    HAS_WAPPALYZER = True
except ImportError:
    HAS_WAPPALYZER = False

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class WappalyzerEngine:
    """
    Wrapper for python-Wappalyzer library.
    Provides access to official Wappalyzer signatures (2000+ technologies).
    """

    def __init__(self):
        if not HAS_WAPPALYZER:
            raise ImportError(
                "python-Wappalyzer not installed. "
                "Install with: pip install python-Wappalyzer"
            )
        self.wappalyzer = Wappalyzer.latest()

    def analyze(self, url: str, html: str, headers: Dict) -> List[Dict]:
        """
        Run Wappalyzer analysis on page content.

        Args:
            url: The page URL
            html: HTML content of the page
            headers: HTTP response headers

        Returns:
            List of detected technologies in normalized format
        """
        try:
            # Create WebPage object from components
            webpage = WebPage.new_from_url(url)
            webpage.html = html
            webpage.headers = headers

            # Run analysis with versions and categories
            results = self.wappalyzer.analyze_with_versions_and_categories(webpage)
            return self._normalize_results(results)
        except Exception as e:
            print(f"    [!] Wappalyzer error: {e}")
            return []

    def analyze_from_response(self, response: requests.Response) -> List[Dict]:
        """
        Run Wappalyzer analysis directly from a requests Response object.

        Args:
            response: requests.Response object

        Returns:
            List of detected technologies in normalized format
        """
        try:
            webpage = WebPage.new_from_response(response)
            results = self.wappalyzer.analyze_with_versions_and_categories(webpage)
            return self._normalize_results(results)
        except Exception as e:
            print(f"    [!] Wappalyzer error: {e}")
            return []

    def _normalize_results(self, results: Dict) -> List[Dict]:
        """
        Convert Wappalyzer output to standard format matching TechFingerprinter.

        Args:
            results: Wappalyzer results dict {tech_name: {versions: [], categories: []}}

        Returns:
            List of technology dicts in normalized format
        """
        normalized = []

        for tech_name, tech_info in results.items():
            # Get version info
            versions = tech_info.get('versions', [])
            version_str = versions[0] if versions else None

            # Get categories
            categories = tech_info.get('categories', [])
            category = categories[0] if categories else 'unknown'

            # Map Wappalyzer categories to our category IDs
            category_id = self._map_category(category)

            normalized.append({
                'tech_id': tech_name.lower().replace(' ', '_').replace('.', '_'),
                'name': tech_name,
                'category': category_id,
                'confidence': 'high',
                'evidence': f"Wappalyzer detection",
                'method': 'wappalyzer',
                'version': version_str,
                'engine': 'wappalyzer'
            })

        return normalized

    def _map_category(self, wappalyzer_category: str) -> str:
        """Map Wappalyzer category names to our internal category IDs."""
        category_map = {
            'Web servers': 'web_servers',
            'JavaScript frameworks': 'javascript_frameworks',
            'JavaScript libraries': 'javascript_libraries',
            'CSS frameworks': 'css_frameworks',
            'Programming languages': 'programming_languages',
            'CMS': 'cms',
            'Ecommerce': 'ecommerce',
            'CDN': 'cdn',
            'Analytics': 'analytics',
            'Security': 'security',
            'Caching': 'caching',
            'Databases': 'databases',
            'PaaS': 'hosting',
            'IaaS': 'hosting',
            'Hosting': 'hosting',
            'Widgets': 'widgets',
            'Marketing automation': 'analytics',
            'Tag managers': 'analytics',
            'Font scripts': 'widgets',
            'Miscellaneous': 'other',
            'Message boards': 'cms',
            'Blogs': 'cms',
            'UI frameworks': 'css_frameworks',
            'Mobile frameworks': 'javascript_frameworks',
            'Web frameworks': 'web_frameworks',
            'Documentation': 'other',
            'Static site generator': 'cms',
            'CI': 'devops',
            'Build tools': 'devops',
            'Issue trackers': 'other',
        }
        return category_map.get(wappalyzer_category, 'other')


class TechFingerprinter:
    """
    Passive technology fingerprinting tool.

    Detects technologies from a single HTTP request by analyzing:
    - HTTP response headers
    - HTML meta tags
    - HTML content patterns
    - JavaScript file references
    - CSS frameworks
    - Cookie patterns
    - Favicon hash

    This is a "semi-passive" tool - it makes ONE request like a normal
    browser visit, then analyzes the response passively.
    """

    DEFAULT_SIGNATURES_PATH = Path(__file__).parent.parent.parent / "config" / "tech_signatures.json"

    # Common User-Agent to look like a real browser (Chrome on Windows)
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )

    # Valid engine options
    ENGINES = ['builtin', 'wappalyzer', 'both']

    def __init__(self, signatures_path: str = None, timeout: int = 15, engine: str = 'builtin'):
        """
        Initialize TechFingerprinter.

        Args:
            signatures_path: Path to custom signatures file (for builtin engine)
            timeout: HTTP request timeout in seconds
            engine: Detection engine to use - 'builtin', 'wappalyzer', or 'both'
        """
        self.timeout = timeout
        self.engine = engine.lower()
        if self.engine not in self.ENGINES:
            print(f"[!] Invalid engine '{engine}', using 'builtin'")
            self.engine = 'builtin'

        self.signatures = self._load_signatures(signatures_path)
        self.wappalyzer_engine = None

        # Initialize Wappalyzer engine if needed
        if self.engine in ('wappalyzer', 'both'):
            if HAS_WAPPALYZER:
                try:
                    self.wappalyzer_engine = WappalyzerEngine()
                except Exception as e:
                    print(f"[!] Failed to initialize Wappalyzer: {e}")
                    if self.engine == 'wappalyzer':
                        print("[!] Falling back to builtin engine")
                        self.engine = 'builtin'
            else:
                print("[!] python-Wappalyzer not installed")
                if self.engine == 'wappalyzer':
                    print("[!] Install with: pip install python-Wappalyzer")
                    print("[!] Falling back to builtin engine")
                    self.engine = 'builtin'
                else:
                    print("[!] 'both' mode will only use builtin engine")

        self.results = {
            'url': '',
            'technologies': [],
            'categories': {},
            'headers_analyzed': {},
            'meta_tags': {},
            'scripts': [],
            'favicon_hash': None,
            'confidence_scores': {},
            'raw_data': {},
            'scan_time': '',
            'scan_type': 'passive',
            'engine': self.engine
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.DEFAULT_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        })

    def _load_signatures(self, path: str = None) -> Dict:
        """Load technology signatures from JSON file."""
        sig_path = Path(path) if path else self.DEFAULT_SIGNATURES_PATH
        try:
            with open(sig_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Signatures file not found: {sig_path}")
            return {"technologies": {}, "favicon_hashes": {}, "categories": {}}
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing signatures file: {e}")
            return {"technologies": {}, "favicon_hashes": {}, "categories": {}}

    def fetch_page(self, url: str) -> Optional[requests.Response]:
        """Fetch the target URL with browser-like headers."""
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )
            # Return response even for non-200 status codes
            # We can still analyze headers and any content returned
            return response
        except requests.exceptions.SSLError as e:
            print(f"    [!] SSL Error: {e}")
            # Try with SSL verification disabled
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                return response
            except Exception as e2:
                print(f"    [!] SSL Error (retry failed): {e2}")
                return None
        except requests.exceptions.ConnectTimeout:
            print(f"    [!] Connection timeout after {self.timeout}s")
            return None
        except requests.exceptions.ReadTimeout:
            print(f"    [!] Read timeout after {self.timeout}s")
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"    [!] Connection error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"    [!] Request error: {e}")
            return None

    def fetch_favicon(self, base_url: str) -> Optional[str]:
        """Fetch favicon and compute its hash."""
        if not HAS_MMH3:
            # Fall back to MD5 hash if mmh3 not available
            pass

        favicon_urls = [
            urljoin(base_url, '/favicon.ico'),
            urljoin(base_url, '/favicon.png'),
        ]

        for favicon_url in favicon_urls:
            try:
                response = self.session.get(
                    favicon_url,
                    timeout=5,
                    allow_redirects=True,
                    verify=False
                )
                if response.status_code == 200 and len(response.content) > 0:
                    if HAS_MMH3:
                        # Calculate MurmurHash3 (same as Shodan)
                        favicon_b64 = base64.b64encode(response.content).decode()
                        favicon_hash = mmh3.hash(favicon_b64)
                        return str(favicon_hash)
                    else:
                        # Fallback to MD5 hash
                        favicon_hash = hashlib.md5(response.content).hexdigest()
                        return f"md5:{favicon_hash}"
            except Exception:
                continue

        return None

    def analyze_headers(self, headers: Dict) -> List[Dict]:
        """Analyze HTTP headers for technology signatures."""
        detected = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for tech_id, tech_info in self.signatures.get('technologies', {}).items():
            detection = tech_info.get('detection', {})
            header_patterns = detection.get('headers', {})

            for header_name, pattern in header_patterns.items():
                header_lower = header_name.lower()

                # Check if header exists
                for h_name, h_value in headers_lower.items():
                    if header_lower in h_name or h_name in header_lower:
                        if re.search(pattern, h_value, re.IGNORECASE):
                            detected.append({
                                'tech_id': tech_id,
                                'name': tech_info.get('name', tech_id),
                                'category': tech_info.get('category', 'unknown'),
                                'confidence': 'high',
                                'evidence': f"Header {h_name}: {h_value[:100]}",
                                'method': 'header'
                            })
                            break

        return detected

    def analyze_html(self, html: str) -> List[Dict]:
        """Analyze HTML content for technology signatures."""
        detected = []

        for tech_id, tech_info in self.signatures.get('technologies', {}).items():
            detection = tech_info.get('detection', {})
            html_patterns = detection.get('html', [])

            for pattern in html_patterns:
                try:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        detected.append({
                            'tech_id': tech_id,
                            'name': tech_info.get('name', tech_id),
                            'category': tech_info.get('category', 'unknown'),
                            'confidence': 'medium',
                            'evidence': f"HTML pattern: {match.group(0)[:80]}",
                            'method': 'html'
                        })
                        break
                except re.error:
                    continue

        return detected

    def analyze_meta_tags(self, html: str) -> tuple:
        """Extract and analyze meta tags."""
        detected = []
        meta_tags = {}

        # Extract meta tags
        meta_pattern = r'<meta\s+[^>]*(?:name|property|http-equiv)=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']'
        meta_pattern_alt = r'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*(?:name|property|http-equiv)=["\']([^"\']+)["\']'

        for match in re.finditer(meta_pattern, html, re.IGNORECASE):
            meta_tags[match.group(1).lower()] = match.group(2)

        for match in re.finditer(meta_pattern_alt, html, re.IGNORECASE):
            meta_tags[match.group(2).lower()] = match.group(1)

        # Check for generator meta tag
        generator = meta_tags.get('generator', '')

        for tech_id, tech_info in self.signatures.get('technologies', {}).items():
            detection = tech_info.get('detection', {})
            meta_patterns = detection.get('meta', {})

            for meta_name, pattern in meta_patterns.items():
                meta_value = meta_tags.get(meta_name.lower(), '')
                if meta_value and re.search(pattern, meta_value, re.IGNORECASE):
                    detected.append({
                        'tech_id': tech_id,
                        'name': tech_info.get('name', tech_id),
                        'category': tech_info.get('category', 'unknown'),
                        'confidence': 'high',
                        'evidence': f"Meta {meta_name}: {meta_value[:50]}",
                        'method': 'meta'
                    })
                    break

        return detected, meta_tags

    def analyze_scripts(self, html: str) -> tuple:
        """Extract and analyze script sources."""
        detected = []
        scripts = []

        # Extract script sources
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        for match in re.finditer(script_pattern, html, re.IGNORECASE):
            scripts.append(match.group(1))

        # Check against signatures
        for tech_id, tech_info in self.signatures.get('technologies', {}).items():
            detection = tech_info.get('detection', {})
            script_patterns = detection.get('scripts', [])

            for pattern in script_patterns:
                for script in scripts:
                    if pattern.lower() in script.lower():
                        detected.append({
                            'tech_id': tech_id,
                            'name': tech_info.get('name', tech_id),
                            'category': tech_info.get('category', 'unknown'),
                            'confidence': 'high',
                            'evidence': f"Script: {script[:80]}",
                            'method': 'script'
                        })
                        break

        return detected, scripts

    def analyze_cookies(self, cookies: Dict) -> List[Dict]:
        """Analyze cookies for technology signatures."""
        detected = []
        cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])

        for tech_id, tech_info in self.signatures.get('technologies', {}).items():
            detection = tech_info.get('detection', {})
            header_patterns = detection.get('headers', {})

            # Check Set-Cookie patterns
            cookie_pattern = header_patterns.get('Set-Cookie', '')
            if cookie_pattern:
                if re.search(cookie_pattern, cookie_str, re.IGNORECASE):
                    detected.append({
                        'tech_id': tech_id,
                        'name': tech_info.get('name', tech_id),
                        'category': tech_info.get('category', 'unknown'),
                        'confidence': 'high',
                        'evidence': f"Cookie pattern matched",
                        'method': 'cookie'
                    })

        return detected

    def analyze_favicon(self, favicon_hash: str) -> List[Dict]:
        """Match favicon hash against known signatures."""
        detected = []
        favicon_hashes = self.signatures.get('favicon_hashes', {})

        if favicon_hash in favicon_hashes:
            tech_name = favicon_hashes[favicon_hash]
            detected.append({
                'tech_id': tech_name.lower().replace(' ', '_'),
                'name': tech_name,
                'category': 'unknown',
                'confidence': 'high',
                'evidence': f"Favicon hash: {favicon_hash}",
                'method': 'favicon'
            })

        return detected

    def deduplicate_results(self, detections: List[Dict]) -> List[Dict]:
        """Remove duplicate detections, keeping highest confidence."""
        seen = {}
        for detection in detections:
            tech_id = detection['tech_id']
            if tech_id not in seen:
                seen[tech_id] = detection
            else:
                # Keep higher confidence
                confidence_order = {'high': 3, 'medium': 2, 'low': 1}
                current = confidence_order.get(seen[tech_id]['confidence'], 0)
                new = confidence_order.get(detection['confidence'], 0)
                if new > current:
                    seen[tech_id] = detection

        return list(seen.values())

    def fingerprint(self, url: str, fetch_favicon: bool = True) -> Dict[str, Any]:
        """
        Perform full technology fingerprinting on a URL.

        Args:
            url: Target URL to fingerprint
            fetch_favicon: Whether to fetch and hash favicon

        Returns:
            Dictionary with detected technologies and metadata
        """
        engine_label = {
            'builtin': 'Built-in Engine',
            'wappalyzer': 'Wappalyzer Engine',
            'both': 'Built-in + Wappalyzer'
        }.get(self.engine, self.engine)

        print(f"\n{'='*60}")
        print(f"Technology Fingerprinting: {url}")
        print(f"Engine: {engine_label}")
        print(f"{'='*60}\n")

        self.results['url'] = url
        self.results['scan_time'] = datetime.now().isoformat()

        # Fetch the page
        print("[*] Fetching page...")
        response = self.fetch_page(url)

        if response is None:
            self.results['error'] = "Failed to fetch page - connection failed"
            return self.results

        print(f"    Status: {response.status_code}")
        print(f"    Content-Type: {response.headers.get('Content-Type', 'unknown')}")
        print(f"    Content-Length: {len(response.content)} bytes")

        # Check for bot protection / challenges
        if response.status_code == 429:
            print("    [!] Warning: Rate limited (429) - bot protection detected")
        elif response.status_code == 403:
            print("    [!] Warning: Forbidden (403) - may be blocked")
        elif response.status_code >= 400:
            print(f"    [!] Warning: HTTP {response.status_code} - analyzing available data anyway")

        # Store raw data
        self.results['raw_data'] = {
            'status_code': response.status_code,
            'final_url': response.url,
            'content_type': response.headers.get('Content-Type', ''),
            'content_length': len(response.content)
        }

        all_detections = []
        html = response.text

        # Run Wappalyzer engine if selected
        if self.engine in ('wappalyzer', 'both') and self.wappalyzer_engine:
            print("\n[*] Running Wappalyzer analysis...")
            wappalyzer_detections = self.wappalyzer_engine.analyze_from_response(response)
            all_detections.extend(wappalyzer_detections)
            print(f"    Found {len(wappalyzer_detections)} technologies via Wappalyzer")

        # Run builtin engine if selected
        if self.engine in ('builtin', 'both'):
            # Analyze headers (even on error responses - still reveals server info)
            print("\n[*] Analyzing headers (builtin)...")
            header_detections = self.analyze_headers(dict(response.headers))
            # Add engine tag to builtin results
            for d in header_detections:
                d['engine'] = 'builtin'
            all_detections.extend(header_detections)
            print(f"    Found {len(header_detections)} technologies from headers")
            self.results['headers_analyzed'] = dict(response.headers)

            # Analyze HTML patterns
            print("\n[*] Analyzing HTML patterns (builtin)...")
            html_detections = self.analyze_html(html)
            for d in html_detections:
                d['engine'] = 'builtin'
            all_detections.extend(html_detections)
            print(f"    Found {len(html_detections)} technologies from HTML")

            # Analyze meta tags
            print("\n[*] Analyzing meta tags (builtin)...")
            meta_detections, meta_tags = self.analyze_meta_tags(html)
            for d in meta_detections:
                d['engine'] = 'builtin'
            all_detections.extend(meta_detections)
            print(f"    Found {len(meta_tags)} meta tags, {len(meta_detections)} technologies")
            self.results['meta_tags'] = meta_tags

            # Analyze scripts
            print("\n[*] Analyzing scripts (builtin)...")
            script_detections, scripts = self.analyze_scripts(html)
            for d in script_detections:
                d['engine'] = 'builtin'
            all_detections.extend(script_detections)
            print(f"    Found {len(scripts)} scripts, {len(script_detections)} technologies")
            self.results['scripts'] = scripts[:50]  # Limit stored scripts

            # Analyze cookies
            print("\n[*] Analyzing cookies (builtin)...")
            cookie_detections = self.analyze_cookies(dict(response.cookies))
            for d in cookie_detections:
                d['engine'] = 'builtin'
            all_detections.extend(cookie_detections)
            print(f"    Found {len(cookie_detections)} technologies from cookies")

            # Analyze favicon
            if fetch_favicon:
                print("\n[*] Fetching favicon...")
                parsed = urlparse(response.url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                favicon_hash = self.fetch_favicon(base_url)

                if favicon_hash:
                    self.results['favicon_hash'] = favicon_hash
                    print(f"    Favicon hash: {favicon_hash}")
                    favicon_detections = self.analyze_favicon(favicon_hash)
                    for d in favicon_detections:
                        d['engine'] = 'builtin'
                    all_detections.extend(favicon_detections)
                    print(f"    Found {len(favicon_detections)} technologies from favicon")
                else:
                    print("    No favicon found")

        # Deduplicate and organize results
        unique_detections = self.deduplicate_results(all_detections)

        # Organize by category
        categories = {}
        for detection in unique_detections:
            category = detection['category']
            if category not in categories:
                categories[category] = []
            tech_entry = {
                'name': detection['name'],
                'confidence': detection['confidence'],
                'evidence': detection['evidence'],
                'engine': detection.get('engine', 'builtin')
            }
            # Add version if present
            if detection.get('version'):
                tech_entry['version'] = detection['version']
            categories[category].append(tech_entry)

        self.results['technologies'] = unique_detections
        self.results['categories'] = categories

        # Calculate confidence scores per category
        category_info = self.signatures.get('categories', {})
        for cat_id, techs in categories.items():
            cat_name = category_info.get(cat_id, {}).get('description', cat_id)
            self.results['confidence_scores'][cat_name] = len(techs)

        return self.results

    def print_results(self):
        """Print formatted results."""
        print(f"\n{'='*60}")
        print("FINGERPRINTING RESULTS")
        print(f"{'='*60}")

        print(f"\n  URL: {self.results['url']}")
        print(f"  Final URL: {self.results.get('raw_data', {}).get('final_url', 'N/A')}")
        print(f"  Scan Time: {self.results['scan_time']}")
        print(f"  Engine: {self.results.get('engine', 'builtin')}")

        if self.results.get('error'):
            print(f"\n  Error: {self.results['error']}")
            return

        categories = self.results.get('categories', {})
        category_info = self.signatures.get('categories', {})

        if categories:
            print(f"\n  Detected Technologies ({len(self.results['technologies'])} total):")
            print(f"  {'-'*50}")

            for cat_id, techs in sorted(categories.items()):
                cat_name = category_info.get(cat_id, {}).get('description', cat_id.replace('_', ' ').title())
                print(f"\n  [{cat_name}]")
                for tech in techs:
                    conf_icon = {'high': '+', 'medium': '~', 'low': '?'}.get(tech['confidence'], '?')
                    # Build tech display string
                    tech_display = tech['name']
                    if tech.get('version'):
                        tech_display += f" ({tech['version']})"
                    # Show engine source if using 'both' mode
                    if self.engine == 'both':
                        engine_tag = 'W' if tech.get('engine') == 'wappalyzer' else 'B'
                        print(f"    [{conf_icon}] {tech_display} [{engine_tag}]")
                    else:
                        print(f"    [{conf_icon}] {tech_display}")
        else:
            print("\n  No technologies detected")

        # Print meta tags of interest
        meta_tags = self.results.get('meta_tags', {})
        interesting_meta = ['generator', 'framework', 'powered-by', 'application-name']
        found_meta = {k: v for k, v in meta_tags.items() if any(m in k for m in interesting_meta)}
        if found_meta:
            print(f"\n  Interesting Meta Tags:")
            for name, value in found_meta.items():
                print(f"    {name}: {value[:60]}")

        # Print some detected scripts
        scripts = self.results.get('scripts', [])
        if scripts:
            print(f"\n  Script Sources (showing first 10 of {len(scripts)}):")
            for script in scripts[:10]:
                print(f"    - {script[:70]}{'...' if len(script) > 70 else ''}")

        if self.results.get('favicon_hash'):
            print(f"\n  Favicon Hash: {self.results['favicon_hash']}")

    def save_results(self, output_file: str):
        """Save results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[+] Results saved to {output_file}")

    def get_tech_list(self) -> List[str]:
        """Get simple list of detected technology names."""
        return [t['name'] for t in self.results.get('technologies', [])]

    def get_security_relevant(self) -> List[Dict]:
        """Get security-relevant findings from detected technologies."""
        findings = []

        for tech in self.results.get('technologies', []):
            name = tech['name']
            category = tech['category']

            # Flag potentially outdated/risky technologies
            risky_techs = {
                'jquery': 'jQuery detected - check for outdated versions with known XSS vulnerabilities',
                'angular': 'AngularJS (1.x) may have security issues if outdated',
                'wordpress': 'WordPress CMS - check for plugin vulnerabilities and version',
                'drupal': 'Drupal CMS - ensure core and modules are updated',
                'joomla': 'Joomla CMS - verify version for known vulnerabilities',
                'magento': 'Magento - common target for Magecart attacks',
                'php': 'PHP detected - verify version is not EOL',
                'asp_net': 'ASP.NET - check for ViewState security misconfigurations',
            }

            tech_id = tech.get('tech_id', name.lower().replace(' ', '_'))
            if tech_id in risky_techs:
                findings.append({
                    'technology': name,
                    'category': category,
                    'note': risky_techs[tech_id],
                    'severity': 'info'
                })

            # Flag missing security headers based on what we detect
            if category == 'cdn':
                findings.append({
                    'technology': name,
                    'category': 'cdn',
                    'note': f'CDN detected ({name}) - verify CDN security configuration',
                    'severity': 'info'
                })

            if category == 'security':
                findings.append({
                    'technology': name,
                    'category': 'security',
                    'note': f'Security tool/WAF detected ({name})',
                    'severity': 'info'
                })

        return findings


def main():
    parser = argparse.ArgumentParser(
        description="Technology Fingerprinting Tool (Semi-Passive)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool performs technology detection from a single HTTP request.
It analyzes headers, HTML, scripts, cookies, and favicon to identify
web technologies, frameworks, and libraries.

Semi-passive: Makes ONE request like a normal browser visit.

Engines:
  builtin    - Built-in detection engine (~80 signatures)
  wappalyzer - Official Wappalyzer engine (2000+ signatures, requires python-Wappalyzer)
  both       - Run both engines for maximum coverage

Examples:
  python tech_fingerprint.py -u https://example.com
  python tech_fingerprint.py -u https://example.com --engine wappalyzer
  python tech_fingerprint.py -u https://example.com --engine both
  python tech_fingerprint.py -u https://example.com -o results.json
  python tech_fingerprint.py -u example.com --no-favicon
  python tech_fingerprint.py -u example.com --no-save
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL to fingerprint")
    parser.add_argument("-o", "--output", help="Output file (JSON) - default: auto-generated in ./output/")
    parser.add_argument("--engine", choices=['builtin', 'wappalyzer', 'both'], default='builtin',
                        help="Detection engine: builtin (default), wappalyzer, or both")
    parser.add_argument("--no-favicon", action="store_true", help="Skip favicon fetching")
    parser.add_argument("--no-save", action="store_true", help="Don't auto-save results to file")
    parser.add_argument("--signatures", help="Custom signatures file path (for builtin engine)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15)")
    parser.add_argument("--json", action="store_true", help="Output as JSON only")

    args = parser.parse_args()

    fingerprinter = TechFingerprinter(
        signatures_path=args.signatures,
        timeout=args.timeout,
        engine=args.engine
    )

    results = fingerprinter.fingerprint(
        args.url,
        fetch_favicon=not args.no_favicon
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        fingerprinter.print_results()

        # Print security notes
        security = fingerprinter.get_security_relevant()
        if security:
            print(f"\n  Security Notes:")
            for finding in security:
                print(f"    [{finding['severity'].upper()}] {finding['note']}")

    # Auto-save results unless --no-save is specified
    if not args.no_save:
        if args.output:
            output_file = args.output
        else:
            # Auto-generate output filename
            output_dir = Path("./output/tech_fingerprint")
            output_dir.mkdir(parents=True, exist_ok=True)

            # Extract domain from URL for filename
            parsed_url = urlparse(args.url if args.url.startswith(('http://', 'https://')) else f'https://{args.url}')
            domain = parsed_url.netloc.replace(':', '_').replace('/', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = output_dir / f"{domain}_{timestamp}.json"

        fingerprinter.save_results(str(output_file))

    return 0


if __name__ == "__main__":
    sys.exit(main())
