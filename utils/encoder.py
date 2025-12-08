"""
Encoding/decoding utilities for payload manipulation.

Provides tools for:
- URL encoding (single and double)
- Base64 encoding/decoding
- HTML entity encoding
- Unicode encoding
- Hex encoding
- Chained encoding
- Common payload transformations
"""

import base64
import urllib.parse
import html
import json
import binascii
from typing import List, Union, Optional


class PayloadEncoder:
    """Encoding utilities for security testing payloads."""

    # URL Encoding
    @staticmethod
    def url_encode(payload: str, safe: str = '', double: bool = False) -> str:
        """
        URL encode a payload.

        Args:
            payload: String to encode
            safe: Characters to not encode
            double: Apply double encoding

        Returns:
            URL encoded string
        """
        encoded = urllib.parse.quote(payload, safe=safe)
        if double:
            encoded = urllib.parse.quote(encoded, safe='')
        return encoded

    @staticmethod
    def url_decode(payload: str, double: bool = False) -> str:
        """
        URL decode a payload.

        Args:
            payload: String to decode
            double: Apply double decoding

        Returns:
            Decoded string
        """
        decoded = urllib.parse.unquote(payload)
        if double:
            decoded = urllib.parse.unquote(decoded)
        return decoded

    @staticmethod
    def url_encode_all(payload: str) -> str:
        """URL encode all characters (including safe ones)."""
        return ''.join(f'%{ord(c):02X}' for c in payload)

    # Base64 Encoding
    @staticmethod
    def base64_encode(payload: Union[str, bytes]) -> str:
        """
        Base64 encode a payload.

        Args:
            payload: String or bytes to encode

        Returns:
            Base64 encoded string
        """
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        return base64.b64encode(payload).decode('utf-8')

    @staticmethod
    def base64_decode(payload: str) -> str:
        """
        Base64 decode a payload.

        Args:
            payload: Base64 encoded string

        Returns:
            Decoded string
        """
        # Handle padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return base64.b64decode(payload).decode('utf-8')

    @staticmethod
    def base64url_encode(payload: Union[str, bytes]) -> str:
        """Base64 URL-safe encode (used in JWTs)."""
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        return base64.urlsafe_b64encode(payload).decode('utf-8').rstrip('=')

    @staticmethod
    def base64url_decode(payload: str) -> str:
        """Base64 URL-safe decode (used in JWTs)."""
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return base64.urlsafe_b64decode(payload).decode('utf-8')

    # HTML Encoding
    @staticmethod
    def html_encode(payload: str) -> str:
        """HTML entity encode a payload."""
        return html.escape(payload)

    @staticmethod
    def html_decode(payload: str) -> str:
        """HTML entity decode a payload."""
        return html.unescape(payload)

    @staticmethod
    def html_encode_all(payload: str) -> str:
        """HTML encode all characters as numeric entities."""
        return ''.join(f'&#{ord(c)};' for c in payload)

    @staticmethod
    def html_encode_hex(payload: str) -> str:
        """HTML encode all characters as hex entities."""
        return ''.join(f'&#x{ord(c):x};' for c in payload)

    # Unicode Encoding
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode escape encode (\\uXXXX format)."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def unicode_decode(payload: str) -> str:
        """Decode Unicode escape sequences."""
        return payload.encode().decode('unicode_escape')

    @staticmethod
    def unicode_encode_wide(payload: str) -> str:
        """Wide Unicode encoding (\\u00XX format for ASCII)."""
        return ''.join(f'\\u00{ord(c):02x}' for c in payload)

    # Hex Encoding
    @staticmethod
    def hex_encode(payload: Union[str, bytes]) -> str:
        """Hex encode a payload."""
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        return payload.hex()

    @staticmethod
    def hex_decode(payload: str) -> str:
        """Hex decode a payload."""
        return bytes.fromhex(payload).decode('utf-8')

    @staticmethod
    def hex_encode_0x(payload: str) -> str:
        """Hex encode with 0x prefix for each character."""
        return ''.join(f'0x{ord(c):02x}' for c in payload)

    # Binary Encoding
    @staticmethod
    def binary_encode(payload: str) -> str:
        """Binary encode a string."""
        return ' '.join(f'{ord(c):08b}' for c in payload)

    @staticmethod
    def binary_decode(payload: str) -> str:
        """Decode binary string."""
        binary_values = payload.split()
        return ''.join(chr(int(b, 2)) for b in binary_values)

    # Octal Encoding
    @staticmethod
    def octal_encode(payload: str) -> str:
        """Octal encode a string (useful for some injection contexts)."""
        return ''.join(f'\\{ord(c):03o}' for c in payload)

    # JSON Encoding
    @staticmethod
    def json_encode(payload: str) -> str:
        """JSON string encode (handles escaping)."""
        return json.dumps(payload)[1:-1]  # Remove surrounding quotes

    @staticmethod
    def json_unicode_encode(payload: str) -> str:
        """JSON encode with all non-ASCII as \\uXXXX."""
        return json.dumps(payload, ensure_ascii=True)[1:-1]

    # Chained Encoding
    @staticmethod
    def chain_encode(payload: str, encodings: List[str]) -> str:
        """
        Apply multiple encodings in sequence.

        Args:
            payload: String to encode
            encodings: List of encoding names in order

        Supported encodings:
            url, url_double, url_all, base64, base64url, html, html_all,
            html_hex, unicode, unicode_wide, hex, hex_0x, binary, octal,
            json, json_unicode

        Returns:
            Encoded string
        """
        encoding_map = {
            'url': lambda p: PayloadEncoder.url_encode(p),
            'url_double': lambda p: PayloadEncoder.url_encode(p, double=True),
            'url_all': PayloadEncoder.url_encode_all,
            'base64': PayloadEncoder.base64_encode,
            'base64url': PayloadEncoder.base64url_encode,
            'html': PayloadEncoder.html_encode,
            'html_all': PayloadEncoder.html_encode_all,
            'html_hex': PayloadEncoder.html_encode_hex,
            'unicode': PayloadEncoder.unicode_encode,
            'unicode_wide': PayloadEncoder.unicode_encode_wide,
            'hex': PayloadEncoder.hex_encode,
            'hex_0x': PayloadEncoder.hex_encode_0x,
            'binary': PayloadEncoder.binary_encode,
            'octal': PayloadEncoder.octal_encode,
            'json': PayloadEncoder.json_encode,
            'json_unicode': PayloadEncoder.json_unicode_encode,
        }

        result = payload
        for encoding in encodings:
            if encoding not in encoding_map:
                raise ValueError(f"Unknown encoding: {encoding}")
            result = encoding_map[encoding](result)

        return result

    # Payload Transformations
    @staticmethod
    def case_swap(payload: str) -> str:
        """Swap case of alphabetic characters."""
        return payload.swapcase()

    @staticmethod
    def alternate_case(payload: str, start_upper: bool = True) -> str:
        """Alternate case (aLtErNaTe or AlTeRnAtE)."""
        result = []
        upper = start_upper
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if upper else c.lower())
                upper = not upper
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def reverse(payload: str) -> str:
        """Reverse a string."""
        return payload[::-1]

    @staticmethod
    def double_encode_special(payload: str) -> str:
        """Double URL encode only special characters."""
        special = '<>"\'&;()[]{}|\\`^'
        result = []
        for c in payload:
            if c in special:
                result.append(urllib.parse.quote(urllib.parse.quote(c, safe=''), safe=''))
            else:
                result.append(c)
        return ''.join(result)

    # Common XSS Bypass Encodings
    @staticmethod
    def xss_variants(payload: str) -> List[str]:
        """Generate common XSS bypass variants of a payload."""
        variants = [
            payload,  # Original
            PayloadEncoder.html_encode(payload),
            PayloadEncoder.url_encode(payload),
            PayloadEncoder.unicode_encode(payload),
            PayloadEncoder.case_swap(payload),
            PayloadEncoder.alternate_case(payload),
            # Mixed case
            payload.upper(),
            payload.lower(),
            # URL encoded
            PayloadEncoder.url_encode(payload, double=True),
            # Unicode variations
            payload.replace('<', '\\u003c').replace('>', '\\u003e'),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            # Null byte insertion
            payload.replace('<', '<\x00').replace('>', '\x00>'),
        ]
        return list(set(variants))  # Remove duplicates

    # SQL Injection Bypass Encodings
    @staticmethod
    def sql_bypass_variants(payload: str) -> List[str]:
        """Generate SQL injection bypass variants."""
        variants = [
            payload,
            # Comments
            payload.replace(' ', '/**/'),
            payload.replace(' ', '/*!*/'),
            # Case variations
            PayloadEncoder.alternate_case(payload),
            # URL encoding
            PayloadEncoder.url_encode(payload),
            PayloadEncoder.url_encode(payload, double=True),
            # Hex encoding for strings
            '0x' + payload.encode().hex() if "'" not in payload else payload,
            # Unicode
            payload.replace("'", "\\'"),
            payload.replace("'", "''"),
        ]
        return list(set(variants))


class PayloadDecoder:
    """Decoding utilities for analyzing encoded payloads."""

    @staticmethod
    def auto_decode(payload: str, max_iterations: int = 10) -> List[dict]:
        """
        Attempt to automatically decode a payload.

        Args:
            payload: Encoded payload
            max_iterations: Maximum decode iterations

        Returns:
            List of decode steps taken
        """
        steps = []
        current = payload
        iterations = 0

        while iterations < max_iterations:
            decoded = None
            encoding = None

            # Try URL decoding
            try:
                test = urllib.parse.unquote(current)
                if test != current:
                    decoded = test
                    encoding = 'url'
            except Exception:
                pass

            # Try Base64 decoding
            if not decoded:
                try:
                    # Check if it looks like base64
                    if len(current) % 4 == 0 or current.endswith('='):
                        test = base64.b64decode(current + '=' * (4 - len(current) % 4)).decode('utf-8')
                        if test.isprintable() or test.strip().isprintable():
                            decoded = test
                            encoding = 'base64'
                except Exception:
                    pass

            # Try HTML decoding
            if not decoded:
                try:
                    test = html.unescape(current)
                    if test != current:
                        decoded = test
                        encoding = 'html'
                except Exception:
                    pass

            # Try hex decoding
            if not decoded and all(c in '0123456789abcdefABCDEF' for c in current):
                try:
                    if len(current) % 2 == 0:
                        test = bytes.fromhex(current).decode('utf-8')
                        decoded = test
                        encoding = 'hex'
                except Exception:
                    pass

            if decoded:
                steps.append({
                    'iteration': iterations + 1,
                    'encoding': encoding,
                    'input': current,
                    'output': decoded
                })
                current = decoded
            else:
                break

            iterations += 1

        return steps

    @staticmethod
    def identify_encoding(payload: str) -> List[str]:
        """
        Attempt to identify the encoding of a payload.

        Args:
            payload: Payload to analyze

        Returns:
            List of possible encodings
        """
        possible = []

        # Check for URL encoding
        if '%' in payload:
            possible.append('url_encoded')
            if '%25' in payload:
                possible.append('double_url_encoded')

        # Check for Base64
        try:
            if len(payload) % 4 == 0 or payload.endswith('='):
                base64.b64decode(payload)
                possible.append('base64')
        except Exception:
            pass

        # Check for HTML entities
        if '&' in payload and ';' in payload:
            if '&#' in payload:
                possible.append('html_numeric_entity')
            elif '&lt;' in payload or '&gt;' in payload:
                possible.append('html_named_entity')

        # Check for Unicode escapes
        if '\\u' in payload:
            possible.append('unicode_escaped')

        # Check for hex
        if payload.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in payload):
            if len(payload) % 2 == 0:
                possible.append('hex')

        return possible


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Payload Encoder/Decoder')
    parser.add_argument('payload', help='Payload to encode/decode')
    parser.add_argument('--encode', '-e', action='append',
                        help='Encoding(s) to apply (can be used multiple times)')
    parser.add_argument('--decode', '-d', action='store_true',
                        help='Auto-decode the payload')
    parser.add_argument('--identify', '-i', action='store_true',
                        help='Identify encoding')
    parser.add_argument('--xss', action='store_true',
                        help='Generate XSS bypass variants')
    parser.add_argument('--sql', action='store_true',
                        help='Generate SQL bypass variants')

    args = parser.parse_args()

    if args.decode:
        print("[+] Auto-decoding payload...")
        steps = PayloadDecoder.auto_decode(args.payload)
        if steps:
            for step in steps:
                print(f"  Step {step['iteration']}: {step['encoding']}")
                print(f"    Input:  {step['input'][:50]}...")
                print(f"    Output: {step['output'][:50]}...")
            print(f"\n[+] Final decoded: {steps[-1]['output']}")
        else:
            print("[!] Could not decode payload")

    elif args.identify:
        print("[+] Identifying encoding...")
        encodings = PayloadDecoder.identify_encoding(args.payload)
        if encodings:
            print(f"  Possible encodings: {', '.join(encodings)}")
        else:
            print("  Could not identify encoding")

    elif args.xss:
        print("[+] XSS Bypass Variants:")
        for variant in PayloadEncoder.xss_variants(args.payload):
            print(f"  {variant}")

    elif args.sql:
        print("[+] SQL Bypass Variants:")
        for variant in PayloadEncoder.sql_bypass_variants(args.payload):
            print(f"  {variant}")

    elif args.encode:
        result = PayloadEncoder.chain_encode(args.payload, args.encode)
        print(f"[+] Encoded: {result}")

    else:
        # Show all encodings
        print(f"[+] Original: {args.payload}")
        print(f"[+] URL:      {PayloadEncoder.url_encode(args.payload)}")
        print(f"[+] Base64:   {PayloadEncoder.base64_encode(args.payload)}")
        print(f"[+] HTML:     {PayloadEncoder.html_encode(args.payload)}")
        print(f"[+] Unicode:  {PayloadEncoder.unicode_encode(args.payload)}")
        print(f"[+] Hex:      {PayloadEncoder.hex_encode(args.payload)}")
