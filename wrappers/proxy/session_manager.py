"""
Session and cookie management for security testing.

Provides tools for:
- Managing multiple authentication sessions
- Storing and switching between user contexts
- Token management (JWT, API keys, etc.)
- Session persistence and loading
"""

import json
import os
import base64
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path
from dataclasses import dataclass, field, asdict


@dataclass
class TokenInfo:
    """Token information storage."""
    value: str
    token_type: str  # bearer, api_key, basic, custom
    header_name: str = 'Authorization'
    header_format: str = 'Bearer {token}'
    expires_at: Optional[str] = None
    refresh_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionData:
    """Session data storage."""
    name: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, TokenInfo] = field(default_factory=dict)
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    last_used: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionManager:
    """Session and cookie management for security testing."""

    def __init__(self, storage_dir: str = './output/sessions'):
        """
        Initialize SessionManager.

        Args:
            storage_dir: Directory for storing session files
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.sessions: Dict[str, SessionData] = {}
        self.current_session: Optional[str] = None

    def create_session(
        self,
        name: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        make_current: bool = True
    ) -> str:
        """
        Create a new named session.

        Args:
            name: Session name
            cookies: Initial cookies
            headers: Initial headers
            metadata: Additional metadata
            make_current: Set as current session

        Returns:
            Session name
        """
        if name in self.sessions:
            raise ValueError(f"Session '{name}' already exists. Use update_session() or delete it first.")

        session = SessionData(
            name=name,
            cookies=cookies or {},
            headers=headers or {},
            metadata=metadata or {}
        )

        self.sessions[name] = session

        if make_current:
            self.current_session = name

        print(f"[+] Created session: {name}")
        return name

    def delete_session(self, name: str):
        """Delete a session."""
        if name not in self.sessions:
            raise KeyError(f"Session '{name}' not found")

        del self.sessions[name]

        if self.current_session == name:
            self.current_session = None

        print(f"[+] Deleted session: {name}")

    def switch_session(self, name: str) -> SessionData:
        """
        Switch to a different session.

        Args:
            name: Session name to switch to

        Returns:
            Session data
        """
        if name not in self.sessions:
            raise KeyError(f"Session '{name}' not found")

        self.current_session = name
        self.sessions[name].last_used = datetime.now().isoformat()

        print(f"[+] Switched to session: {name}")
        return self.sessions[name]

    def get_current_session(self) -> Optional[SessionData]:
        """Get current session data."""
        if not self.current_session:
            return None
        return self.sessions.get(self.current_session)

    def add_token(
        self,
        token_name: str,
        token_value: str,
        token_type: str = 'bearer',
        header_name: str = 'Authorization',
        header_format: str = 'Bearer {token}',
        expires_at: Optional[str] = None,
        refresh_token: Optional[str] = None,
        session_name: Optional[str] = None
    ):
        """
        Add authentication token to a session.

        Args:
            token_name: Name to identify this token
            token_value: The token value
            token_type: Token type (bearer, api_key, basic, custom)
            header_name: Header name to use
            header_format: Format string for header value
            expires_at: Token expiration time (ISO format)
            refresh_token: Optional refresh token
            session_name: Session to add token to (uses current if None)
        """
        session_name = session_name or self.current_session
        if not session_name:
            raise ValueError("No active session. Create or switch to a session first.")

        if session_name not in self.sessions:
            raise KeyError(f"Session '{session_name}' not found")

        token_info = TokenInfo(
            value=token_value,
            token_type=token_type,
            header_name=header_name,
            header_format=header_format,
            expires_at=expires_at,
            refresh_token=refresh_token
        )

        self.sessions[session_name].tokens[token_name] = token_info
        print(f"[+] Added token '{token_name}' to session '{session_name}'")

    def add_jwt(
        self,
        token_name: str,
        jwt_token: str,
        refresh_token: Optional[str] = None,
        session_name: Optional[str] = None
    ):
        """
        Add JWT token to session (convenience method).

        Args:
            token_name: Name for the token
            jwt_token: JWT token value
            refresh_token: Optional refresh token
            session_name: Target session
        """
        # Try to decode JWT to get expiration
        expires_at = None
        try:
            # Decode without verification to get expiry
            parts = jwt_token.split('.')
            if len(parts) == 3:
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                if 'exp' in payload:
                    expires_at = datetime.fromtimestamp(payload['exp']).isoformat()
        except Exception:
            pass

        self.add_token(
            token_name=token_name,
            token_value=jwt_token,
            token_type='bearer',
            header_name='Authorization',
            header_format='Bearer {token}',
            expires_at=expires_at,
            refresh_token=refresh_token,
            session_name=session_name
        )

    def add_api_key(
        self,
        token_name: str,
        api_key: str,
        header_name: str = 'X-API-Key',
        session_name: Optional[str] = None
    ):
        """
        Add API key to session (convenience method).

        Args:
            token_name: Name for the token
            api_key: API key value
            header_name: Header name for API key
            session_name: Target session
        """
        self.add_token(
            token_name=token_name,
            token_value=api_key,
            token_type='api_key',
            header_name=header_name,
            header_format='{token}',
            session_name=session_name
        )

    def add_basic_auth(
        self,
        token_name: str,
        username: str,
        password: str,
        session_name: Optional[str] = None
    ):
        """
        Add Basic authentication to session.

        Args:
            token_name: Name for the credential
            username: Username
            password: Password
            session_name: Target session
        """
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

        self.add_token(
            token_name=token_name,
            token_value=credentials,
            token_type='basic',
            header_name='Authorization',
            header_format='Basic {token}',
            session_name=session_name
        )

    def add_cookie(
        self,
        name: str,
        value: str,
        session_name: Optional[str] = None
    ):
        """
        Add cookie to session.

        Args:
            name: Cookie name
            value: Cookie value
            session_name: Target session
        """
        session_name = session_name or self.current_session
        if not session_name:
            raise ValueError("No active session")

        self.sessions[session_name].cookies[name] = value
        print(f"[+] Added cookie '{name}' to session '{session_name}'")

    def add_header(
        self,
        name: str,
        value: str,
        session_name: Optional[str] = None
    ):
        """
        Add custom header to session.

        Args:
            name: Header name
            value: Header value
            session_name: Target session
        """
        session_name = session_name or self.current_session
        if not session_name:
            raise ValueError("No active session")

        self.sessions[session_name].headers[name] = value
        print(f"[+] Added header '{name}' to session '{session_name}'")

    def get_auth_headers(self, session_name: Optional[str] = None) -> Dict[str, str]:
        """
        Get all authentication headers for a session.

        Args:
            session_name: Session name (uses current if None)

        Returns:
            Dictionary of headers with authentication
        """
        session_name = session_name or self.current_session
        if not session_name:
            return {}

        session = self.sessions.get(session_name)
        if not session:
            return {}

        headers = session.headers.copy()

        # Add token headers
        for token_name, token_info in session.tokens.items():
            header_value = token_info.header_format.format(token=token_info.value)
            headers[token_info.header_name] = header_value

        return headers

    def get_cookies(self, session_name: Optional[str] = None) -> Dict[str, str]:
        """
        Get all cookies for a session.

        Args:
            session_name: Session name (uses current if None)

        Returns:
            Dictionary of cookies
        """
        session_name = session_name or self.current_session
        if not session_name:
            return {}

        session = self.sessions.get(session_name)
        return session.cookies.copy() if session else {}

    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all sessions.

        Returns:
            List of session summaries
        """
        return [
            {
                'name': name,
                'current': name == self.current_session,
                'tokens': list(session.tokens.keys()),
                'cookies': list(session.cookies.keys()),
                'created': session.created,
                'last_used': session.last_used
            }
            for name, session in self.sessions.items()
        ]

    def save_sessions(self, filepath: Optional[str] = None):
        """
        Save all sessions to file.

        Args:
            filepath: Output file path (default: sessions.json in storage_dir)
        """
        filepath = filepath or (self.storage_dir / 'sessions.json')

        data = {
            'current_session': self.current_session,
            'sessions': {}
        }

        for name, session in self.sessions.items():
            session_dict = {
                'name': session.name,
                'cookies': session.cookies,
                'headers': session.headers,
                'tokens': {
                    k: {
                        'value': v.value,
                        'token_type': v.token_type,
                        'header_name': v.header_name,
                        'header_format': v.header_format,
                        'expires_at': v.expires_at,
                        'refresh_token': v.refresh_token,
                        'metadata': v.metadata
                    }
                    for k, v in session.tokens.items()
                },
                'created': session.created,
                'last_used': session.last_used,
                'metadata': session.metadata
            }
            data['sessions'][name] = session_dict

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Sessions saved to: {filepath}")

    def load_sessions(self, filepath: Optional[str] = None):
        """
        Load sessions from file.

        Args:
            filepath: Input file path (default: sessions.json in storage_dir)
        """
        filepath = filepath or (self.storage_dir / 'sessions.json')

        if not os.path.exists(filepath):
            print(f"[!] Session file not found: {filepath}")
            return

        with open(filepath, 'r') as f:
            data = json.load(f)

        self.sessions = {}

        for name, session_dict in data.get('sessions', {}).items():
            tokens = {}
            for token_name, token_data in session_dict.get('tokens', {}).items():
                tokens[token_name] = TokenInfo(
                    value=token_data['value'],
                    token_type=token_data['token_type'],
                    header_name=token_data.get('header_name', 'Authorization'),
                    header_format=token_data.get('header_format', 'Bearer {token}'),
                    expires_at=token_data.get('expires_at'),
                    refresh_token=token_data.get('refresh_token'),
                    metadata=token_data.get('metadata', {})
                )

            self.sessions[name] = SessionData(
                name=session_dict['name'],
                cookies=session_dict.get('cookies', {}),
                headers=session_dict.get('headers', {}),
                tokens=tokens,
                created=session_dict.get('created', datetime.now().isoformat()),
                last_used=session_dict.get('last_used', datetime.now().isoformat()),
                metadata=session_dict.get('metadata', {})
            )

        self.current_session = data.get('current_session')

        print(f"[+] Loaded {len(self.sessions)} sessions from: {filepath}")

    def export_for_requests(self, session_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Export session data in format suitable for requests library.

        Args:
            session_name: Session to export (uses current if None)

        Returns:
            Dictionary with 'headers' and 'cookies' keys
        """
        return {
            'headers': self.get_auth_headers(session_name),
            'cookies': self.get_cookies(session_name)
        }

    def clone_session(self, source_name: str, new_name: str) -> str:
        """
        Clone an existing session.

        Args:
            source_name: Source session name
            new_name: New session name

        Returns:
            New session name
        """
        if source_name not in self.sessions:
            raise KeyError(f"Session '{source_name}' not found")

        if new_name in self.sessions:
            raise ValueError(f"Session '{new_name}' already exists")

        source = self.sessions[source_name]

        # Deep copy tokens
        new_tokens = {
            k: TokenInfo(
                value=v.value,
                token_type=v.token_type,
                header_name=v.header_name,
                header_format=v.header_format,
                expires_at=v.expires_at,
                refresh_token=v.refresh_token,
                metadata=v.metadata.copy()
            )
            for k, v in source.tokens.items()
        }

        self.sessions[new_name] = SessionData(
            name=new_name,
            cookies=source.cookies.copy(),
            headers=source.headers.copy(),
            tokens=new_tokens,
            metadata=source.metadata.copy()
        )

        print(f"[+] Cloned session '{source_name}' to '{new_name}'")
        return new_name


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Session Manager')
    parser.add_argument('--action', '-a', choices=['create', 'list', 'switch', 'export'],
                        required=True, help='Action to perform')
    parser.add_argument('--name', '-n', help='Session name')
    parser.add_argument('--token', '-t', help='Token value (for create)')
    parser.add_argument('--token-type', default='bearer', help='Token type')
    parser.add_argument('--storage', '-s', default='./output/sessions', help='Storage directory')

    args = parser.parse_args()

    manager = SessionManager(storage_dir=args.storage)

    # Try to load existing sessions
    try:
        manager.load_sessions()
    except Exception:
        pass

    if args.action == 'create':
        if not args.name:
            print("[!] Session name required for create action")
        else:
            manager.create_session(args.name)
            if args.token:
                manager.add_token('default', args.token, token_type=args.token_type)
            manager.save_sessions()

    elif args.action == 'list':
        sessions = manager.list_sessions()
        print("\n[+] Sessions:")
        for s in sessions:
            current = " (current)" if s['current'] else ""
            print(f"  - {s['name']}{current}")
            print(f"    Tokens: {s['tokens']}")
            print(f"    Cookies: {s['cookies']}")

    elif args.action == 'switch':
        if not args.name:
            print("[!] Session name required for switch action")
        else:
            manager.switch_session(args.name)
            manager.save_sessions()

    elif args.action == 'export':
        session_name = args.name or manager.current_session
        if not session_name:
            print("[!] No session specified or selected")
        else:
            data = manager.export_for_requests(session_name)
            print(json.dumps(data, indent=2))
