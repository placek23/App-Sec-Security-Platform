"""
SQLAlchemy models for persistent storage of security scan data.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Float,
    DateTime, Boolean, ForeignKey, JSON, Enum as SQLEnum,
    Index, Table
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.ext.hybrid import hybrid_property
import enum
import json

Base = declarative_base()


class SeverityLevel(enum.Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(enum.Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(enum.Enum):
    """Types of security scans"""
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    WEB_DISCOVERY = "web_discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    INJECTION_TEST = "injection_test"
    ADVANCED_VULN = "advanced_vuln"
    API_TEST = "api_test"
    AUTH_TEST = "auth_test"
    FULL_HUNT = "full_hunt"


# Many-to-many relationship between scans and findings
scan_findings = Table(
    'scan_findings',
    Base.metadata,
    Column('scan_id', Integer, ForeignKey('scans.id'), primary_key=True),
    Column('finding_id', Integer, ForeignKey('findings.id'), primary_key=True)
)


class Target(Base):
    """Target organization or domain being tested"""
    __tablename__ = 'targets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text)
    scope = Column(JSON)  # In-scope and out-of-scope patterns
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    extra_data = Column(JSON)  # Additional target metadata

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    subdomains = relationship("Subdomain", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Target(name={self.name}, domain={self.domain})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'domain': self.domain,
            'description': self.description,
            'scope': self.scope,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'extra_data': self.extra_data
        }


class Scan(Base):
    """Security scan execution record"""
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False, index=True)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Float)
    tools_used = Column(JSON)  # List of tools executed
    configuration = Column(JSON)  # Scan configuration/options
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Summary statistics
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Relationships
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", secondary=scan_findings, back_populates="scans")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index('ix_scans_target_type', 'target_id', 'scan_type'),
        Index('ix_scans_status_created', 'status', 'created_at'),
    )

    def __repr__(self):
        return f"<Scan(id={self.id}, type={self.scan_type}, status={self.status})>"

    @hybrid_property
    def risk_score(self) -> float:
        """Calculate overall risk score based on findings"""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        total = (
            self.critical_count * weights['critical'] +
            self.high_count * weights['high'] +
            self.medium_count * weights['medium'] +
            self.low_count * weights['low'] +
            self.info_count * weights['info']
        )
        max_possible = self.findings_count * 10 if self.findings_count > 0 else 1
        return round((total / max_possible) * 100, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'target_id': self.target_id,
            'scan_type': self.scan_type.value if self.scan_type else None,
            'status': self.status.value if self.status else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'tools_used': self.tools_used,
            'configuration': self.configuration,
            'findings_count': self.findings_count,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'risk_score': self.risk_score,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Finding(Base):
    """Security finding/vulnerability"""
    __tablename__ = 'findings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(SeverityLevel), nullable=False, index=True)
    finding_type = Column(String(100), index=True)  # sqli, xss, ssrf, etc.
    tool = Column(String(100))  # Tool that discovered it

    # Location details
    url = Column(Text)
    parameter = Column(String(255))
    method = Column(String(10))  # GET, POST, etc.

    # Technical details
    payload = Column(Text)
    evidence = Column(Text)
    request = Column(Text)  # Raw HTTP request
    response = Column(Text)  # Raw HTTP response (truncated)

    # Classification
    cwe_id = Column(String(20))  # CWE-79, CWE-89, etc.
    cvss_score = Column(Float)  # CVSS 3.1 score
    cvss_vector = Column(String(100))  # CVSS vector string

    # Remediation
    remediation = Column(Text)
    references = Column(JSON)  # List of reference URLs

    # Status tracking
    is_false_positive = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime)
    verified_by = Column(String(100))
    notes = Column(Text)

    # Extra data
    raw_output = Column(Text)  # Original tool output
    extra_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Hash for deduplication
    finding_hash = Column(String(64), unique=True, index=True)

    # Relationships
    scans = relationship("Scan", secondary=scan_findings, back_populates="findings")

    __table_args__ = (
        Index('ix_findings_severity_type', 'severity', 'finding_type'),
        Index('ix_findings_tool', 'tool'),
    )

    def __repr__(self):
        return f"<Finding(title={self.title[:50]}, severity={self.severity})>"

    def calculate_hash(self) -> str:
        """Generate unique hash for deduplication"""
        import hashlib
        content = f"{self.title}:{self.url}:{self.parameter}:{self.finding_type}"
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value if self.severity else None,
            'finding_type': self.finding_type,
            'tool': self.tool,
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'payload': self.payload,
            'evidence': self.evidence,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'remediation': self.remediation,
            'references': self.references,
            'is_false_positive': self.is_false_positive,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class Subdomain(Base):
    """Discovered subdomain"""
    __tablename__ = 'subdomains'

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    ip_address = Column(String(45))  # IPv4 or IPv6
    status_code = Column(Integer)
    title = Column(String(500))
    technologies = Column(JSON)  # Detected technologies
    source = Column(String(100))  # Tool that discovered it
    is_alive = Column(Boolean, default=True)
    https_available = Column(Boolean)
    certificate_info = Column(JSON)  # SSL/TLS certificate details
    headers = Column(JSON)  # Response headers
    extra_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="subdomains")

    __table_args__ = (
        Index('ix_subdomains_target_domain', 'target_id', 'domain'),
    )

    def __repr__(self):
        return f"<Subdomain(domain={self.domain}, ip={self.ip_address})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'target_id': self.target_id,
            'domain': self.domain,
            'ip_address': self.ip_address,
            'status_code': self.status_code,
            'title': self.title,
            'technologies': self.technologies,
            'source': self.source,
            'is_alive': self.is_alive,
            'https_available': self.https_available,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }


class Endpoint(Base):
    """Discovered API endpoint or URL"""
    __tablename__ = 'endpoints'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), index=True)
    url = Column(Text, nullable=False)
    method = Column(String(10), default='GET')
    parameters = Column(JSON)  # List of parameters
    status_code = Column(Integer)
    content_type = Column(String(100))
    content_length = Column(Integer)
    source = Column(String(100))  # Tool that discovered it
    is_api_endpoint = Column(Boolean, default=False)
    authentication_required = Column(Boolean)
    extra_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="endpoints")

    def __repr__(self):
        return f"<Endpoint(url={self.url[:50]}, method={self.method})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'url': self.url,
            'method': self.method,
            'parameters': self.parameters,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'source': self.source,
            'is_api_endpoint': self.is_api_endpoint,
            'authentication_required': self.authentication_required,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Session(Base):
    """Authentication session storage"""
    __tablename__ = 'sessions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    cookies = Column(JSON)
    headers = Column(JSON)
    tokens = Column(JSON)  # JWT, API keys, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    extra_data = Column(JSON)

    def __repr__(self):
        return f"<Session(name={self.name})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'cookies': self.cookies,
            'headers': self.headers,
            'tokens': self.tokens,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }


class Report(Base):
    """Generated security report"""
    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), index=True)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50))  # html, pdf, json, markdown
    file_path = Column(String(500))
    file_size = Column(Integer)
    generated_at = Column(DateTime, default=datetime.utcnow)
    generated_by = Column(String(100))

    # Report content summary
    executive_summary = Column(Text)
    risk_rating = Column(String(20))  # Critical, High, Medium, Low
    total_findings = Column(Integer, default=0)

    # Configuration
    configuration = Column(JSON)  # Report generation options
    extra_data = Column(JSON)

    # Relationships
    scan = relationship("Scan", back_populates="reports")

    def __repr__(self):
        return f"<Report(title={self.title}, type={self.report_type})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'report_type': self.report_type,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'generated_by': self.generated_by,
            'executive_summary': self.executive_summary,
            'risk_rating': self.risk_rating,
            'total_findings': self.total_findings
        }


def init_db(db_path: str = "sqlite:///./output/appsec_bounty.db"):
    """Initialize database and create all tables"""
    engine = create_engine(db_path, echo=False)
    Base.metadata.create_all(engine)
    return engine


def get_session(engine):
    """Get database session"""
    Session = sessionmaker(bind=engine)
    return Session()
