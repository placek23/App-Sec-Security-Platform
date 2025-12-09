"""
Database Manager - CRUD operations for security scan data.
"""
import os
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from contextlib import contextmanager

from sqlalchemy import create_engine, func, and_, or_, desc
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError

from database.models import (
    Base, Target, Scan, Finding, Subdomain, Endpoint,
    Session as ScanSession, Report,
    SeverityLevel, ScanStatus, ScanType
)


class DatabaseManager:
    """Manager class for database operations"""

    def __init__(self, db_path: str = None):
        """Initialize database connection"""
        if db_path is None:
            # Default to output directory
            output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
            os.makedirs(output_dir, exist_ok=True)
            db_path = f"sqlite:///{os.path.join(output_dir, 'appsec_bounty.db')}"

        self.db_path = db_path
        self.engine = create_engine(db_path, echo=False)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

    @contextmanager
    def get_session(self) -> Session:
        """Context manager for database sessions"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    # ==================== Target Operations ====================

    def create_target(self, name: str, domain: str, description: str = None,
                      scope: Dict = None, metadata: Dict = None) -> Target:
        """Create a new target"""
        with self.get_session() as session:
            target = Target(
                name=name,
                domain=domain,
                description=description,
                scope=scope or {'in_scope': [], 'out_of_scope': []},
                metadata=metadata
            )
            session.add(target)
            session.flush()
            return target.to_dict()

    def get_target(self, target_id: int = None, domain: str = None) -> Optional[Dict]:
        """Get target by ID or domain"""
        with self.get_session() as session:
            if target_id:
                target = session.query(Target).filter(Target.id == target_id).first()
            elif domain:
                target = session.query(Target).filter(Target.domain == domain).first()
            else:
                return None
            return target.to_dict() if target else None

    def get_or_create_target(self, name: str, domain: str, **kwargs) -> Dict:
        """Get existing target or create new one"""
        with self.get_session() as session:
            target = session.query(Target).filter(Target.domain == domain).first()
            if not target:
                target = Target(name=name, domain=domain, **kwargs)
                session.add(target)
                session.flush()
            return target.to_dict()

    def list_targets(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """List all targets"""
        with self.get_session() as session:
            targets = session.query(Target).order_by(
                desc(Target.updated_at)
            ).offset(offset).limit(limit).all()
            return [t.to_dict() for t in targets]

    def update_target(self, target_id: int, **kwargs) -> Optional[Dict]:
        """Update target details"""
        with self.get_session() as session:
            target = session.query(Target).filter(Target.id == target_id).first()
            if not target:
                return None
            for key, value in kwargs.items():
                if hasattr(target, key):
                    setattr(target, key, value)
            target.updated_at = datetime.utcnow()
            session.flush()
            return target.to_dict()

    def delete_target(self, target_id: int) -> bool:
        """Delete target and all related data"""
        with self.get_session() as session:
            target = session.query(Target).filter(Target.id == target_id).first()
            if target:
                session.delete(target)
                return True
            return False

    # ==================== Scan Operations ====================

    def create_scan(self, target_id: int, scan_type: str,
                    configuration: Dict = None) -> Dict:
        """Create a new scan"""
        with self.get_session() as session:
            scan = Scan(
                target_id=target_id,
                scan_type=ScanType(scan_type),
                status=ScanStatus.PENDING,
                configuration=configuration or {}
            )
            session.add(scan)
            session.flush()
            return scan.to_dict()

    def start_scan(self, scan_id: int, tools: List[str] = None) -> Dict:
        """Mark scan as started"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.tools_used = tools or []
                session.flush()
                return scan.to_dict()
            return None

    def complete_scan(self, scan_id: int, error_message: str = None) -> Dict:
        """Mark scan as completed or failed"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.completed_at = datetime.utcnow()
                if scan.started_at:
                    scan.duration_seconds = (
                        scan.completed_at - scan.started_at
                    ).total_seconds()

                if error_message:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = error_message
                else:
                    scan.status = ScanStatus.COMPLETED

                # Update finding counts
                self._update_scan_counts(session, scan)
                session.flush()
                return scan.to_dict()
            return None

    def _update_scan_counts(self, session: Session, scan: Scan):
        """Update finding counts for a scan"""
        findings = scan.findings
        scan.findings_count = len(findings)
        scan.critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        scan.high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        scan.medium_count = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        scan.low_count = sum(1 for f in findings if f.severity == SeverityLevel.LOW)
        scan.info_count = sum(1 for f in findings if f.severity == SeverityLevel.INFO)

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        """Get scan by ID"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            return scan.to_dict() if scan else None

    def list_scans(self, target_id: int = None, scan_type: str = None,
                   status: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """List scans with optional filters"""
        with self.get_session() as session:
            query = session.query(Scan)
            if target_id:
                query = query.filter(Scan.target_id == target_id)
            if scan_type:
                query = query.filter(Scan.scan_type == ScanType(scan_type))
            if status:
                query = query.filter(Scan.status == ScanStatus(status))
            scans = query.order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()
            return [s.to_dict() for s in scans]

    def get_scan_with_findings(self, scan_id: int) -> Optional[Dict]:
        """Get scan with all its findings"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return None
            result = scan.to_dict()
            result['findings'] = [f.to_dict() for f in scan.findings]
            result['endpoints'] = [e.to_dict() for e in scan.endpoints]
            return result

    # ==================== Finding Operations ====================

    def add_finding(self, scan_id: int, title: str, severity: str,
                    description: str = None, **kwargs) -> Dict:
        """Add a new finding to a scan"""
        with self.get_session() as session:
            # Generate hash for deduplication
            finding_hash = hashlib.sha256(
                f"{title}:{kwargs.get('url', '')}:{kwargs.get('parameter', '')}:{kwargs.get('finding_type', '')}".encode()
            ).hexdigest()

            # Check for duplicate
            existing = session.query(Finding).filter(
                Finding.finding_hash == finding_hash
            ).first()

            if existing:
                # Link to scan if not already linked
                scan = session.query(Scan).filter(Scan.id == scan_id).first()
                if scan and existing not in scan.findings:
                    scan.findings.append(existing)
                return existing.to_dict()

            # Create new finding
            finding = Finding(
                title=title,
                severity=SeverityLevel(severity.lower()),
                description=description,
                finding_hash=finding_hash,
                **kwargs
            )
            session.add(finding)

            # Link to scan
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.findings.append(finding)

            session.flush()
            return finding.to_dict()

    def add_findings_batch(self, scan_id: int, findings: List[Dict]) -> int:
        """Add multiple findings in batch"""
        added_count = 0
        for finding_data in findings:
            try:
                self.add_finding(scan_id, **finding_data)
                added_count += 1
            except Exception:
                continue
        return added_count

    def get_finding(self, finding_id: int) -> Optional[Dict]:
        """Get finding by ID"""
        with self.get_session() as session:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            return finding.to_dict() if finding else None

    def update_finding(self, finding_id: int, **kwargs) -> Optional[Dict]:
        """Update finding details"""
        with self.get_session() as session:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                return None
            for key, value in kwargs.items():
                if hasattr(finding, key):
                    if key == 'severity':
                        value = SeverityLevel(value.lower())
                    setattr(finding, key, value)
            finding.updated_at = datetime.utcnow()
            session.flush()
            return finding.to_dict()

    def mark_false_positive(self, finding_id: int, notes: str = None) -> Optional[Dict]:
        """Mark finding as false positive"""
        return self.update_finding(
            finding_id,
            is_false_positive=True,
            notes=notes
        )

    def verify_finding(self, finding_id: int, verified_by: str = None) -> Optional[Dict]:
        """Mark finding as verified"""
        return self.update_finding(
            finding_id,
            is_verified=True,
            verified_at=datetime.utcnow(),
            verified_by=verified_by
        )

    def list_findings(self, scan_id: int = None, severity: str = None,
                      finding_type: str = None, is_false_positive: bool = None,
                      limit: int = 100, offset: int = 0) -> List[Dict]:
        """List findings with filters"""
        with self.get_session() as session:
            query = session.query(Finding)

            if scan_id:
                scan = session.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    query = query.filter(Finding.id.in_([f.id for f in scan.findings]))

            if severity:
                query = query.filter(Finding.severity == SeverityLevel(severity.lower()))

            if finding_type:
                query = query.filter(Finding.finding_type == finding_type)

            if is_false_positive is not None:
                query = query.filter(Finding.is_false_positive == is_false_positive)

            findings = query.order_by(desc(Finding.created_at)).offset(offset).limit(limit).all()
            return [f.to_dict() for f in findings]

    def get_findings_by_severity(self, scan_id: int = None) -> Dict[str, List[Dict]]:
        """Group findings by severity"""
        findings = self.list_findings(scan_id=scan_id, limit=1000)
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        for finding in findings:
            sev = finding.get('severity', 'info')
            if sev in grouped:
                grouped[sev].append(finding)
        return grouped

    # ==================== Subdomain Operations ====================

    def add_subdomain(self, target_id: int, domain: str, **kwargs) -> Dict:
        """Add discovered subdomain"""
        with self.get_session() as session:
            # Check for existing
            existing = session.query(Subdomain).filter(
                and_(Subdomain.target_id == target_id, Subdomain.domain == domain)
            ).first()

            if existing:
                # Update existing subdomain
                for key, value in kwargs.items():
                    if hasattr(existing, key) and value:
                        setattr(existing, key, value)
                existing.last_seen = datetime.utcnow()
                session.flush()
                return existing.to_dict()

            subdomain = Subdomain(
                target_id=target_id,
                domain=domain,
                **kwargs
            )
            session.add(subdomain)
            session.flush()
            return subdomain.to_dict()

    def add_subdomains_batch(self, target_id: int, subdomains: List[Dict]) -> int:
        """Add multiple subdomains in batch"""
        added_count = 0
        for sub_data in subdomains:
            try:
                self.add_subdomain(target_id, **sub_data)
                added_count += 1
            except Exception:
                continue
        return added_count

    def list_subdomains(self, target_id: int, is_alive: bool = None,
                        limit: int = 1000, offset: int = 0) -> List[Dict]:
        """List subdomains for a target"""
        with self.get_session() as session:
            query = session.query(Subdomain).filter(Subdomain.target_id == target_id)
            if is_alive is not None:
                query = query.filter(Subdomain.is_alive == is_alive)
            subdomains = query.order_by(Subdomain.domain).offset(offset).limit(limit).all()
            return [s.to_dict() for s in subdomains]

    # ==================== Endpoint Operations ====================

    def add_endpoint(self, scan_id: int, url: str, **kwargs) -> Dict:
        """Add discovered endpoint"""
        with self.get_session() as session:
            endpoint = Endpoint(
                scan_id=scan_id,
                url=url,
                **kwargs
            )
            session.add(endpoint)
            session.flush()
            return endpoint.to_dict()

    def add_endpoints_batch(self, scan_id: int, endpoints: List[Dict]) -> int:
        """Add multiple endpoints in batch"""
        added_count = 0
        for ep_data in endpoints:
            try:
                self.add_endpoint(scan_id, **ep_data)
                added_count += 1
            except Exception:
                continue
        return added_count

    def list_endpoints(self, scan_id: int, is_api: bool = None,
                       limit: int = 1000, offset: int = 0) -> List[Dict]:
        """List endpoints for a scan"""
        with self.get_session() as session:
            query = session.query(Endpoint).filter(Endpoint.scan_id == scan_id)
            if is_api is not None:
                query = query.filter(Endpoint.is_api_endpoint == is_api)
            endpoints = query.order_by(Endpoint.url).offset(offset).limit(limit).all()
            return [e.to_dict() for e in endpoints]

    # ==================== Report Operations ====================

    def create_report(self, scan_id: int, title: str, report_type: str,
                      file_path: str, **kwargs) -> Dict:
        """Create report record"""
        with self.get_session() as session:
            report = Report(
                scan_id=scan_id,
                title=title,
                report_type=report_type,
                file_path=file_path,
                generated_at=datetime.utcnow(),
                **kwargs
            )
            session.add(report)
            session.flush()
            return report.to_dict()

    def list_reports(self, scan_id: int = None, report_type: str = None,
                     limit: int = 100, offset: int = 0) -> List[Dict]:
        """List generated reports"""
        with self.get_session() as session:
            query = session.query(Report)
            if scan_id:
                query = query.filter(Report.scan_id == scan_id)
            if report_type:
                query = query.filter(Report.report_type == report_type)
            reports = query.order_by(desc(Report.generated_at)).offset(offset).limit(limit).all()
            return [r.to_dict() for r in reports]

    # ==================== Analytics Operations ====================

    def get_summary_stats(self, target_id: int = None,
                          days: int = 30) -> Dict[str, Any]:
        """Get summary statistics"""
        with self.get_session() as session:
            since = datetime.utcnow() - timedelta(days=days)

            # Base query
            scan_query = session.query(Scan).filter(Scan.created_at >= since)
            finding_query = session.query(Finding).filter(Finding.created_at >= since)

            if target_id:
                scan_query = scan_query.filter(Scan.target_id == target_id)
                # For findings, we need to join through scan_findings
                scan_ids = [s.id for s in scan_query.all()]
                finding_query = finding_query.filter(
                    Finding.scans.any(Scan.id.in_(scan_ids))
                )

            # Calculate stats
            scans = scan_query.all()
            findings = finding_query.all()

            severity_counts = {
                'critical': sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
                'high': sum(1 for f in findings if f.severity == SeverityLevel.HIGH),
                'medium': sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM),
                'low': sum(1 for f in findings if f.severity == SeverityLevel.LOW),
                'info': sum(1 for f in findings if f.severity == SeverityLevel.INFO)
            }

            return {
                'period_days': days,
                'total_scans': len(scans),
                'completed_scans': sum(1 for s in scans if s.status == ScanStatus.COMPLETED),
                'failed_scans': sum(1 for s in scans if s.status == ScanStatus.FAILED),
                'total_findings': len(findings),
                'severity_breakdown': severity_counts,
                'false_positives': sum(1 for f in findings if f.is_false_positive),
                'verified_findings': sum(1 for f in findings if f.is_verified),
                'unique_finding_types': len(set(f.finding_type for f in findings if f.finding_type)),
                'avg_findings_per_scan': round(len(findings) / len(scans), 2) if scans else 0
            }

    def get_trend_data(self, target_id: int = None,
                       days: int = 30, interval: str = 'day') -> List[Dict]:
        """Get trend data for charting"""
        with self.get_session() as session:
            since = datetime.utcnow() - timedelta(days=days)

            scan_query = session.query(Scan).filter(Scan.created_at >= since)
            if target_id:
                scan_query = scan_query.filter(Scan.target_id == target_id)

            scans = scan_query.order_by(Scan.created_at).all()

            # Group by date
            trends = {}
            for scan in scans:
                if interval == 'day':
                    key = scan.created_at.strftime('%Y-%m-%d')
                elif interval == 'week':
                    key = scan.created_at.strftime('%Y-W%W')
                else:
                    key = scan.created_at.strftime('%Y-%m')

                if key not in trends:
                    trends[key] = {
                        'date': key,
                        'scans': 0,
                        'findings': 0,
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0
                    }

                trends[key]['scans'] += 1
                trends[key]['findings'] += scan.findings_count or 0
                trends[key]['critical'] += scan.critical_count or 0
                trends[key]['high'] += scan.high_count or 0
                trends[key]['medium'] += scan.medium_count or 0
                trends[key]['low'] += scan.low_count or 0

            return list(trends.values())

    def compare_scans(self, scan_id_1: int, scan_id_2: int) -> Dict[str, Any]:
        """Compare two scans"""
        scan1 = self.get_scan_with_findings(scan_id_1)
        scan2 = self.get_scan_with_findings(scan_id_2)

        if not scan1 or not scan2:
            return None

        findings1 = {f['finding_hash'] if 'finding_hash' in f else f['id']: f for f in scan1.get('findings', [])}
        findings2 = {f['finding_hash'] if 'finding_hash' in f else f['id']: f for f in scan2.get('findings', [])}

        new_findings = [f for k, f in findings2.items() if k not in findings1]
        resolved_findings = [f for k, f in findings1.items() if k not in findings2]
        common_findings = [f for k, f in findings2.items() if k in findings1]

        return {
            'scan_1': {
                'id': scan_id_1,
                'total_findings': scan1.get('findings_count', 0),
                'risk_score': scan1.get('risk_score', 0)
            },
            'scan_2': {
                'id': scan_id_2,
                'total_findings': scan2.get('findings_count', 0),
                'risk_score': scan2.get('risk_score', 0)
            },
            'new_findings': len(new_findings),
            'resolved_findings': len(resolved_findings),
            'common_findings': len(common_findings),
            'new_findings_list': new_findings,
            'resolved_findings_list': resolved_findings
        }

    def export_data(self, target_id: int = None, format: str = 'json') -> str:
        """Export all data for a target"""
        import json

        data = {
            'exported_at': datetime.utcnow().isoformat(),
            'targets': [],
            'scans': [],
            'findings': [],
            'subdomains': [],
            'endpoints': []
        }

        if target_id:
            target = self.get_target(target_id=target_id)
            if target:
                data['targets'] = [target]
                data['scans'] = self.list_scans(target_id=target_id, limit=10000)
                data['subdomains'] = self.list_subdomains(target_id, limit=10000)
                for scan in data['scans']:
                    data['findings'].extend(self.list_findings(scan_id=scan['id'], limit=10000))
                    data['endpoints'].extend(self.list_endpoints(scan['id'], limit=10000))
        else:
            data['targets'] = self.list_targets(limit=10000)
            for target in data['targets']:
                data['scans'].extend(self.list_scans(target_id=target['id'], limit=10000))
                data['subdomains'].extend(self.list_subdomains(target['id'], limit=10000))
            for scan in data['scans']:
                data['findings'].extend(self.list_findings(scan_id=scan['id'], limit=10000))
                data['endpoints'].extend(self.list_endpoints(scan['id'], limit=10000))

        if format == 'json':
            return json.dumps(data, indent=2, default=str)
        else:
            return data
