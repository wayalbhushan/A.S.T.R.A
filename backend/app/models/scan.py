import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.extensions import db

class ScanRecord(db.Model):
    """Stores every APK scan along with analysis and signal results."""
    __tablename__ = "scan_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)  # SHA-256
    package_name: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)  # pending, processing, complete, failed
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 0 to 100
    verdict: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # TRUSTED, UNKNOWN, SUSPICIOUS, MALICIOUS
    
    # ML specific fields
    ml_class: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ml_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    static_ml_class: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    static_ml_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # Signatures and external APIs
    signature_verdict: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    vt_detection_ratio: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Granular analysis details stored as JSONB/JSON
    androguard_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    vt_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    sandbox_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ml_explanation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Certificate association (ForeignKey with user corrections)
    cert_hash: Mapped[Optional[str]] = mapped_column(
        ForeignKey("certificate_records.cert_hash"), 
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), 
        nullable=True
    )

    # Relationships
    certificate: Mapped[Optional["CertificateRecord"]] = relationship(
        "CertificateRecord", 
        back_populates="scans",
        foreign_keys=[cert_hash]
    )

    def __init__(
        self,
        id: uuid.UUID,
        file_name: str,
        file_hash: str,
        status: str = "pending",
        package_name: Optional[str] = None,
        risk_score: Optional[int] = None,
        verdict: Optional[str] = None,
        ml_class: Optional[str] = None,
        ml_confidence: Optional[float] = None,
        static_ml_class: Optional[str] = None,
        static_ml_confidence: Optional[float] = None,
        signature_verdict: Optional[str] = None,
        vt_detection_ratio: Optional[str] = None,
        androguard_data: Optional[dict] = None,
        vt_data: Optional[dict] = None,
        sandbox_data: Optional[dict] = None,
        ml_explanation: Optional[dict] = None,
        cert_hash: Optional[str] = None,
        completed_at: Optional[datetime] = None
    ) -> None:
        """Constructs a ScanRecord instance."""
        self.id = id
        self.file_name = file_name
        self.file_hash = file_hash
        self.status = status
        self.package_name = package_name
        self.risk_score = risk_score
        self.verdict = verdict
        self.ml_class = ml_class
        self.ml_confidence = ml_confidence
        self.static_ml_class = static_ml_class
        self.static_ml_confidence = static_ml_confidence
        self.signature_verdict = signature_verdict
        self.vt_detection_ratio = vt_detection_ratio
        self.androguard_data = androguard_data
        self.vt_data = vt_data
        self.sandbox_data = sandbox_data
        self.ml_explanation = ml_explanation
        self.cert_hash = cert_hash
        self.completed_at = completed_at

    def __repr__(self) -> str:
        return f"<ScanRecord id={self.id} file={self.file_name} status={self.status}>"


class CertificateRecord(db.Model):
    """Stores certificate hashes used for tracking threat campaigns."""
    __tablename__ = "certificate_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cert_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    issuer: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scan_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    malicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    scans: Mapped[List["ScanRecord"]] = relationship(
        "ScanRecord",
        back_populates="certificate",
        foreign_keys=[ScanRecord.cert_hash]
    )

    def __init__(
        self,
        cert_hash: str,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        scan_count: int = 0,
        malicious_count: int = 0
    ) -> None:
        """Constructs a CertificateRecord instance."""
        self.cert_hash = cert_hash
        self.issuer = issuer
        self.subject = subject
        self.scan_count = scan_count
        self.malicious_count = malicious_count

    def __repr__(self) -> str:
        return f"<CertificateRecord hash={self.cert_hash} issuer={self.issuer}>"
