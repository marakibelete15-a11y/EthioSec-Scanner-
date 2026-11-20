from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, Text, JSON, Index, UniqueConstraint, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
import uuid
import datetime
from database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    full_name = Column(String, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)
    website = Column(String, nullable=True)
    
    # Email verification (default True for direct DB entities; register endpoint explicitly sets False)
    is_verified = Column(Boolean, default=True, nullable=False)
    verification_code_hash = Column(String, nullable=True)
    verification_expires_at = Column(String, nullable=True)
    verification_attempts = Column(Integer, default=0, nullable=False)
    verification_sent_at = Column(String, nullable=True)

    # Password reset
    reset_token_hash = Column(String, nullable=True)
    reset_expires_at = Column(String, nullable=True)
    reset_attempts = Column(Integer, default=0, nullable=False)

    # Session & Account Lockout
    session_revoked_at = Column(String, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(String, nullable=True)

    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "role IN ('user', 'User', 'admin', 'Administrator', 'Security Administrator', 'Security Analyst')",
            name="chk_users_role"
        ),
    )

class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    url = Column(String, nullable=False)
    authorized = Column(Boolean, default=False, nullable=False)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(), nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "url", name="uq_scan_targets_user_id_url"),
        Index("idx_scan_targets_user_id", "user_id"),
    )

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    target_url = Column(String, nullable=False)
    depth = Column(String, default="standard", nullable=False)
    status = Column(String, default="queued", nullable=False, index=True) # queued, running, completed, failed
    progress = Column(Integer, default=0, nullable=False)
    stage = Column(String, default="Queued", nullable=False)
    checks = Column(JSON().with_variant(JSONB, "postgresql"), default=dict)
    modules = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    security_score = Column(Integer, nullable=True)
    
    # Optional Auth Contexts (JSON, typically {"headers": {"Authorization": "Bearer..."}})
    auth_context_1 = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    auth_context_2 = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(), nullable=False)
    finished_at = Column(String, nullable=True)
    
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_user_created", "user_id", "created_at"),
        Index("idx_scans_status", "status"),
        CheckConstraint("depth IN ('quick', 'standard', 'deep')", name="chk_scans_depth"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="chk_scans_status"
        ),
        CheckConstraint("progress >= 0 AND progress <= 100", name="chk_scans_progress"),
    )

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_id = Column(String, ForeignKey("scan_targets.id", ondelete="SET NULL"), nullable=True)
    type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True) # critical, high, medium, low, info
    confidence = Column(String, default="HIGH")
    status = Column(String, default="NOT_DETECTED") # HIGH, MEDIUM, LOW, NOT_DETECTED, SCANNER_ERROR
    url = Column(String, nullable=True)
    parameter = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    http_method = Column(String, nullable=True)
    request = Column(Text, nullable=True)
    response_summary = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(JSON().with_variant(JSONB, "postgresql"), default=list) # JSON list of strings
    owasp = Column(String, nullable=True)
    cwe = Column(String, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(), nullable=False)

    scan = relationship("Scan", back_populates="findings")
    target = relationship("ScanTarget")

    __table_args__ = (
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_type", "type"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="chk_findings_severity"
        ),
        CheckConstraint(
            "status IN ('HIGH', 'MEDIUM', 'LOW', 'NOT_DETECTED', 'SCANNER_ERROR', 'INCONCLUSIVE', 'CONFIRMED', 'ERROR', 'DETECTED', 'open', 'resolved', 'false_positive')",
            name="chk_findings_status"
        ),
    )

class UserSettings(Base):
    __tablename__ = "user_settings"
    
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    default_scan_depth = Column(String, default="standard", nullable=False)
    notif_scan_completed = Column(Boolean, default=True, nullable=False)
    notif_scan_failed = Column(Boolean, default=True, nullable=False)
    notif_security_findings = Column(Boolean, default=True, nullable=False)
    updated_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(), nullable=False)

    __table_args__ = (
        CheckConstraint("default_scan_depth IN ('quick', 'standard', 'deep')", name="chk_user_settings_depth"),
    )
