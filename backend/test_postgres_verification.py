import os
import uuid
import pytest
from sqlalchemy import text, inspect
from sqlalchemy.exc import IntegrityError
from fastapi.testclient import TestClient

from database import engine, SessionLocal, DATABASE_URL
from models import User, ScanTarget, Scan, Finding, UserSettings, Base
from main import app
from email_service import email_service
from rate_limiter import _limiter

pytestmark = pytest.mark.skipif(
    not DATABASE_URL.startswith("postgresql"),
    reason="PostgreSQL verification tests require a postgresql DATABASE_URL"
)

@pytest.fixture(autouse=True)
def reset_rate_limits():
    _limiter.clear()
    yield
    _limiter.clear()

def test_postgresql_engine_configuration():
    assert engine.dialect.name == "postgresql"
    assert engine.pool.size() == 10
    assert engine.pool._max_overflow == 20
    assert engine.pool._pre_ping is True

def test_postgresql_tables_exist():
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    expected_tables = ["users", "scan_targets", "scans", "findings", "user_settings", "alembic_version"]
    for table in expected_tables:
        assert table in table_names, f"Expected table '{table}' in PostgreSQL database"

def test_postgresql_foreign_keys_and_cascade():
    inspector = inspect(engine)
    # Check scan_targets FK to users (CASCADE)
    fks_targets = inspector.get_foreign_keys("scan_targets")
    user_fk = next((fk for fk in fks_targets if fk["referred_table"] == "users"), None)
    assert user_fk is not None
    assert user_fk.get("options", {}).get("ondelete", "").upper() == "CASCADE"

    # Check scans FK to users (CASCADE)
    fks_scans = inspector.get_foreign_keys("scans")
    target_fk = next((fk for fk in fks_scans if fk["referred_table"] == "users"), None)
    assert target_fk is not None
    assert target_fk.get("options", {}).get("ondelete", "").upper() == "CASCADE"

    # Check findings FK to scans (CASCADE) and scan_targets (SET NULL)
    fks_findings = inspector.get_foreign_keys("findings")
    scan_fk = next((fk for fk in fks_findings if fk["referred_table"] == "scans"), None)
    assert scan_fk is not None
    assert scan_fk.get("options", {}).get("ondelete", "").upper() == "CASCADE"
    tgt_fk = next((fk for fk in fks_findings if fk["referred_table"] == "scan_targets"), None)
    assert tgt_fk is not None
    assert tgt_fk.get("options", {}).get("ondelete", "").upper() == "SET NULL"

def test_postgresql_indexes():
    inspector = inspect(engine)
    scan_indexes = [idx["name"] for idx in inspector.get_indexes("scans")]
    assert "idx_scans_user_created" in scan_indexes
    assert "idx_scans_status" in scan_indexes

    finding_indexes = [idx["name"] for idx in inspector.get_indexes("findings")]
    assert "idx_findings_scan_id" in finding_indexes
    assert "idx_findings_severity" in finding_indexes
    assert "idx_findings_type" in finding_indexes

def test_postgresql_check_constraints():
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT conname FROM pg_constraint 
            WHERE conname IN ('chk_scans_status', 'chk_findings_severity', 'chk_scans_depth')
        """)).fetchall()
        connames = {row[0] for row in result}
        assert "chk_scans_status" in connames
        assert "chk_findings_severity" in connames
        assert "chk_scans_depth" in connames

def test_postgresql_check_constraint_enforcement():
    db = SessionLocal()
    unique_id = uuid.uuid4().hex[:8]
    user = User(
        id=f"usr_test_{unique_id}",
        email=f"constraint_{unique_id}@test.com",
        password_hash="dummy_hash",
        full_name="Constraint Tester",
        is_verified=True
    )
    db.add(user)
    db.commit()

    invalid_scan = Scan(
        id=f"scan_{unique_id}",
        user_id=user.id,
        target_url="https://constraint-check.local",
        status="INVALID_STATUS_SHOULD_FAIL"
    )
    db.add(invalid_scan)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()

    # Clean up user
    db.delete(user)
    db.commit()
    db.close()

def test_postgresql_jsonb_columns():
    db = SessionLocal()
    unique_id = uuid.uuid4().hex[:8]
    user = User(
        id=f"usr_jsonb_{unique_id}",
        email=f"jsonb_{unique_id}@test.com",
        password_hash="dummy_hash",
        full_name="JSONB Tester",
        is_verified=True
    )
    db.add(user)
    db.commit()

    scan = Scan(
        id=f"scan_jsonb_{unique_id}",
        user_id=user.id,
        target_url="https://jsonb-check.local",
        status="completed",
        checks={"ssl": {"valid": True}, "headers": {"hsts": True}},
        modules={"sqli": True, "xss": True}
    )
    db.add(scan)
    db.commit()

    finding = Finding(
        id=f"find_jsonb_{unique_id}",
        scan_id=scan.id,
        type="sqli",
        title="Test Finding",
        description="Detailed test description",
        severity="medium",
        confidence="HIGH",
        status="DETECTED",
        remediation=["Restrict admin access", "Implement parameterized queries"]
    )
    db.add(finding)
    db.commit()

    # Query back and verify dict/list structures
    db_scan = db.query(Scan).filter(Scan.id == scan.id).first()
    assert isinstance(db_scan.checks, dict)
    assert db_scan.checks["ssl"]["valid"] is True
    assert db_scan.modules["sqli"] is True

    db_finding = db.query(Finding).filter(Finding.id == finding.id).first()
    assert isinstance(db_finding.remediation, list)
    assert "Implement parameterized queries" in db_finding.remediation

    # Clean up
    db.delete(user)
    db.commit()
    db.close()

def test_api_workflow_on_postgresql():
    client = TestClient(app)
    unique_id = uuid.uuid4().hex[:8]
    test_email = f"pg_api_{unique_id}@ethiosec.test"
    test_password = "SecurePassword123!"

    # 1. Register
    reg_resp = client.post("/api/auth/register", json={
        "email": test_email,
        "password": test_password,
        "full_name": "Postgres API Tester"
    })
    assert reg_resp.status_code == 200

    # 2. Verify Email
    code = email_service.get_last_sent_code(test_email)
    assert code is not None
    ver_resp = client.post("/api/auth/verify-email", json={
        "email": test_email,
        "code": code
    })
    assert ver_resp.status_code == 200

    # 3. Login
    login_resp = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_password
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    user_id = login_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    # 4. Create Scan Target
    tgt_resp = client.post("/api/targets", json={
        "url": f"https://target-{unique_id}.local"
    }, headers=headers)
    assert tgt_resp.status_code == 200
    target_id = tgt_resp.json()["id"]

    # 5. Create Scan
    scan_resp = client.post("/api/scans", json={
        "target_id": target_id,
        "depth": "quick",
        "authorized": True
    }, headers=headers)
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    # 6. Verify directly in PostgreSQL DB
    with engine.connect() as conn:
        u_row = conn.execute(text("SELECT email, is_verified FROM users WHERE id = :uid"), {"uid": user_id}).fetchone()
        assert u_row is not None
        assert u_row[0] == test_email.lower()
        assert u_row[1] is True

        t_row = conn.execute(text("SELECT url FROM scan_targets WHERE id = :tid"), {"tid": target_id}).fetchone()
        assert t_row is not None
        assert t_row[0] == f"https://target-{unique_id}.local"

        s_row = conn.execute(text("SELECT status FROM scans WHERE id = :sid"), {"sid": scan_id}).fetchone()
        assert s_row is not None

    # 7. Test Cascade Delete: deleting user deletes target and scan
    db = SessionLocal()
    user_obj = db.query(User).filter(User.id == user_id).first()
    db.delete(user_obj)
    db.commit()
    db.close()

    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM users WHERE id = :uid"), {"uid": user_id}).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM scan_targets WHERE id = :tid"), {"tid": target_id}).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM scans WHERE id = :sid"), {"sid": scan_id}).scalar() == 0
