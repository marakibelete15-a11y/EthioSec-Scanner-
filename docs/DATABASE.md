# EthioSec Scanner - Database Architecture & Guide

EthioSec Scanner utilizes **PostgreSQL** as its primary production-grade relational database engine, managed via **SQLAlchemy 2.0+** ORM and **Alembic** migration tracking.

---

## 1. Entity Relationship (ER) Diagram

```mermaid
erDiagram
    users ||--o{ scan_targets : "owns (CASCADE)"
    users ||--o{ scans : "launches (CASCADE)"
    users ||--|| user_settings : "configures (CASCADE)"
    scans ||--o{ findings : "contains (CASCADE)"
    scan_targets ||--o{ findings : "references (SET NULL)"

    users {
        varchar(36) id PK "UUID string"
        varchar(255) email UK "Unique login email"
        varchar full_name "User display name"
        varchar password_hash "Argon2id password hash"
        varchar role "Role (admin, user, analyst)"
        varchar website "Optional website URL"
        boolean is_verified "Email verification flag"
        varchar verification_code_hash "Argon2 hash of 6-digit OTP"
        varchar verification_expires_at "ISO-8601 expiry timestamp"
        integer verification_attempts "Failed OTP verification attempts"
        varchar verification_sent_at "ISO-8601 OTP dispatched timestamp"
        varchar reset_token_hash "Argon2 hash of reset token"
        varchar reset_expires_at "ISO-8601 reset expiry timestamp"
        integer reset_attempts "Failed reset verification attempts"
        varchar session_revoked_at "ISO-8601 session invalidation timestamp"
        integer failed_login_attempts "Consecutive failed login count"
        varchar locked_until "ISO-8601 account lockout timestamp"
        varchar created_at "ISO-8601 registration timestamp"
    }

    scan_targets {
        varchar(36) id PK "UUID string"
        varchar user_id FK "References users.id (CASCADE)"
        varchar url "Target domain or URL"
        boolean authorized "Ownership/authorization verification flag"
        varchar created_at "ISO-8601 creation timestamp"
    }

    scans {
        varchar(36) id PK "UUID string"
        varchar user_id FK "References users.id (CASCADE)"
        varchar target_url "Scanned URL endpoint"
        varchar depth "Scan depth (quick, standard, deep)"
        varchar status "Status (queued, running, completed, failed, cancelled)"
        integer progress "Percentage completed (0-100)"
        varchar stage "Current execution pipeline stage"
        jsonb checks "Structured dictionary of executed vulnerability checks"
        jsonb modules "Selected scanning modules"
        integer security_score "Computed target security score (0-100)"
        jsonb auth_context_1 "Primary authenticated testing session headers"
        jsonb auth_context_2 "Secondary authenticated testing session headers"
        varchar created_at "ISO-8601 scan creation timestamp"
        varchar finished_at "ISO-8601 scan completion timestamp"
    }

    findings {
        varchar(36) id PK "UUID string"
        varchar scan_id FK "References scans.id (CASCADE)"
        varchar target_id FK "References scan_targets.id (SET NULL)"
        varchar type "Vulnerability classification identifier"
        varchar severity "Severity level (critical, high, medium, low, info)"
        varchar confidence "Detection confidence rating"
        varchar status "Verification status"
        varchar url "Specific vulnerable URL endpoint"
        varchar parameter "Vulnerable parameter name"
        varchar title "Vulnerability title"
        text description "Detailed vulnerability description"
        text evidence "Technical proof-of-concept evidence"
        varchar http_method "HTTP method (GET, POST, etc.)"
        text request "Recorded HTTP request payload"
        text response_summary "Recorded HTTP response summary"
        text impact "Potential business / security impact"
        jsonb remediation "Ordered list of remediation actions"
        varchar owasp "OWASP Top 10 category mapping"
        varchar cwe "Common Weakness Enumeration ID"
        text ai_explanation "AI contextual analysis and remediation explanation"
        varchar created_at "ISO-8601 finding discovery timestamp"
    }

    user_settings {
        varchar user_id PK, FK "References users.id (CASCADE)"
        varchar default_scan_depth "Default scan depth (quick, standard, deep)"
        boolean notif_scan_completed "Notify on scan completed"
        boolean notif_scan_failed "Notify on scan failed"
        boolean notif_security_findings "Notify on security findings discovered"
        varchar updated_at "ISO-8601 last update timestamp"
    }
```

---

## 2. Table Catalog & Schema Improvements

### `users`
Stores user authentication credentials, role assignments, multi-factor email verification tokens, and lockout counters.
- **Primary Key**: `id` (`VARCHAR`, string UUID).
- **Unique**: `email` (case-insensitive normalized index).
- **Foreign Keys**: None.
- **Constraints**:
  - `chk_users_role`: `CHECK (role IN ('user', 'User', 'admin', 'Administrator', 'Security Administrator', 'Security Analyst'))`.
- **Key Columns**:
  - `password_hash`: OWASP-compliant Argon2id password hash (`$argon2id$...`).
  - `is_verified`: Default `FALSE` for registered users, unblocks scan endpoints upon OTP confirmation.
  - `failed_login_attempts` & `locked_until`: Brute-force protection counter and temporary lockout window.

### `scan_targets`
Represents target web applications registered by users.
- **Primary Key**: `id` (`VARCHAR`, string UUID).
- **Foreign Key**: `user_id` $\to$ `users.id` with `ON DELETE CASCADE`.
- **Constraints & Indexes**:
  - `uq_scan_targets_user_id_url`: `UNIQUE (user_id, url)` prevents duplicate target registrations by the same user.
  - `idx_scan_targets_user_id`: Index on `user_id` for fast user-specific target lookups.

### `scans`
Maintains security scan job execution states, progress, and configuration metadata.
- **Primary Key**: `id` (`VARCHAR`, string UUID).
- **Foreign Key**: `user_id` $\to$ `users.id` with `ON DELETE CASCADE`.
- **JSONB Columns**:
  - `checks`: Structured check details (e.g. status, elapsed time, finding counts).
  - `modules`: List of enabled scanning modules.
  - `auth_context_1`, `auth_context_2`: Header configurations for multi-user authorization matrix scans.
- **Constraints & Indexes**:
  - `idx_scans_user_created`: Composite index `(user_id, created_at)` for fast historical timeline pagination.
  - `idx_scans_status`: Index on `status` for queue filtering and dashboard aggregations.
  - `chk_scans_depth`: `CHECK (depth IN ('quick', 'standard', 'deep'))`.
  - `chk_scans_status`: `CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'))`.
  - `chk_scans_progress`: `CHECK (progress >= 0 AND progress <= 100)`.

### `findings`
Stores discovered vulnerabilities, proofs-of-concept, and actionable guidance.
- **Primary Key**: `id` (`VARCHAR`, string UUID).
- **Foreign Keys**:
  - `scan_id` $\to$ `scans.id` with `ON DELETE CASCADE` (deleting a scan cleans up all findings).
  - `target_id` $\to$ `scan_targets.id` with `ON DELETE SET NULL` (deleting target preserves historical scan finding records).
- **JSONB Columns**:
  - `remediation`: JSONB array of step-by-step remediation instructions.
- **Constraints & Indexes**:
  - `idx_findings_scan_id`: Index on `scan_id` for scan result retrieval.
  - `idx_findings_severity`: Index on `severity` for vulnerability severity breakdown metrics.
  - `idx_findings_type`: Index on `type` for check categorization.
  - `chk_findings_severity`: `CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))`.
  - `chk_findings_status`: `CHECK (status IN ('HIGH', 'MEDIUM', 'LOW', 'NOT_DETECTED', 'SCANNER_ERROR', 'INCONCLUSIVE', 'CONFIRMED', 'ERROR', 'DETECTED', 'open', 'resolved', 'false_positive'))`.

### `user_settings`
User-specific scanner preferences and notification toggles.
- **Primary Key / Foreign Key**: `user_id` $\to$ `users.id` with `ON DELETE CASCADE`.
- **Constraints**:
  - `chk_user_settings_depth`: `CHECK (default_scan_depth IN ('quick', 'standard', 'deep'))`.

---

## 3. PostgreSQL Setup Guide (Fedora / Linux)

### Prerequisites Installation
On Fedora:
```bash
sudo dnf install -y postgresql-server postgresql-contrib
```
On Ubuntu/Debian:
```bash
sudo apt-get install -y postgresql postgresql-contrib
```

### Initialize and Start PostgreSQL Service
On Fedora (first-time initialization):
```bash
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

### Run Provisioning Helper Script
EthioSec Scanner provides an automated helper script to configure the role and database:
```bash
bash db/setup_postgres.sh
```
This script ensures:
- Role `ethiosec_user` is created with password `ethiosecpass`.
- Database `ethiosec_db` is created and owned by `ethiosec_user`.
- Public schema permissions are properly granted.
- Connectivity is validated.

### Environment Variable Configuration
Configure your `backend/.env` file:
```dotenv
ENVIRONMENT=development
DATABASE_URL=postgresql+psycopg2://ethiosec_user:ethiosecpass@localhost:5432/ethiosec_db
```

---

## 4. Alembic Migration Management

Database schema changes are managed strictly via Alembic.

### Apply All Migrations
Run from repository root:
```bash
alembic upgrade head
```

### Check Migration Status
```bash
alembic current
alembic history --verbose
```

### Roll Back Migrations
Roll back the latest migration:
```bash
alembic downgrade -1
```
Roll back all migrations to clean slate:
```bash
alembic downgrade base
```

### Create a New Migration
```bash
alembic revision -m "description_of_change"
```
