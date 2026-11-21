"""check constraints

Revision ID: 004_check_constraints
Revises: 003_indexes_and_unique
Create Date: 2026-11-20 20:02:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '004_check_constraints'
down_revision: Union[str, None] = '003_indexes_and_unique'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. User role CHECK constraint
    op.create_check_constraint(
        'chk_users_role',
        'users',
        "role IN ('user', 'User', 'admin', 'Administrator', 'Security Administrator', 'Security Analyst')"
    )

    # 2. Scans depth, status, and progress CHECK constraints
    op.create_check_constraint(
        'chk_scans_depth',
        'scans',
        "depth IN ('quick', 'standard', 'deep')"
    )
    op.create_check_constraint(
        'chk_scans_status',
        'scans',
        "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')"
    )
    op.create_check_constraint(
        'chk_scans_progress',
        'scans',
        "progress >= 0 AND progress <= 100"
    )

    # 3. Findings severity and status CHECK constraints
    op.create_check_constraint(
        'chk_findings_severity',
        'findings',
        "severity IN ('critical', 'high', 'medium', 'low', 'info', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')"
    )
    op.create_check_constraint(
        'chk_findings_status',
        'findings',
        "status IN ('HIGH', 'MEDIUM', 'LOW', 'NOT_DETECTED', 'SCANNER_ERROR', 'INCONCLUSIVE', 'CONFIRMED', 'ERROR', 'DETECTED', 'open', 'resolved', 'false_positive')"
    )

    # 4. UserSettings depth CHECK constraint
    op.create_check_constraint(
        'chk_user_settings_depth',
        'user_settings',
        "default_scan_depth IN ('quick', 'standard', 'deep')"
    )


def downgrade() -> None:
    op.drop_constraint('chk_user_settings_depth', 'user_settings', type_='check')
    op.drop_constraint('chk_findings_status', 'findings', type_='check')
    op.drop_constraint('chk_findings_severity', 'findings', type_='check')
    op.drop_constraint('chk_scans_progress', 'scans', type_='check')
    op.drop_constraint('chk_scans_status', 'scans', type_='check')
    op.drop_constraint('chk_scans_depth', 'scans', type_='check')
    op.drop_constraint('chk_users_role', 'users', type_='check')
