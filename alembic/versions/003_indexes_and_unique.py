"""indexes and unique constraints

Revision ID: 003_indexes_and_unique
Revises: 002_foreign_keys_and_on_delete
Create Date: 2026-11-20 20:01:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_indexes_and_unique'
down_revision: Union[str, None] = '002_foreign_keys_and_on_delete'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Indexes on scans
    op.create_index('idx_scans_user_created', 'scans', ['user_id', 'created_at'], unique=False)
    op.create_index('idx_scans_status', 'scans', ['status'], unique=False)

    # 2. Indexes on findings
    op.create_index('idx_findings_scan_id', 'findings', ['scan_id'], unique=False)
    op.create_index('idx_findings_severity', 'findings', ['severity'], unique=False)
    op.create_index('idx_findings_type', 'findings', ['type'], unique=False)

    # 3. Index on scan_targets
    op.create_index('idx_scan_targets_user_id', 'scan_targets', ['user_id'], unique=False)


def downgrade() -> None:
    # 1. Drop index on scan_targets
    op.drop_index('idx_scan_targets_user_id', table_name='scan_targets')

    # 2. Drop indexes on findings
    op.drop_index('idx_findings_type', table_name='findings')
    op.drop_index('idx_findings_severity', table_name='findings')
    op.drop_index('idx_findings_scan_id', table_name='findings')

    # 3. Drop indexes on scans
    op.drop_index('idx_scans_status', table_name='scans')
    op.drop_index('idx_scans_user_created', table_name='scans')
