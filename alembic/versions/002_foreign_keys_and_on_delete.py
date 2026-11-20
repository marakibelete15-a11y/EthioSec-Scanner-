"""foreign keys and on delete rules

Revision ID: 002_foreign_keys_and_on_delete
Revises: 001_initial_schema
Create Date: 2026-11-20 19:59:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_foreign_keys_and_on_delete'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Drop existing foreign keys
    op.drop_constraint('findings_target_id_fkey', 'findings', type_='foreignkey')
    op.drop_constraint('findings_scan_id_fkey', 'findings', type_='foreignkey')
    op.drop_constraint('user_settings_user_id_fkey', 'user_settings', type_='foreignkey')
    op.drop_constraint('scans_user_id_fkey', 'scans', type_='foreignkey')
    op.drop_constraint('scan_targets_user_id_fkey', 'scan_targets', type_='foreignkey')

    # 2. Re-create foreign keys with ON DELETE rules
    op.create_foreign_key(
        'scan_targets_user_id_fkey',
        'scan_targets', 'users',
        ['user_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_foreign_key(
        'scans_user_id_fkey',
        'scans', 'users',
        ['user_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_foreign_key(
        'user_settings_user_id_fkey',
        'user_settings', 'users',
        ['user_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_foreign_key(
        'findings_scan_id_fkey',
        'findings', 'scans',
        ['scan_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_foreign_key(
        'findings_target_id_fkey',
        'findings', 'scan_targets',
        ['target_id'], ['id'],
        ondelete='SET NULL'
    )

    # 3. NOT NULL constraints on essential fields
    op.alter_column('users', 'role', nullable=False, server_default='user')
    op.alter_column('scan_targets', 'authorized', nullable=False, server_default=sa.text('false'))
    op.alter_column('scans', 'depth', nullable=False, server_default='standard')
    op.alter_column('scans', 'status', nullable=False, server_default='queued')
    op.alter_column('scans', 'progress', nullable=False, server_default='0')
    op.alter_column('scans', 'stage', nullable=False, server_default='Queued')
    op.alter_column('user_settings', 'default_scan_depth', nullable=False, server_default='standard')
    op.alter_column('user_settings', 'notif_scan_completed', nullable=False, server_default=sa.text('true'))
    op.alter_column('user_settings', 'notif_scan_failed', nullable=False, server_default=sa.text('true'))
    op.alter_column('user_settings', 'notif_security_findings', nullable=False, server_default=sa.text('true'))


def downgrade() -> None:
    # 1. Revert NOT NULL constraints
    op.alter_column('user_settings', 'notif_security_findings', nullable=True, server_default=sa.text('true'))
    op.alter_column('user_settings', 'notif_scan_failed', nullable=True, server_default=sa.text('true'))
    op.alter_column('user_settings', 'notif_scan_completed', nullable=True, server_default=sa.text('true'))
    op.alter_column('user_settings', 'default_scan_depth', nullable=True, server_default='standard')
    op.alter_column('scans', 'stage', nullable=True, server_default='Queued')
    op.alter_column('scans', 'progress', nullable=True, server_default='0')
    op.alter_column('scans', 'status', nullable=True, server_default='queued')
    op.alter_column('scans', 'depth', nullable=True, server_default='standard')
    op.alter_column('scan_targets', 'authorized', nullable=True, server_default=sa.text('false'))
    op.alter_column('users', 'role', nullable=True)

    # 2. Drop cascade foreign keys
    op.drop_constraint('findings_target_id_fkey', 'findings', type_='foreignkey')
    op.drop_constraint('findings_scan_id_fkey', 'findings', type_='foreignkey')
    op.drop_constraint('user_settings_user_id_fkey', 'user_settings', type_='foreignkey')
    op.drop_constraint('scans_user_id_fkey', 'scans', type_='foreignkey')
    op.drop_constraint('scan_targets_user_id_fkey', 'scan_targets', type_='foreignkey')

    # 3. Restore plain foreign keys
    op.create_foreign_key(
        'scan_targets_user_id_fkey',
        'scan_targets', 'users',
        ['user_id'], ['id']
    )
    op.create_foreign_key(
        'scans_user_id_fkey',
        'scans', 'users',
        ['user_id'], ['id']
    )
    op.create_foreign_key(
        'user_settings_user_id_fkey',
        'user_settings', 'users',
        ['user_id'], ['id']
    )
    op.create_foreign_key(
        'findings_scan_id_fkey',
        'findings', 'scans',
        ['scan_id'], ['id']
    )
    op.create_foreign_key(
        'findings_target_id_fkey',
        'findings', 'scan_targets',
        ['target_id'], ['id']
    )
