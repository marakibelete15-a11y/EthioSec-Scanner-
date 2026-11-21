"""jsonb columns

Revision ID: 005_jsonb_columns
Revises: 004_check_constraints
Create Date: 2026-11-20 20:03:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '005_jsonb_columns'
down_revision: Union[str, None] = '004_check_constraints'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE scans ALTER COLUMN checks TYPE JSONB USING checks::jsonb")
        op.execute("ALTER TABLE scans ALTER COLUMN modules TYPE JSONB USING modules::jsonb")
        op.execute("ALTER TABLE scans ALTER COLUMN auth_context_1 TYPE JSONB USING auth_context_1::jsonb")
        op.execute("ALTER TABLE scans ALTER COLUMN auth_context_2 TYPE JSONB USING auth_context_2::jsonb")
        op.execute("ALTER TABLE findings ALTER COLUMN remediation TYPE JSONB USING remediation::jsonb")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE scans ALTER COLUMN checks TYPE JSON USING checks::json")
        op.execute("ALTER TABLE scans ALTER COLUMN modules TYPE JSON USING modules::json")
        op.execute("ALTER TABLE scans ALTER COLUMN auth_context_1 TYPE JSON USING auth_context_1::json")
        op.execute("ALTER TABLE scans ALTER COLUMN auth_context_2 TYPE JSON USING auth_context_2::json")
        op.execute("ALTER TABLE findings ALTER COLUMN remediation TYPE JSON USING remediation::json")
