#!/usr/bin/env bash
# ==============================================================================
# EthioSec Scanner - PostgreSQL Provisioning Helper Script
# Creates the ethiosec_user role and ethiosec_db database with appropriate
# permissions and verifies connectivity.
# ==============================================================================
set -euo pipefail

DB_NAME="${DB_NAME:-ethiosec_db}"
DB_USER="${DB_USER:-ethiosec_user}"
DB_PASSWORD="${DB_PASSWORD:-ethiosecpass}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
ADMIN_USER="${ADMIN_USER:-postgres}"

echo "=================================================="
echo " EthioSec Scanner - PostgreSQL Setup"
echo " Target Database: ${DB_NAME}"
echo " Target User:     ${DB_USER}"
echo " Host:            ${DB_HOST}:${DB_PORT}"
echo "=================================================="

# Function to execute administrative SQL commands
run_admin_sql() {
    local sql="$1"
    if [[ -n "${PG_ADMIN_URL:-}" ]]; then
        psql "$PG_ADMIN_URL" -v ON_ERROR_STOP=1 -c "$sql"
    elif [[ -n "${ADMIN_PASSWORD:-}" ]]; then
        PGPASSWORD="${ADMIN_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$ADMIN_USER" -d postgres -v ON_ERROR_STOP=1 -c "$sql"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo -u postgres psql -p "$DB_PORT" -d postgres -v ON_ERROR_STOP=1 -c "$sql"
    else
        # Try local socket with current OS user (e.g. maraki or local admin)
        psql -h /tmp -p "$DB_PORT" -U "$(whoami)" -d postgres -v ON_ERROR_STOP=1 -c "$sql" 2>/dev/null || \
        PGPASSWORD="${DB_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "$sql" 2>/dev/null || \
        psql -h /tmp -p "$DB_PORT" -U "$ADMIN_USER" -d postgres -v ON_ERROR_STOP=1 -c "$sql"
    fi
}

echo "[1/4] Ensuring role '${DB_USER}' exists and has configured password..."
# Try updating role password if user already exists, or creating if admin privileges available
if PGPASSWORD="${DB_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "\q" 2>/dev/null; then
    echo "Role '${DB_USER}' is already able to authenticate with password."
else
    run_admin_sql "
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
            CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';
        ELSE
            ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';
        END IF;
    END
    \$\$;
    " || {
        echo "Attempting password update directly as '${DB_USER}'..."
        PGPASSWORD="EthioSec123!" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" 2>/dev/null || true
    }
fi

echo "[2/4] Ensuring database '${DB_NAME}' exists..."
run_admin_sql "
SELECT format('CREATE DATABASE %I OWNER %I', '${DB_NAME}', '${DB_USER}')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')
\gexec
" || {
    echo "Database creation query executed or already exists."
}

echo "[3/4] Granting privileges on '${DB_NAME}' to '${DB_USER}'..."
run_admin_sql "
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
" 2>/dev/null || true

# Grant schema privileges in target database
PGPASSWORD="${DB_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -c "GRANT ALL ON SCHEMA public TO ${DB_USER};" 2>/dev/null || true

echo "[4/4] Verifying connection as '${DB_USER}'..."
PGPASSWORD="${DB_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 'Connection successful: ' || current_user || '@' || current_database();"

echo "=================================================="
echo " Setup complete! Database '${DB_NAME}' is ready."
echo " Set DATABASE_URL in your backend/.env:"
echo " DATABASE_URL=postgresql+psycopg2://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "=================================================="
