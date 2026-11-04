#!/bin/sh
# Creates one database and one least-privilege login role per service.
# Runs once, on first initialisation of the PostgreSQL data volume.
set -eu

create_owned_database() {
  name="$1"
  password="$2"
  if [ -z "$password" ]; then
    echo "Missing password for database role $name" >&2
    exit 1
  fi
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v name="$name" -v password="$password" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', :'name', :'password') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'name', :'name') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'name') \gexec
SQL
  # Only the owner may create objects in the public schema of its database.
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$name" \
    -c 'REVOKE CREATE ON SCHEMA public FROM PUBLIC'
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$name" -v name="$name" <<'SQL'
SELECT format('ALTER SCHEMA public OWNER TO %I', :'name') \gexec
SQL
}

create_owned_database identity_service "${IDENTITY_SERVICE_DB_PASSWORD:-}"
create_owned_database cve_service "${CVE_SERVICE_DB_PASSWORD:-}"
create_owned_database intelligence_service "${INTELLIGENCE_SERVICE_DB_PASSWORD:-}"
create_owned_database asset_service "${ASSET_SERVICE_DB_PASSWORD:-}"
create_owned_database poc_service "${POC_SERVICE_DB_PASSWORD:-}"
create_owned_database download_service "${DOWNLOAD_SERVICE_DB_PASSWORD:-}"
create_owned_database exploit_service "${EXPLOIT_SERVICE_DB_PASSWORD:-}"
create_owned_database reporting_service "${REPORTING_SERVICE_DB_PASSWORD:-}"
create_owned_database notification_service "${NOTIFICATION_SERVICE_DB_PASSWORD:-}"
create_owned_database keycloak "${KEYCLOAK_DB_PASSWORD:-}"

# Read-only monitoring role for postgres-exporter (built-in pg_monitor role, no data access).
if [ -z "${POSTGRES_EXPORTER_PASSWORD:-}" ]; then
  echo "Missing password for database role postgres_exporter" >&2
  exit 1
fi
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v password="$POSTGRES_EXPORTER_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE postgres_exporter LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 5', :'password') \gexec
GRANT pg_monitor TO postgres_exporter;
-- Service roles may not open sessions on the maintenance databases.
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE postgres TO postgres_exporter;
SQL
