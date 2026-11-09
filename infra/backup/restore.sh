#!/bin/sh
# Restores a backup set into the running data stores. DESTRUCTIVE: the restored databases and
# buckets are replaced by the content of the set.
#
# Usage:
#   infra/backup/restore.sh <backup-set-directory|latest> --yes [--only postgres|minio]
#
# Preconditions (docs/disaster-recovery.md):
# - postgres and minio are running and healthy (`docker compose up -d postgres minio`);
# - the application services are stopped (`docker compose --profile apps stop`), so nothing
#   writes while data is replaced (the script refuses otherwise);
# - .env holds the same Keycloak client secrets as the backed-up deployment (restore
#   config/env.age first when rebuilding a host).
#
# Each database is dropped and re-created with the same least-privilege owner and grants as
# infra/postgres/init, then restored with pg_restore as that owner. Buckets are mirrored back
# with --overwrite and --remove, so objects created after the backup are deleted (MinIO
# versioning keeps their previous versions).
set -eu
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=infra/backup/lib.sh
. "$script_dir/lib.sh"

require_command docker
require_command sha256sum
require_command tar

set_arg="${1:-}"
[ $# -gt 0 ] && shift
confirmed=false
only=all
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) confirmed=true ;;
    --only)
      shift
      only="${1:-}"
      ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done
case "$only" in
  all | postgres | minio) ;;
  *) die "--only must be postgres or minio" ;;
esac
set_dir=$(resolve_set "$set_arg")
[ "$confirmed" = "true" ] || die "restoring replaces live data; re-run with --yes to confirm"

(cd "$set_dir" && sha256sum --quiet --check SHA256SUMS) || die "checksum mismatch in $set_dir"

running=$(compose ps --status running --services 2>/dev/null || true)
for service in api-gateway identity-service cve-service intelligence-service asset-service \
  poc-service download-service exploit-service reporting-service notification-service keycloak web; do
  if printf '%s\n' "$running" | grep -qx "$service"; then
    die "$service is running; stop the application services and Keycloak before restoring"
  fi
done

restore_database() {
  dump="$1"
  database=$(basename "$dump")
  database=${database%.age}
  database=${database%.dump}
  assert_identifier "$database"
  log "restoring database $database"
  # shellcheck disable=SC2016 # expanded inside the container
  pg_exec sh -c '
    set -eu
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -v name="$1" <<SQL
SELECT format('"'"'DROP DATABASE IF EXISTS %I WITH (FORCE)'"'"', :'"'"'name'"'"') \gexec
SELECT format('"'"'CREATE DATABASE %I OWNER %I'"'"', :'"'"'name'"'"', :'"'"'name'"'"') \gexec
SELECT format('"'"'REVOKE ALL ON DATABASE %I FROM PUBLIC'"'"', :'"'"'name'"'"') \gexec
SQL
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1" -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC"
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1" -v name="$1" <<SQL
SELECT format('"'"'ALTER SCHEMA public OWNER TO %I'"'"', :'"'"'name'"'"') \gexec
SQL
  ' sh "$database"
  # Restore as the owning role so every object belongs to the service, exactly like migrations.
  decrypt_stream "$dump" | pg_exec sh -c \
    'pg_restore -U "$POSTGRES_USER" --dbname "$1" --role "$1" --no-owner --no-privileges --exit-on-error' \
    sh "$database"
}

if [ "$only" = all ] || [ "$only" = postgres ]; then
  found=0
  for dump in "$set_dir"/postgres/*.dump "$set_dir"/postgres/*.dump.age; do
    [ -e "$dump" ] || continue
    restore_database "$dump"
    found=$((found + 1))
  done
  [ "$found" -gt 0 ] || die "no database dumps in $set_dir"
  log "restored $found databases"
fi

if [ "$only" = all ] || [ "$only" = minio ]; then
  archive=""
  for candidate in "$set_dir/minio/objects.tar" "$set_dir/minio/objects.tar.age"; do
    [ -e "$candidate" ] && archive="$candidate"
  done
  [ -n "$archive" ] || die "no object archive in $set_dir"
  work=$(mktemp -d "${TMPDIR:-/tmp}/cve-restore.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  decrypt_stream "$archive" | tar -C "$work" -xf -
  log "restoring object storage buckets"
  # shellcheck disable=SC2016 # expanded inside the container
  compose run --rm --no-deps -T --user "$(id -u):$(id -g)" -v "$work:/backup:ro" \
    --entrypoint /bin/sh minio-init -c '
      set -eu
      export MC_CONFIG_DIR=/tmp/mc HOME=/tmp
      mc alias set platform "${MINIO_ENDPOINT:-http://minio:9000}" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
      for bucket in '"$PLATFORM_BUCKETS"'; do
        mc mb --ignore-existing "platform/$bucket" >/dev/null
        mc mirror --quiet --overwrite --remove "/backup/objects/$bucket" "platform/$bucket" >/dev/null
      done
    '
  log "object storage restored"
fi

log "restore of $set_dir finished. Start the stack (docker compose --profile apps up -d) and check /api/v1/health/services"
