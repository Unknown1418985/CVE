#!/bin/sh
# Creates a consistent, encrypted backup set of the platform's durable state:
#
#   postgres/<database>.dump[.age]   pg_dump custom format, one file per service database + Keycloak
#   minio/objects.tar[.age]          current object versions of every platform bucket
#   rabbitmq/definitions.json[.age]  broker definitions (topology is also re-provisioned on start)
#   config/env[.age]                 the deployment's .env (only ever stored encrypted)
#   backup-info.txt                  what, when, from which commit, encrypted or not
#   SHA256SUMS                       integrity of every file above
#
# Usage (from the repository root, on the Docker host):
#   infra/backup/backup.sh
#
# Configuration (environment or .env): BACKUP_DIR, BACKUP_AGE_RECIPIENTS, BACKUP_RETENTION_DAYS,
# BACKUP_ALLOW_UNENCRYPTED (development only). See docs/disaster-recovery.md.
#
# Not backed up on purpose: Redis (BullMQ queues and caches; services re-create their schedules
# at start), OpenSearch (holds no primary data: no service writes to it yet), Prometheus and
# Grafana data (provisioned from this repository), TLS certificates (re-issued).
set -eu
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=infra/backup/lib.sh
. "$script_dir/lib.sh"

require_command docker
require_command sha256sum
require_command tar

BACKUP_DIR=$(config_value BACKUP_DIR ./backups)
RETENTION_DAYS=$(config_value BACKUP_RETENTION_DAYS 14)
RECIPIENTS=$(config_value BACKUP_AGE_RECIPIENTS)
ALLOW_UNENCRYPTED=$(config_value BACKUP_ALLOW_UNENCRYPTED false)

case "$RETENTION_DAYS" in
  '' | *[!0-9]*) die "BACKUP_RETENTION_DAYS must be a whole number of days" ;;
esac

# Backups hold password hashes, user data, audit logs and quarantined malware samples.
if [ -n "$RECIPIENTS" ]; then
  require_command age
  ENCRYPT=true
  AGE_RECIPIENT_FLAGS=""
  old_ifs=$IFS
  IFS=','
  for recipient in $RECIPIENTS; do
    case "$recipient" in
      age1*) AGE_RECIPIENT_FLAGS="$AGE_RECIPIENT_FLAGS --recipient $recipient" ;;
      *) IFS=$old_ifs; die "BACKUP_AGE_RECIPIENTS must contain age public keys (age1...)" ;;
    esac
  done
  IFS=$old_ifs
elif [ "$ALLOW_UNENCRYPTED" = "true" ]; then
  ENCRYPT=false
  AGE_RECIPIENT_FLAGS=""
  log "WARNING: writing an UNENCRYPTED backup (BACKUP_ALLOW_UNENCRYPTED=true); never do this in production"
else
  die "BACKUP_AGE_RECIPIENTS is not set. Refusing to write unencrypted backups (set BACKUP_ALLOW_UNENCRYPTED=true only for local development)"
fi
suffix=""
[ "$ENCRYPT" = "true" ] && suffix=".age"

compose ps --status running --services 2>/dev/null | grep -qx postgres ||
  die "the postgres container is not running"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"
staging="$BACKUP_DIR/.incomplete-$timestamp"
final="$BACKUP_DIR/$timestamp"
[ -e "$final" ] && die "$final already exists"
mkdir -m 700 "$staging" "$staging/postgres" "$staging/minio" "$staging/rabbitmq" "$staging/config"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    log "backup failed; removing the incomplete set $staging"
    rm -rf "$staging"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ------------------------------------------------------------------ PostgreSQL
# shellcheck disable=SC2016 # expanded inside the container
existing=$(pg_exec sh -c 'psql -U "$POSTGRES_USER" -d postgres -At -c "SELECT datname FROM pg_database WHERE NOT datistemplate"')
databases=""
for database in $PLATFORM_DATABASES; do
  if printf '%s\n' "$existing" | grep -qx "$database"; then
    databases="$databases $database"
  else
    die "database $database does not exist; is this the platform's PostgreSQL?"
  fi
done

for database in $databases; do
  assert_identifier "$database"
  log "dumping database $database"
  out="$staging/postgres/$database.dump$suffix"
  # A failing pg_dump must fail the backup even though it is the first command of a pipeline.
  { pg_exec sh -c 'pg_dump -U "$POSTGRES_USER" --format=custom --compress=6 --no-password "$1"' sh "$database" ||
    echo "pg_dump failed" >"$staging/.failed"; } | encrypt_stream >"$out"
  [ ! -e "$staging/.failed" ] || die "pg_dump of $database failed"
  [ -s "$out" ] || die "empty dump for $database"
done

# ------------------------------------------------------------------ MinIO
log "copying object storage buckets"
uid=$(id -u)
gid=$(id -g)
# minio-init carries the root credentials and the data network; it only reads the buckets here.
# shellcheck disable=SC2016 # expanded inside the container
compose run --rm --no-deps -T --user "$uid:$gid" \
  -v "$(CDPATH='' cd -- "$staging/minio" && pwd):/backup" \
  --entrypoint /bin/sh minio-init -c '
    set -eu
    export MC_CONFIG_DIR=/tmp/mc HOME=/tmp
    mc alias set platform "${MINIO_ENDPOINT:-http://minio:9000}" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
    for bucket in '"$PLATFORM_BUCKETS"'; do
      mkdir -p "/backup/objects/$bucket"
      mc mirror --quiet --preserve "platform/$bucket" "/backup/objects/$bucket" >/dev/null
    done
    mc ls --recursive --json platform >/backup/listing.json
  '
tar -C "$staging/minio" -cf - objects listing.json | encrypt_stream >"$staging/minio/objects.tar$suffix"
rm -rf "$staging/minio/objects" "$staging/minio/listing.json"

# ------------------------------------------------------------------ RabbitMQ
if compose ps --status running --services 2>/dev/null | grep -qx rabbitmq; then
  log "exporting RabbitMQ definitions"
  compose exec -T rabbitmq rabbitmqctl export_definitions - --quiet |
    encrypt_stream >"$staging/rabbitmq/definitions.json$suffix"
else
  log "WARNING: rabbitmq is not running; definitions not exported (they are re-provisioned on start)"
  rmdir "$staging/rabbitmq"
fi

# ------------------------------------------------------------------ configuration
env_file="${ENV_FILE:-.env}"
if [ "$ENCRYPT" = "true" ] && [ -f "$env_file" ]; then
  log "storing the encrypted deployment configuration"
  encrypt_stream <"$env_file" >"$staging/config/env.age"
else
  log "WARNING: .env not included (only stored when encryption is enabled)"
  rmdir "$staging/config"
fi

# ------------------------------------------------------------------ manifest
commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
{
  echo "created_at=$timestamp"
  echo "platform_commit=$commit"
  echo "encrypted=$ENCRYPT"
  echo "databases=$(echo "$databases" | sed 's/^ //')"
  echo "buckets=$PLATFORM_BUCKETS"
  echo "postgres_version=$(pg_exec postgres --version | tr -d '\r')"
  echo "host=$(hostname)"
} >"$staging/backup-info.txt"
(cd "$staging" && find . -type f ! -name SHA256SUMS ! -name '.failed' | sort | xargs sha256sum >SHA256SUMS)

mv "$staging" "$final"
printf '%s\n' "$timestamp" >"$BACKUP_DIR/LATEST.tmp" && mv "$BACKUP_DIR/LATEST.tmp" "$BACKUP_DIR/LATEST"
log "backup set written to $final ($(du -sh "$final" | cut -f1))"

# ------------------------------------------------------------------ retention
if [ "$RETENTION_DAYS" -gt 0 ]; then
  find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '20[0-9][0-9][01][0-9][0-3][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z' \
    -mtime "+$RETENTION_DAYS" | while read -r old; do
    [ "$old" = "$final" ] && continue
    log "removing expired backup set $old"
    rm -rf "$old"
  done
fi
trap - EXIT
