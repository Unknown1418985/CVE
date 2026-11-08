#!/bin/sh
# Shared helpers for backup.sh, verify.sh and restore.sh. POSIX sh; sourced, never executed.
#
# The scripts run on the Docker host from the repository root (they call `docker compose`, so
# COMPOSE_FILE / COMPOSE_PROJECT_NAME from the environment are honoured). Secrets never leave
# the containers: database dumps run inside the postgres container with its own credentials and
# object storage is copied by a short-lived container on the internal data network.

log() {
  printf '%s backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

# Reads KEY from the environment, falling back to .env (only simple KEY=value lines are read and
# nothing is evaluated, so .env content can never execute).
config_value() {
  key="$1"
  default="${2:-}"
  eval "current=\${$key:-}"
  if [ -n "$current" ]; then
    printf '%s' "$current"
    return
  fi
  env_file="${ENV_FILE:-.env}"
  if [ -f "$env_file" ]; then
    line=$(grep -E "^${key}=" "$env_file" | tail -n 1 || true)
    if [ -n "$line" ]; then
      printf '%s' "${line#*=}"
      return
    fi
  fi
  printf '%s' "$default"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

# Databases that belong to the platform (one per service plus Keycloak).
PLATFORM_DATABASES="identity_service cve_service intelligence_service asset_service poc_service \
download_service exploit_service reporting_service notification_service keycloak"

# Buckets in MinIO (OBJECT_STORAGE_BUCKETS in @cve/contracts).
PLATFORM_BUCKETS="cve-poc-quarantine cve-poc-artifacts cve-reports"

compose() {
  docker compose "$@"
}

# Runs a command in the postgres container as the superuser (credentials stay in the container).
pg_exec() {
  compose exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec "$@"' sh "$@"
}

# Database names are fixed identifiers; refuse anything else before it reaches SQL.
assert_identifier() {
  case "$1" in
    *[!a-z0-9_]* | '') die "invalid identifier: $1" ;;
  esac
}

# Encryption: age with one or more recipients. Prints the encrypt command for a pipeline.
encrypt_stream() {
  if [ "$ENCRYPT" = "true" ]; then
    # shellcheck disable=SC2086 # recipient flags are intentionally split
    age $AGE_RECIPIENT_FLAGS
  else
    cat
  fi
}

decrypt_stream() {
  file="$1"
  case "$file" in
    *.age)
      identity=$(config_value BACKUP_AGE_IDENTITY_FILE)
      [ -n "$identity" ] || die "BACKUP_AGE_IDENTITY_FILE is required to read encrypted backups"
      [ -r "$identity" ] || die "cannot read BACKUP_AGE_IDENTITY_FILE ($identity)"
      age --decrypt --identity "$identity" "$file"
      ;;
    *) cat "$file" ;;
  esac
}

# Resolves a backup set argument (a directory, or "latest") to a path.
resolve_set() {
  set_arg="${1:-}"
  [ -n "$set_arg" ] || die "usage: $0 <backup-set-directory|latest>"
  if [ "$set_arg" = "latest" ]; then
    base=$(config_value BACKUP_DIR ./backups)
    [ -f "$base/LATEST" ] || die "no LATEST marker in $base"
    set_arg="$base/$(cat "$base/LATEST")"
  fi
  [ -d "$set_arg" ] || die "backup set not found: $set_arg"
  [ -f "$set_arg/SHA256SUMS" ] || die "$set_arg is incomplete (no SHA256SUMS)"
  printf '%s' "$set_arg"
}
