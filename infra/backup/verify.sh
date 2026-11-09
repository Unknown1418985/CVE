#!/bin/sh
# Verifies a backup set without touching the running platform's data:
#   1. every file matches SHA256SUMS;
#   2. every database dump decrypts and is a readable pg_dump archive (pg_restore --list);
#   3. the object archive decrypts and is a readable tar file;
#   4. the encrypted configuration decrypts.
#
# Usage: infra/backup/verify.sh <backup-set-directory|latest>
# Encrypted sets need BACKUP_AGE_IDENTITY_FILE (the age private key, kept off the platform host).
# Exit status 0 means the set is restorable as far as can be checked offline. Run it after every
# backup (cron) and alert on a non-zero exit.
set -eu
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=infra/backup/lib.sh
. "$script_dir/lib.sh"

require_command docker
require_command sha256sum
require_command tar

set_dir=$(resolve_set "${1:-}")
log "verifying $set_dir"

(cd "$set_dir" && sha256sum --quiet --check SHA256SUMS) || die "checksum mismatch in $set_dir"
log "checksums ok"

if grep -q '\.age' "$set_dir/SHA256SUMS"; then
  require_command age
fi

count=0
for dump in "$set_dir"/postgres/*.dump "$set_dir"/postgres/*.dump.age; do
  [ -e "$dump" ] || continue
  # pg_restore reads the archive from stdin; --list parses the whole table of contents.
  entries=$(decrypt_stream "$dump" | compose exec -T postgres pg_restore --list | grep -c '^[0-9]' || true)
  [ "$entries" -gt 0 ] || die "$(basename "$dump") is not a readable pg_dump archive"
  log "$(basename "$dump"): $entries archive entries"
  count=$((count + 1))
done
expected=$(echo "$PLATFORM_DATABASES" | wc -w)
[ "$count" -eq "$expected" ] || die "expected $expected database dumps, found $count"

for archive in "$set_dir"/minio/objects.tar "$set_dir"/minio/objects.tar.age; do
  [ -e "$archive" ] || continue
  objects=$(decrypt_stream "$archive" | tar -tf - | grep -c '^objects/.*[^/]$' || true)
  log "$(basename "$archive"): $objects objects"
done

if [ -e "$set_dir/config/env.age" ]; then
  decrypt_stream "$set_dir/config/env.age" | grep -q '^POSTGRES_SUPERUSER_PASSWORD=' ||
    die "config/env.age does not contain a platform .env"
  log "config/env.age decrypts"
fi

log "backup set $set_dir verified"
