#!/bin/sh
# Generates the Redis ACL file from environment variables, then starts Redis.
#
# Users:
#   default          disabled
#   admin            full access, for operators only (REDIS_ADMIN_PASSWORD)
#   metrics          read-only server introspection for redis_exporter (REDIS_EXPORTER_PASSWORD)
#   <service>        one user per backend service, restricted to keys and channels under
#                    `cve:<service>:*` and without dangerous/admin commands
#                    (<SERVICE>_REDIS_PASSWORD, e.g. CVE_SERVICE_REDIS_PASSWORD)
#
# Passwords are stored as SHA-256 hashes in a tmpfs-backed file that is never written to the
# data volume.
set -eu

ACL_FILE="${REDIS_ACL_FILE:-/run/redis/users.acl}"
SERVICES="identity-service cve-service intelligence-service asset-service poc-service download-service exploit-service reporting-service notification-service"

fail() {
  echo "redis-entrypoint: $*" >&2
  exit 1
}

hash_password() {
  printf '%s' "$1" | sha256sum | cut -d ' ' -f 1
}

password_for() {
  variable="$1"
  eval "value=\${$variable:-}"
  [ -n "$value" ] || fail "$variable is required"
  [ "${#value}" -ge 16 ] || fail "$variable must be at least 16 characters"
  printf '%s' "$value"
}

umask 077
tmp_file="$ACL_FILE.tmp"
{
  echo "user default off resetkeys resetchannels -@all"
  echo "user admin on #$(hash_password "$(password_for REDIS_ADMIN_PASSWORD)") ~* &* +@all"
  echo "user metrics on #$(hash_password "$(password_for REDIS_EXPORTER_PASSWORD)") resetkeys resetchannels -@all +ping +info +select +client|setname +client|info +config|get +slowlog|get +slowlog|len +latency|latest +cluster|info +memory|stats +dbsize"
  for service in $SERVICES; do
    variable="$(printf '%s' "$service" | tr 'a-z-' 'A-Z_')_REDIS_PASSWORD"
    echo "user $service on #$(hash_password "$(password_for "$variable")") resetkeys ~cve:$service:* resetchannels &cve:$service:* +@all -@dangerous -@admin +info +client|setname +client|getname +client|id"
  done
} > "$tmp_file"
mv "$tmp_file" "$ACL_FILE"

exec redis-server /usr/local/etc/redis/redis.conf --aclfile "$ACL_FILE" "$@"
