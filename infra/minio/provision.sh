#!/bin/sh
# Idempotently provisions MinIO buckets, policies and per-service users with `mc`.
# Runs as the one-shot `minio-init` container after MinIO is healthy.
#
# Buckets
#   cve-poc-quarantine   every downloaded artifact lands here first (CLAUDE.md §7)
#   cve-poc-artifacts    artifacts released after inspection
#   cve-reports          generated reports
#
# Users (access key = service name)
#   download-service     owns artifact storage: quarantine and released artifacts
#                        (the only writer of either bucket)
#   poc-service          read released artifacts only (it stores metadata, never files)
#   reporting-service    read/write reports only
set -eu

fail() {
  echo "minio-provision: $*" >&2
  exit 1
}

require() {
  eval "value=\${$1:-}"
  [ -n "$value" ] || fail "$1 is required"
  [ "${#value}" -ge 16 ] || fail "$1 must be at least 16 characters"
}

for variable in MINIO_ROOT_USER MINIO_ROOT_PASSWORD DOWNLOAD_SERVICE_MINIO_SECRET_KEY \
  POC_SERVICE_MINIO_SECRET_KEY REPORTING_SERVICE_MINIO_SECRET_KEY; do
  [ "$variable" = MINIO_ROOT_USER ] && { [ -n "${MINIO_ROOT_USER:-}" ] || fail "MINIO_ROOT_USER is required"; continue; }
  require "$variable"
done

export MC_CONFIG_DIR=/tmp/mc
mc alias set platform "${MINIO_ENDPOINT:-http://minio:9000}" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null

for bucket in cve-poc-quarantine cve-poc-artifacts cve-reports; do
  mc mb --ignore-existing "platform/$bucket"
  # Keep every version of an object so overwrites and deletions are recoverable.
  mc version enable "platform/$bucket"
  # No anonymous access, ever.
  mc anonymous set none "platform/$bucket"
done

policy_dir=/tmp/policies
mkdir -p "$policy_dir"

cat > "$policy_dir/download-service.json" <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::cve-poc-quarantine", "arn:aws:s3:::cve-poc-artifacts"]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": ["arn:aws:s3:::cve-poc-quarantine/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      "Resource": ["arn:aws:s3:::cve-poc-artifacts/*"]
    }
  ]
}
JSON

cat > "$policy_dir/poc-service.json" <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation"],
      "Resource": ["arn:aws:s3:::cve-poc-artifacts"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::cve-poc-artifacts/*"]
    }
  ]
}
JSON

cat > "$policy_dir/reporting-service.json" <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::cve-reports"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      "Resource": ["arn:aws:s3:::cve-reports/*"]
    }
  ]
}
JSON

provision_user() {
  service="$1"
  secret="$2"
  policy="cve-$service"
  # `mc admin policy create` replaces an existing policy with the same name.
  mc admin policy create platform "$policy" "$policy_dir/$service.json" >/dev/null
  # Re-adding a user updates its secret, so rotating a password in .env takes effect.
  mc admin user add platform "$service" "$secret" >/dev/null
  mc admin policy attach platform "$policy" --user "$service" >/dev/null 2>&1 || true
  # Confirm the attachment instead of trusting the exit code above (it fails when already attached).
  info="$(mc admin user info platform "$service" --json)"
  case "$info" in
    *"\"$policy\""*) ;;
    *) fail "policy $policy is not attached to $service" ;;
  esac
  echo "minio-provision: user $service has policy $policy"
}

provision_user download-service "$DOWNLOAD_SERVICE_MINIO_SECRET_KEY"
provision_user poc-service "$POC_SERVICE_MINIO_SECRET_KEY"
provision_user reporting-service "$REPORTING_SERVICE_MINIO_SECRET_KEY"

echo "minio-provision: done"
