/**
 * Object storage buckets (MinIO). Buckets, policies and per-service users are provisioned by
 * `infra/minio/provision.sh`; access is granted per service as documented there.
 */
export const OBJECT_STORAGE_BUCKETS = {
  /** Every downloaded PoC artifact lands here first; never exposed to ordinary users. */
  pocQuarantine: 'cve-poc-quarantine',
  /** Artifacts released after inspection and scanning. */
  pocArtifacts: 'cve-poc-artifacts',
  /** Generated reports. */
  reports: 'cve-reports',
} as const;

export type ObjectStorageBucket =
  (typeof OBJECT_STORAGE_BUCKETS)[keyof typeof OBJECT_STORAGE_BUCKETS];
