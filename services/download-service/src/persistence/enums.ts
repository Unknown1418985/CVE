import type { ArtifactScanStatus, ArtifactVerificationStatus, ScanVerdict } from '@cve/contracts';

import type {
  ArtifactScanStatus as DbScanStatus,
  ScanVerdict as DbScanVerdict,
  VerificationStatus as DbVerificationStatus,
} from '../generated/prisma/client.js';

// Prisma enum keys cannot contain `-`; the API and events use the hyphenated labels.

export const SCAN_STATUS_TO_DB = {
  pending: 'pending',
  scanning: 'scanning',
  clean: 'clean',
  suspicious: 'suspicious',
  malicious: 'malicious',
  incomplete: 'incomplete',
  'integrity-failure': 'integrity_failure',
} as const satisfies Record<ArtifactScanStatus, DbScanStatus>;

export const SCAN_STATUS_TO_API: Readonly<Record<DbScanStatus, ArtifactScanStatus>> = {
  pending: 'pending',
  scanning: 'scanning',
  clean: 'clean',
  suspicious: 'suspicious',
  malicious: 'malicious',
  incomplete: 'incomplete',
  integrity_failure: 'integrity-failure',
};

export const VERIFICATION_TO_DB = {
  unverified: 'unverified',
  'in-review': 'in_review',
  verified: 'verified',
  rejected: 'rejected',
  malicious: 'malicious',
} as const satisfies Record<ArtifactVerificationStatus, DbVerificationStatus>;

export const VERIFICATION_TO_API: Readonly<Record<DbVerificationStatus, ArtifactVerificationStatus>> =
  {
    unverified: 'unverified',
    in_review: 'in-review',
    verified: 'verified',
    rejected: 'rejected',
    malicious: 'malicious',
  };

export const VERDICT_TO_DB = {
  clean: 'clean',
  suspicious: 'suspicious',
  malicious: 'malicious',
  error: 'error',
  'not-configured': 'not_configured',
} as const satisfies Record<ScanVerdict, DbScanVerdict>;

export const VERDICT_TO_API: Readonly<Record<DbScanVerdict, ScanVerdict>> = {
  clean: 'clean',
  suspicious: 'suspicious',
  malicious: 'malicious',
  error: 'error',
  not_configured: 'not-configured',
};
