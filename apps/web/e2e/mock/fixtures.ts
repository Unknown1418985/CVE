/**
 * Synthetic test data for the end-to-end suite. CVE IDs use the reserved-looking 9xxxx range of
 * a future year so they cannot be mistaken for real vulnerabilities, and every record is checked
 * against the shared contracts when the mock server starts.
 */
import {
  ROLE_PERMISSIONS,
  type CveRecord,
  type CveSummary,
  type DownloadArtifactDetail,
  type LifecycleEvent,
  type Role,
  type ScanResult,
  type UserProfile,
} from '@cve/contracts';

export interface MockUser {
  readonly key: 'admin' | 'viewer';
  readonly profile: UserProfile;
}

function profile(id: string, username: string, role: Role, displayName: string): UserProfile {
  return {
    id,
    username,
    email: `${username}@example.test`,
    emailVerified: true,
    firstName: displayName.split(' ')[0] ?? null,
    lastName: displayName.split(' ')[1] ?? null,
    displayName,
    jobTitle: null,
    timezone: 'UTC',
    roles: [role],
    permissions: [...ROLE_PERMISSIONS[role]],
    firstSeenAt: '2026-01-05T09:00:00.000Z',
    lastSeenAt: '2026-11-01T09:00:00.000Z',
  };
}

export const USERS: Readonly<Record<MockUser['key'], MockUser>> = {
  admin: {
    key: 'admin',
    profile: profile(
      '6f1c1c3e-0000-4000-8000-000000000001',
      'e2e-admin',
      'super-admin',
      'Avery Admin',
    ),
  },
  viewer: {
    key: 'viewer',
    profile: profile('6f1c1c3e-0000-4000-8000-000000000002', 'e2e-viewer', 'viewer', 'Vic Viewer'),
  },
};

const SEVERITY_CYCLE = ['critical', 'high', 'medium', 'low', 'high', 'medium'] as const;
const SCORE: Readonly<Record<(typeof SEVERITY_CYCLE)[number], number>> = {
  critical: 9.8,
  high: 8.1,
  medium: 5.4,
  low: 3.1,
};

function uuid(prefix: string, index: number): string {
  return `${prefix}-0000-4000-8000-${String(index).padStart(12, '0')}`;
}

/** 30 CVEs, newest first: CVE-2026-90030 … CVE-2026-90001. */
export const CVES: readonly CveSummary[] = Array.from({ length: 30 }, (_, offset) => {
  const index = 30 - offset;
  const severity = SEVERITY_CYCLE[index % SEVERITY_CYCLE.length] ?? 'medium';
  const day = String(1 + (index % 28)).padStart(2, '0');
  return {
    id: uuid('c0e00000', index),
    cveId: `CVE-2026-${String(90_000 + index)}`,
    state: 'published',
    title: `Synthetic ${severity} test vulnerability ${index}`,
    description: `End-to-end test record ${index}. Not a real vulnerability.`,
    severity,
    cvssScore: SCORE[severity],
    cvssVersion: '3.1',
    inKev: index % 10 === 0,
    epssScore: index / 100,
    epssPercentile: Math.min(0.99, index / 31),
    cweIds: ['CWE-79'],
    publishedAt: `2026-${index > 15 ? '10' : '09'}-${day}T12:00:00.000Z`,
    lastModifiedAt: `2026-10-${day}T12:00:00.000Z`,
    updatedAt: '2026-11-01T00:00:00.000Z',
  } satisfies CveSummary;
});

export function cveRecord(summary: CveSummary): CveRecord {
  return {
    id: summary.id,
    cveId: summary.cveId,
    state: summary.state,
    title: summary.title,
    description: summary.description,
    assigner: 'e2e-cna',
    publishedAt: summary.publishedAt,
    lastModifiedAt: summary.lastModifiedAt,
    source: 'nvd',
    severity: summary.severity,
    cvssScore: summary.cvssScore,
    cvssVersion: summary.cvssVersion,
    kev: summary.inKev
      ? {
          dateAdded: '2026-10-20',
          dueDate: '2026-11-10',
          vulnerabilityName: `${summary.cveId} synthetic KEV entry`,
          requiredAction: 'Apply the vendor update.',
          knownRansomwareCampaignUse: 'unknown',
          notes: null,
          source: 'cisa-kev',
          observedAt: '2026-10-20T00:00:00.000Z',
        }
      : null,
    epss:
      summary.epssScore === null || summary.epssPercentile === null
        ? null
        : {
            score: summary.epssScore,
            percentile: summary.epssPercentile,
            scoreDate: '2026-11-01',
            modelVersion: 'v2025.03.14',
            source: 'first-epss',
            observedAt: '2026-11-01T00:00:00.000Z',
          },
    cvssMetrics:
      summary.cvssScore === null
        ? []
        : [
            {
              id: uuid('c0551000', Number(summary.cveId.slice(-2))),
              version: '3.1',
              source: 'nvd@nist.gov',
              type: 'primary',
              vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              baseScore: summary.cvssScore,
              baseSeverity:
                summary.severity === 'none' || summary.severity === 'unknown'
                  ? 'low'
                  : summary.severity,
              metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
              observedAt: '2026-10-01T00:00:00.000Z',
              supersededAt: null,
            },
          ],
    weaknesses: [{ cweId: 'CWE-79', source: 'nvd' }],
    references: [
      { url: 'https://example.test/advisory', source: 'nvd', tags: ['Vendor Advisory'] },
    ],
    affectedProducts: [],
    version: 3,
    createdAt: '2026-09-01T00:00:00.000Z',
    updatedAt: summary.updatedAt,
  };
}

const SHA = (fill: string) => fill.repeat(64).slice(0, 64);

function artifact(
  index: number,
  overrides: Pick<
    DownloadArtifactDetail,
    'lifecycleStatus' | 'scanStatus' | 'verificationStatus' | 'releasable'
  > & { sha: string },
): DownloadArtifactDetail {
  const { sha, ...status } = overrides;
  const id = uuid('a7f00000', index);
  const requestId = uuid('d0e00000', index);
  const scan: ScanResult = {
    id: uuid('5ca00000', index),
    scanner: 'clamav',
    verdict: status.scanStatus === 'malicious' ? 'malicious' : 'clean',
    findings:
      status.scanStatus === 'malicious' ? [{ name: 'Eicar-Test-Signature', detail: null }] : [],
    engineVersion: 'ClamAV 1.4.1',
    signatureVersion: '27450',
    error: null,
    scanRunId: uuid('5c400000', index),
    startedAt: '2026-11-01T10:00:00.000Z',
    finishedAt: '2026-11-01T10:00:05.000Z',
  };
  return {
    id,
    sha256: SHA(sha),
    sizeBytes: 20_480 * index,
    mimeType: 'application/gzip',
    detectedType: 'gzip',
    declaredContentType: 'application/x-gzip',
    originalFilename: `poc-${index}.tar.gz`,
    storageBucket: 'cve-artifacts-quarantine',
    storageKey: `sha256/${SHA(sha).slice(0, 2)}/${SHA(sha)}`,
    source: 'github-archive',
    sourceUrl: `https://codeload.github.com/example/poc-${index}/tar.gz/${'0'.repeat(40)}`,
    sourceRepository: `example/poc-${index}`,
    cveIds: [`CVE-2026-${String(90_000 + index)}`],
    riskIndicators: ['archive'],
    pocArtifactIds: [],
    discoveredAt: '2026-10-31T08:00:00.000Z',
    downloadedAt: '2026-11-01T09:59:00.000Z',
    lastScannedAt: '2026-11-01T10:00:05.000Z',
    releasedAt: status.lifecycleStatus === 'released' ? '2026-11-02T10:00:00.000Z' : null,
    version: 1,
    ...status,
    provenance: [
      {
        requestId,
        source: 'github-archive',
        sourceUrl: `https://codeload.github.com/example/poc-${index}/tar.gz/${'0'.repeat(40)}`,
        finalUrl: null,
        sourceRepository: `example/poc-${index}`,
        pocArtifactId: null,
        commitSha: '0'.repeat(40),
        cveIds: [`CVE-2026-${String(90_000 + index)}`],
        discoveredAt: '2026-10-31T08:00:00.000Z',
        downloadedAt: '2026-11-01T09:59:00.000Z',
      },
    ],
    latestScan: [scan],
  };
}

/** A clean quarantined artifact (releasable), a malicious one and a released one. */
export function initialArtifacts(): DownloadArtifactDetail[] {
  return [
    artifact(1, {
      lifecycleStatus: 'quarantined',
      scanStatus: 'clean',
      verificationStatus: 'unverified',
      releasable: true,
      sha: 'a1',
    }),
    artifact(2, {
      lifecycleStatus: 'quarantined',
      scanStatus: 'malicious',
      verificationStatus: 'unverified',
      releasable: false,
      sha: 'b2',
    }),
    artifact(3, {
      lifecycleStatus: 'released',
      scanStatus: 'clean',
      verificationStatus: 'verified',
      releasable: true,
      sha: 'c3',
    }),
  ];
}

export function storedEvent(artifactDetail: DownloadArtifactDetail): LifecycleEvent {
  return {
    id: uuid('e7e00000', Number(artifactDetail.id.slice(-2))),
    fromStatus: null,
    toStatus: 'quarantined',
    reason: 'Stored by the Download Service',
    actorId: 'download-service',
    actorUsername: null,
    createdAt: artifactDetail.downloadedAt,
  };
}
