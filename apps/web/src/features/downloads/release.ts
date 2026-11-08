import { canTransitionLifecycle, type DownloadArtifact } from '@cve/contracts';

import { humanize } from '@/lib/format';

/** Why release is not offered, mirroring the Download Service's own checks. */
export function releaseBlocker(
  artifact: Pick<
    DownloadArtifact,
    'lifecycleStatus' | 'scanStatus' | 'verificationStatus' | 'releasable'
  >,
): string | null {
  if (!canTransitionLifecycle(artifact.lifecycleStatus, 'released')) return null;
  if (artifact.scanStatus !== 'clean')
    return `Release requires a clean scan (current: ${humanize(artifact.scanStatus).toLowerCase()}).`;
  if (artifact.verificationStatus === 'malicious' || artifact.verificationStatus === 'rejected') {
    return `A linked PoC artifact is marked ${artifact.verificationStatus}.`;
  }
  if (!artifact.releasable) return 'The Download Service reports this artifact as not releasable.';
  return null;
}
