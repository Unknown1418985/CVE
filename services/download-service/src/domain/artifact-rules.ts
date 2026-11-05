import type {
  ArtifactLifecycleStatus,
  ArtifactScanner,
  ArtifactScanStatus,
  ArtifactVerificationStatus,
  ScanVerdict,
} from '@cve/contracts';
import { canTransitionLifecycle } from '@cve/contracts';

export interface ScannerOutcome {
  readonly scanner: ArtifactScanner;
  readonly verdict: ScanVerdict;
}

/**
 * Combines scanner verdicts. A positive finding always wins (malicious before suspicious).
 * Otherwise the artifact is `clean` only when every required scanner ran and found nothing: a
 * missing, unconfigured or failing scanner makes the result `incomplete`, never `clean`.
 */
export function aggregateScanStatus(
  outcomes: readonly ScannerOutcome[],
  required: readonly ArtifactScanner[],
): ArtifactScanStatus {
  if (outcomes.some((outcome) => outcome.verdict === 'malicious')) return 'malicious';
  if (outcomes.some((outcome) => outcome.verdict === 'suspicious')) return 'suspicious';
  if (required.length === 0) return 'incomplete';
  const cleanRequired = required.every((scanner) =>
    outcomes.some((outcome) => outcome.scanner === scanner && outcome.verdict === 'clean'),
  );
  return cleanRequired ? 'clean' : 'incomplete';
}

const VERIFICATION_SEVERITY: Readonly<Record<ArtifactVerificationStatus, number>> = {
  malicious: 4,
  rejected: 3,
  'in-review': 2,
  unverified: 1,
  verified: 0,
};

/**
 * One stored artifact can come from several PoC artifacts (identical content). The most severe
 * judgement wins; it is `verified` only when every linked PoC artifact was verified.
 */
export function combineVerification(
  statuses: readonly ArtifactVerificationStatus[],
): ArtifactVerificationStatus {
  if (statuses.length === 0) return 'unverified';
  return statuses.reduce((worst, status) =>
    VERIFICATION_SEVERITY[status] > VERIFICATION_SEVERITY[worst] ? status : worst,
  );
}

export interface ReleaseState {
  readonly lifecycleStatus: ArtifactLifecycleStatus;
  readonly scanStatus: ArtifactScanStatus;
  readonly verificationStatus: ArtifactVerificationStatus;
}

/** Why an artifact cannot be released, or null when it can. */
export function releaseBlocker(state: ReleaseState): string | null {
  if (state.scanStatus !== 'clean') {
    return `the scan status is ${state.scanStatus}; only artifacts whose scan is clean can be released`;
  }
  if (state.verificationStatus === 'malicious' || state.verificationStatus === 'rejected') {
    return `a linked PoC artifact is ${state.verificationStatus}`;
  }
  return null;
}

export function isReleasable(state: ReleaseState): boolean {
  return state.lifecycleStatus === 'quarantined' && releaseBlocker(state) === null;
}

/** Checks a requested lifecycle change; returns the refusal message or null. */
export function checkLifecycleChange(
  state: ReleaseState,
  to: ArtifactLifecycleStatus,
): string | null {
  if (!canTransitionLifecycle(state.lifecycleStatus, to)) {
    return `cannot change the lifecycle from ${state.lifecycleStatus} to ${to}`;
  }
  return to === 'released' ? releaseBlocker(state) : null;
}

/**
 * A released artifact goes back to quarantine when a rescan finds something or analysts judge
 * a linked PoC artifact malicious or rejected.
 */
export function mustRevokeRelease(state: ReleaseState): boolean {
  return state.lifecycleStatus === 'released' && releaseBlocker(state) !== null;
}
