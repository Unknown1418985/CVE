import {
  canTransitionVerification,
  type ArtifactVerificationStatus,
  type Permission,
} from '@cve/contracts';

export type TransitionCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: 'same-status' | 'not-allowed' | 'forbidden' };

/**
 * Whether a principal may move an artifact from `from` to `to`. Every transition needs
 * `poc:manage`; leaving `malicious` also needs `quarantine:manage`, because it re-exposes
 * content that was judged harmful.
 */
export function checkVerificationTransition(
  from: ArtifactVerificationStatus,
  to: ArtifactVerificationStatus,
  permissions: readonly Permission[],
): TransitionCheck {
  if (from === to) return { ok: false, reason: 'same-status' };
  if (!canTransitionVerification(from, to)) return { ok: false, reason: 'not-allowed' };
  if (!permissions.includes('poc:manage')) return { ok: false, reason: 'forbidden' };
  if (from === 'malicious' && !permissions.includes('quarantine:manage')) {
    return { ok: false, reason: 'forbidden' };
  }
  return { ok: true };
}
