import { boundedLabel, counter } from '@cve/metrics';

/**
 * Rejected requests by reason: the authentication failure reason (`missing-token`,
 * `expired-token`, `invalid-token`, …), `forbidden` for authorization denials and
 * `idp-unavailable` when signing keys or introspection could not be reached. Feeds the security
 * dashboard and the authentication-failure alert.
 */
export const authRejections = () =>
  counter({
    name: 'auth_requests_rejected_total',
    help: 'Requests rejected by authentication or authorization, by reason',
    labelNames: ['reason'] as const,
  });

export function recordAuthRejection(reason: string): void {
  authRejections().inc({ reason: boundedLabel(reason) });
}
