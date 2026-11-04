import type { Logger } from '@cve/logger';

import type { IdentityProvider, IdpEvent } from '../keycloak/identity-provider.js';
import type { AuditRepository, NewAuditEntry, SyncCursorRepository } from '../persistence/ports.js';

export const KEYCLOAK_EVENTS_CURSOR = 'keycloak-events';
const BATCH_LIMIT = 1_000;
/** First run looks back this far; Keycloak keeps events for 30 days (realm setting). */
const INITIAL_LOOKBACK_MS = 24 * 60 * 60 * 1000;

/** `LOGIN_ERROR` → `identity.keycloak-login.failed`-style audit actions. */
export function auditActionForEvent(event: IdpEvent): string {
  if (event.kind === 'admin') {
    const operation = event.type.toLowerCase().replaceAll('_', '-');
    return `identity.keycloak-admin.${operation.replace(/[^a-z-]/g, '') || 'action'}`;
  }
  const base = event.type
    .replace(/_ERROR$/, '')
    .toLowerCase()
    .replaceAll('_', '-');
  return `identity.keycloak-${base.replace(/[^a-z-]/g, '') || 'event'}.${event.type.endsWith('_ERROR') ? 'failed' : 'succeeded'}`;
}

export function toAuditEntry(event: IdpEvent): NewAuditEntry {
  return {
    occurredAt: event.time,
    source: 'keycloak',
    sourceEventId: `${event.kind}:${event.id}`,
    action: auditActionForEvent(event),
    outcome: event.error === null ? 'success' : 'failure',
    actorType: event.userId !== null ? 'user' : event.kind === 'admin' ? 'system' : 'anonymous',
    actorId: event.userId ?? undefined,
    actorUsername: event.details['username'],
    resourceType:
      event.kind === 'admin' ? (event.resourceType?.toLowerCase() ?? undefined) : 'session',
    resourceId:
      event.kind === 'admin' ? (event.resourcePath ?? undefined) : (event.sessionId ?? undefined),
    ipAddress: event.ipAddress ?? undefined,
    details: {
      keycloakType: event.type,
      ...(event.clientId === null ? {} : { clientId: event.clientId }),
      ...(event.error === null ? {} : { error: event.error }),
      // Keycloak details never include credentials; keep only well-known, non-sensitive keys.
      ...pick(event.details, [
        'auth_method',
        'redirect_uri',
        'reason',
        'remember_me',
        'grant_type',
      ]),
    },
  };
}

function pick(source: Readonly<Record<string, string>>, keys: readonly string[]) {
  return Object.fromEntries(keys.filter((key) => key in source).map((key) => [key, source[key]]));
}

/**
 * Incrementally copies Keycloak user and admin events into the audit log. Idempotent: entries are
 * keyed by Keycloak event ID, and the cursor overlaps by one millisecond.
 */
export class KeycloakEventsSync {
  constructor(
    private readonly idp: IdentityProvider,
    private readonly audit: AuditRepository,
    private readonly cursors: SyncCursorRepository,
    private readonly logger: Logger,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async run(): Promise<{ fetched: number; inserted: number }> {
    const cursor =
      (await this.cursors.get(KEYCLOAK_EVENTS_CURSOR)) ??
      new Date(this.now().getTime() - INITIAL_LOOKBACK_MS);
    const events = await this.idp.listEvents(cursor, BATCH_LIMIT);
    const inserted = await this.audit.appendMany(events.map(toAuditEntry));
    const newest = events.at(-1);
    if (newest) await this.cursors.set(KEYCLOAK_EVENTS_CURSOR, newest.time);
    this.logger.info(
      { fetched: events.length, inserted, cursor: (newest?.time ?? cursor).toISOString() },
      'keycloak events synchronised',
    );
    return { fetched: events.length, inserted };
  }
}
