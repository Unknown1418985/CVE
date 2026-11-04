import { describe, expect, it } from 'vitest';

import { createLogger } from '@cve/logger';

import {
  auditActionForEvent,
  KEYCLOAK_EVENTS_CURSOR,
  KeycloakEventsSync,
  toAuditEntry,
} from '../src/audit/keycloak-events.sync.js';
import type { IdpEvent } from '../src/keycloak/identity-provider.js';
import type { SyncCursorRepository } from '../src/persistence/ports.js';
import { FakeIdentityProvider, InMemoryAuditRepository } from './support.js';

const event = (overrides: Partial<IdpEvent>): IdpEvent => ({
  kind: 'user',
  id: 'event-1',
  time: new Date('2026-11-04T08:00:00Z'),
  type: 'LOGIN',
  userId: '6f1c3d2a-0000-4000-8000-000000000001',
  sessionId: 'session-1',
  clientId: 'cve-web',
  ipAddress: '10.0.0.1',
  error: null,
  resourceType: null,
  resourcePath: null,
  details: { username: 'ada', auth_method: 'openid-connect', code_id: 'secret-ish' },
  ...overrides,
});

class MemoryCursors implements SyncCursorRepository {
  readonly values = new Map<string, Date>();
  get(name: string) {
    return Promise.resolve(this.values.get(name) ?? null);
  }
  set(name: string, position: Date) {
    this.values.set(name, position);
    return Promise.resolve();
  }
}

describe('Keycloak event mapping', () => {
  it('derives audit actions in the platform grammar', () => {
    expect(auditActionForEvent(event({}))).toBe('identity.keycloak-login.succeeded');
    expect(auditActionForEvent(event({ type: 'LOGIN_ERROR' }))).toBe(
      'identity.keycloak-login.failed',
    );
    expect(auditActionForEvent(event({ type: 'UPDATE_PASSWORD' }))).toBe(
      'identity.keycloak-update-password.succeeded',
    );
    expect(auditActionForEvent(event({ kind: 'admin', type: 'UPDATE' }))).toBe(
      'identity.keycloak-admin.update',
    );
  });

  it('maps failures and keeps only non-sensitive details', () => {
    const entry = toAuditEntry(
      event({ type: 'LOGIN_ERROR', error: 'invalid_user_credentials', userId: null }),
    );
    expect(entry).toMatchObject({
      source: 'keycloak',
      sourceEventId: 'user:event-1',
      outcome: 'failure',
      actorType: 'anonymous',
      actorUsername: 'ada',
      resourceType: 'session',
    });
    expect(entry.details).toEqual({
      keycloakType: 'LOGIN_ERROR',
      clientId: 'cve-web',
      error: 'invalid_user_credentials',
      auth_method: 'openid-connect',
    });
  });
});

describe('KeycloakEventsSync', () => {
  it('ingests new events once and advances the cursor', async () => {
    const idp = new FakeIdentityProvider();
    const audit = new InMemoryAuditRepository();
    const cursors = new MemoryCursors();
    const logger = createLogger({ service: 'test', level: 'silent' });
    const now = () => new Date('2026-11-04T09:00:00Z');
    idp.events = [
      event({ id: 'a', time: new Date('2026-11-04T08:00:00Z') }),
      event({ id: 'b', time: new Date('2026-11-04T08:30:00Z'), type: 'LOGOUT' }),
    ];
    const sync = new KeycloakEventsSync(idp, audit, cursors, logger, now);

    expect(await sync.run()).toEqual({ fetched: 2, inserted: 2 });
    expect(cursors.values.get(KEYCLOAK_EVENTS_CURSOR)?.toISOString()).toBe(
      '2026-11-04T08:30:00.000Z',
    );
    // The cursor is inclusive, so the newest event is seen again but not stored twice.
    expect(await sync.run()).toEqual({ fetched: 1, inserted: 0 });
    expect(audit.entries.map((e) => e.action)).toEqual([
      'identity.keycloak-login.succeeded',
      'identity.keycloak-logout.succeeded',
    ]);
  });

  it('starts one day back on the first run', async () => {
    const idp = new FakeIdentityProvider();
    idp.events = [event({ id: 'old', time: new Date('2026-11-01T00:00:00Z') })];
    const sync = new KeycloakEventsSync(
      idp,
      new InMemoryAuditRepository(),
      new MemoryCursors(),
      createLogger({ service: 'test', level: 'silent' }),
      () => new Date('2026-11-04T09:00:00Z'),
    );
    expect(await sync.run()).toEqual({ fetched: 0, inserted: 0 });
  });
});
