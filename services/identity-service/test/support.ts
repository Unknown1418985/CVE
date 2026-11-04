import { randomUUID } from 'node:crypto';

import type { INestApplication } from '@nestjs/common';

import type { AuditEvent, DomainEventEnvelope, ListAuditEventsQuery, Role } from '@cve/contracts';
import { ROLES } from '@cve/contracts';
import { createTokenVerifier } from '@cve/auth';
import { createLogger } from '@cve/logger';
import { configureServiceApp } from '@cve/shared';
import { buildServiceTestEnv, createHttpTestApp, type HttpTestApp } from '@cve/testing';
import type { TestTokenIssuer } from '@cve/testing/auth';

import { AppModule } from '../src/app.module.js';
import { loadServiceEnv } from '../src/config/env.js';
import {
  IdentityProviderError,
  type IdentityProvider,
  type IdpEvent,
  type IdpSession,
  type IdpUser,
  type UserPage,
  type UserUpdate,
} from '../src/keycloak/identity-provider.js';
import type {
  AuditRepository,
  NewAuditEntry,
  ProfilePatch,
  ProfileRepository,
  StoredProfile,
} from '../src/persistence/ports.js';
import { SERVICE_NAME } from '../src/service.js';

export function identityTestEnv(overrides: Record<string, string> = {}) {
  return buildServiceTestEnv(SERVICE_NAME, {
    KEYCLOAK_URL: 'http://keycloak.test/auth',
    KEYCLOAK_PUBLIC_URL: 'http://keycloak.test/auth',
    KEYCLOAK_ADMIN_CLIENT_SECRET: 'test-admin-client-secret',
    ACCOUNT_REDIRECT_URI: 'http://localhost:8080/settings/account',
    OUTBOX_RELAY_ENABLED: 'false',
    KEYCLOAK_EVENTS_SYNC_ENABLED: 'false',
    ...overrides,
  });
}

/** Keycloak's composite roles: the effective roles a direct assignment implies. */
const COMPOSITES: Readonly<Record<Role, readonly Role[]>> = {
  viewer: ['viewer'],
  'vulnerability-researcher': ['vulnerability-researcher', 'viewer'],
  'security-analyst': ['security-analyst', 'viewer'],
  administrator: ['administrator', 'security-analyst', 'vulnerability-researcher', 'viewer'],
  'super-admin': [
    'super-admin',
    'administrator',
    'security-analyst',
    'vulnerability-researcher',
    'viewer',
  ],
};

interface FakeUser {
  user: IdpUser;
  roles: Set<Role>;
  sessions: IdpSession[];
}

/** In-memory stand-in for Keycloak that records every mutating call. */
export class FakeIdentityProvider implements IdentityProvider {
  readonly users = new Map<string, FakeUser>();
  readonly calls: string[] = [];
  events: IdpEvent[] = [];
  unavailable = false;

  addUser(roles: Role[], overrides: Partial<IdpUser> = {}): string {
    const id = overrides.id ?? randomUUID();
    this.users.set(id, {
      user: {
        id,
        username: `user-${id.slice(0, 6)}`,
        email: `${id.slice(0, 6)}@example.com`,
        firstName: null,
        lastName: null,
        enabled: true,
        emailVerified: true,
        createdAt: new Date('2026-01-01T00:00:00Z'),
        requiredActions: [],
        ...overrides,
      },
      roles: new Set(roles),
      sessions: [],
    });
    return id;
  }

  addSession(userId: string, id: string = randomUUID()): string {
    this.require(userId).sessions.push({
      id,
      userId,
      ipAddress: '10.0.0.5',
      startedAt: new Date(Date.now() - 60_000),
      lastAccessAt: new Date(),
      clients: ['cve-web'],
    });
    return id;
  }

  private check(): void {
    if (this.unavailable) throw new IdentityProviderError('Keycloak is unreachable', 503);
  }

  private require(userId: string): FakeUser {
    const entry = this.users.get(userId);
    if (!entry) throw new IdentityProviderError('not found', 404);
    return entry;
  }

  listUsers(query: { search?: string; first: number; max: number }): Promise<UserPage> {
    this.check();
    const all = [...this.users.values()]
      .map((entry) => entry.user)
      .filter((user) => query.search === undefined || user.username.includes(query.search));
    return Promise.resolve({
      users: all.slice(query.first, query.first + query.max),
      total: all.length,
    });
  }

  getUser(userId: string): Promise<IdpUser | null> {
    this.check();
    return Promise.resolve(this.users.get(userId)?.user ?? null);
  }

  updateUser(userId: string, update: UserUpdate): Promise<void> {
    this.check();
    const entry = this.require(userId);
    entry.user = {
      ...entry.user,
      ...(update.firstName === undefined ? {} : { firstName: update.firstName }),
      ...(update.lastName === undefined ? {} : { lastName: update.lastName }),
      ...(update.enabled === undefined ? {} : { enabled: update.enabled }),
      ...(update.requiredActions === undefined ? {} : { requiredActions: update.requiredActions }),
    };
    this.calls.push(`updateUser:${userId}`);
    return Promise.resolve();
  }

  getDirectRoles(userId: string): Promise<Role[]> {
    this.check();
    const roles = this.require(userId).roles;
    return Promise.resolve(ROLES.filter((role) => roles.has(role)));
  }

  getEffectiveRoles(userId: string): Promise<Role[]> {
    this.check();
    const effective = new Set([...this.require(userId).roles].flatMap((role) => COMPOSITES[role]));
    return Promise.resolve(ROLES.filter((role) => effective.has(role)));
  }

  addRoles(userId: string, roles: readonly Role[]): Promise<void> {
    for (const role of roles) this.require(userId).roles.add(role);
    if (roles.length > 0) this.calls.push(`addRoles:${userId}:${roles.join(',')}`);
    return Promise.resolve();
  }

  removeRoles(userId: string, roles: readonly Role[]): Promise<void> {
    for (const role of roles) this.require(userId).roles.delete(role);
    if (roles.length > 0) this.calls.push(`removeRoles:${userId}:${roles.join(',')}`);
    return Promise.resolve();
  }

  listEnabledUsersWithRole(role: Role): Promise<IdpUser[]> {
    return Promise.resolve(
      [...this.users.values()]
        .filter((entry) => entry.user.enabled && entry.roles.has(role))
        .map((entry) => entry.user),
    );
  }

  listSessions(userId: string): Promise<IdpSession[]> {
    this.check();
    return Promise.resolve([...this.require(userId).sessions]);
  }

  deleteSession(sessionId: string): Promise<void> {
    for (const entry of this.users.values()) {
      entry.sessions = entry.sessions.filter((session) => session.id !== sessionId);
    }
    this.calls.push(`deleteSession:${sessionId}`);
    return Promise.resolve();
  }

  logoutUser(userId: string): Promise<void> {
    this.require(userId).sessions = [];
    this.calls.push(`logoutUser:${userId}`);
    return Promise.resolve();
  }

  listEvents(since: Date, limit: number): Promise<IdpEvent[]> {
    return Promise.resolve(this.events.filter((event) => event.time >= since).slice(0, limit));
  }

  ping(): Promise<void> {
    this.check();
    return Promise.resolve();
  }
}

export class InMemoryAuditRepository implements AuditRepository {
  readonly entries: (AuditEvent & { sourceEventId: string | null })[] = [];
  readonly outbox: DomainEventEnvelope[] = [];

  private toEvent(entry: NewAuditEntry): AuditEvent & { sourceEventId: string | null } {
    return {
      id: randomUUID(),
      occurredAt: entry.occurredAt.toISOString(),
      recordedAt: new Date().toISOString(),
      source: entry.source,
      sourceEventId: entry.sourceEventId ?? null,
      action: entry.action,
      outcome: entry.outcome,
      actorType: entry.actorType,
      actorId: entry.actorId ?? null,
      actorUsername: entry.actorUsername ?? null,
      resourceType: entry.resourceType ?? null,
      resourceId: entry.resourceId ?? null,
      ipAddress: entry.ipAddress ?? null,
      userAgent: entry.userAgent ?? null,
      correlationId: entry.correlationId ?? null,
      details: entry.details === undefined ? null : { ...entry.details },
    };
  }

  append(entry: NewAuditEntry, events: readonly DomainEventEnvelope[] = []): Promise<void> {
    this.entries.push(this.toEvent(entry));
    this.outbox.push(...events);
    return Promise.resolve();
  }

  appendMany(entries: readonly NewAuditEntry[]): Promise<number> {
    let inserted = 0;
    for (const entry of entries) {
      const duplicate = this.entries.some(
        (existing) =>
          existing.source === entry.source &&
          entry.sourceEventId !== undefined &&
          existing.sourceEventId === entry.sourceEventId,
      );
      if (!duplicate) {
        this.entries.push(this.toEvent(entry));
        inserted += 1;
      }
    }
    return Promise.resolve(inserted);
  }

  list(query: ListAuditEventsQuery): Promise<{ items: AuditEvent[]; total: number }> {
    const matching = this.entries
      .filter(
        (entry) =>
          (query.action === undefined || entry.action === query.action) &&
          (query.actorId === undefined || entry.actorId === query.actorId) &&
          (query.outcome === undefined || entry.outcome === query.outcome),
      )
      .reverse();
    const start = (query.page - 1) * query.pageSize;
    return Promise.resolve({
      items: matching.slice(start, start + query.pageSize),
      total: matching.length,
    });
  }

  find(id: string): Promise<AuditEvent | null> {
    return Promise.resolve(this.entries.find((entry) => entry.id === id) ?? null);
  }

  actions(): string[] {
    return this.entries.map((entry) => `${entry.action}:${entry.outcome}`);
  }
}

export class InMemoryProfileRepository implements ProfileRepository {
  readonly profiles = new Map<string, StoredProfile>();

  touch(
    user: { id: string; username: string; email: string | null },
    at: Date,
  ): Promise<StoredProfile> {
    const existing = this.profiles.get(user.id);
    const profile: StoredProfile = existing
      ? { ...existing, username: user.username, email: user.email, lastSeenAt: at }
      : {
          keycloakUserId: user.id,
          username: user.username,
          email: user.email,
          displayName: null,
          jobTitle: null,
          timezone: 'UTC',
          firstSeenAt: at,
          lastSeenAt: at,
        };
    this.profiles.set(user.id, profile);
    return Promise.resolve(profile);
  }

  update(userId: string, patch: ProfilePatch): Promise<StoredProfile> {
    const existing = this.profiles.get(userId);
    if (!existing) return Promise.reject(new Error('profile not found'));
    const updated: StoredProfile = {
      ...existing,
      ...(patch.displayName === undefined ? {} : { displayName: patch.displayName }),
      ...(patch.jobTitle === undefined ? {} : { jobTitle: patch.jobTitle }),
      ...(patch.timezone === undefined ? {} : { timezone: patch.timezone }),
    };
    this.profiles.set(userId, updated);
    return Promise.resolve(updated);
  }
}

export interface IdentityTestContext {
  readonly t: HttpTestApp;
  readonly idp: FakeIdentityProvider;
  readonly audit: InMemoryAuditRepository;
  readonly profiles: InMemoryProfileRepository;
}

export async function startIdentityApp(issuer: TestTokenIssuer): Promise<IdentityTestContext> {
  const env = loadServiceEnv(identityTestEnv());
  const logger = createLogger({ service: SERVICE_NAME, level: 'silent' });
  const idp = new FakeIdentityProvider();
  const audit = new InMemoryAuditRepository();
  const profiles = new InMemoryProfileRepository();
  const t = await createHttpTestApp(
    AppModule.register(env, {
      logger,
      verifier: createTokenVerifier({
        issuer: issuer.issuer,
        audience: issuer.audience,
        keys: issuer.getKey,
      }),
      identityProvider: idp,
      auditRepository: audit,
      profileRepository: profiles,
      healthIndicators: [],
    }),
    (app: INestApplication) => {
      configureServiceApp(app, {
        service: SERVICE_NAME,
        version: '0.0.0-test',
        logger,
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    },
  );
  return { t, idp, audit, profiles };
}
