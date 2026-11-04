import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createDomainEvent } from '@cve/messaging';

import { PrismaOutboxStore } from '../../src/outbox/prisma-outbox.store.js';
import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { PrismaAuditRepository } from '../../src/persistence/prisma-audit.repository.js';
import { PrismaProfileRepository } from '../../src/persistence/prisma-profile.repository.js';
import { PrismaSyncCursorRepository } from '../../src/persistence/prisma-sync-cursor.repository.js';
import { identityDatabaseUrl, migrate } from './support.js';

let prisma: PrismaClient;

beforeAll(async () => {
  const url = identityDatabaseUrl();
  migrate(url);
  prisma = createPrismaClient(url);
  await prisma.$connect();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('migrations', () => {
  it('are applied and idempotent', async () => {
    migrate(identityDatabaseUrl());
    const rows = await prisma.$queryRaw<{ migration_name: string }[]>`
      SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL`;
    expect(rows.map((row) => row.migration_name)).toContain('20261104000000_init');
  });
});

describe('audit log', () => {
  it('writes the entry and its outbox events in one transaction', async () => {
    const repository = new PrismaAuditRepository(prisma);
    const resourceId = randomUUID();
    const event = createDomainEvent({
      eventType: 'identity.user.roles-changed',
      producer: 'identity-service',
      payload: { userId: resourceId },
    });
    await repository.append(
      {
        occurredAt: new Date(),
        source: 'identity-service',
        action: 'identity.user.roles-changed',
        outcome: 'success',
        actorType: 'user',
        actorId: randomUUID(),
        resourceType: 'user',
        resourceId,
        details: { roles: ['viewer'] },
      },
      [event],
    );
    const { items, total } = await repository.list({ page: 1, pageSize: 10, resourceId });
    expect(total).toBe(1);
    expect(items[0]).toMatchObject({
      action: 'identity.user.roles-changed',
      details: { roles: ['viewer'] },
    });
    expect(await repository.find(items[0]!.id)).toMatchObject({ resourceId });
    const outbox = await prisma.outboxEvent.findUnique({ where: { eventId: event.eventId } });
    expect(outbox?.publishedAt).toBeNull();
  });

  it('rolls back the audit entry when an outbox insert fails', async () => {
    const repository = new PrismaAuditRepository(prisma);
    const resourceId = randomUUID();
    const event = createDomainEvent({
      eventType: 'identity.user.status-changed',
      producer: 'identity-service',
      payload: {},
    });
    const entry = {
      occurredAt: new Date(),
      source: 'identity-service',
      action: 'identity.user.disabled',
      outcome: 'success' as const,
      actorType: 'user' as const,
      resourceId,
    };
    // The same event twice violates the unique event ID.
    await expect(repository.append(entry, [event, event])).rejects.toThrow();
    expect((await repository.list({ page: 1, pageSize: 10, resourceId })).total).toBe(0);
  });

  it('is append-only at the database level', async () => {
    const repository = new PrismaAuditRepository(prisma);
    const resourceId = randomUUID();
    await repository.append({
      occurredAt: new Date(),
      source: 'identity-service',
      action: 'identity.profile.updated',
      outcome: 'success',
      actorType: 'user',
      resourceId,
    });
    await expect(
      prisma.auditEvent.updateMany({ where: { resourceId }, data: { outcome: 'failure' } }),
    ).rejects.toThrow(/append-only/);
    await expect(prisma.auditEvent.deleteMany({ where: { resourceId } })).rejects.toThrow(
      /append-only/,
    );
    await expect(prisma.$executeRawUnsafe('TRUNCATE audit_events')).rejects.toThrow(/append-only/);
  });

  it('ingests external events idempotently and filters by time and outcome', async () => {
    const repository = new PrismaAuditRepository(prisma);
    const actorId = randomUUID();
    const entries = [1, 2, 3].map((n) => ({
      occurredAt: new Date(Date.UTC(2026, 10, 4, 8, n)),
      source: 'keycloak',
      sourceEventId: `user:${actorId}:${n}`,
      action: 'identity.keycloak-login.succeeded',
      outcome: n === 3 ? ('failure' as const) : ('success' as const),
      actorType: 'user' as const,
      actorId,
    }));
    expect(await repository.appendMany(entries)).toBe(3);
    expect(await repository.appendMany(entries)).toBe(0);
    const failures = await repository.list({ page: 1, pageSize: 10, actorId, outcome: 'failure' });
    expect(failures.total).toBe(1);
    const window = await repository.list({
      page: 1,
      pageSize: 10,
      actorId,
      from: '2026-11-04T08:02:00.000Z',
      to: '2026-11-04T08:03:00.000Z',
    });
    expect(window.items.map((item) => item.occurredAt)).toEqual(['2026-11-04T08:02:00.000Z']);
    const newestFirst = await repository.list({ page: 1, pageSize: 2, actorId });
    expect(newestFirst.items[0]!.occurredAt).toBe('2026-11-04T08:03:00.000Z');
  });
});

describe('profiles and cursors', () => {
  it('creates a profile on first sight and updates preferences', async () => {
    const repository = new PrismaProfileRepository(prisma);
    const id = randomUUID();
    const first = await repository.touch(
      { id, username: 'ada', email: null },
      new Date('2026-11-01T00:00:00Z'),
    );
    const second = await repository.touch(
      { id, username: 'ada.l', email: 'ada@example.com' },
      new Date('2026-11-04T00:00:00Z'),
    );
    expect(second.firstSeenAt).toEqual(first.firstSeenAt);
    expect(second).toMatchObject({ username: 'ada.l', email: 'ada@example.com', timezone: 'UTC' });
    const updated = await repository.update(id, { timezone: 'Europe/Berlin', displayName: 'Ada' });
    expect(updated).toMatchObject({
      timezone: 'Europe/Berlin',
      displayName: 'Ada',
      jobTitle: null,
    });
  });

  it('stores sync cursors with millisecond precision', async () => {
    const cursors = new PrismaSyncCursorRepository(prisma);
    const name = `test-${randomUUID().slice(0, 8)}`;
    expect(await cursors.get(name)).toBeNull();
    await cursors.set(name, new Date('2026-11-04T08:00:00.123Z'));
    expect((await cursors.get(name))?.toISOString()).toBe('2026-11-04T08:00:00.123Z');
  });
});

describe('outbox store', () => {
  it('claims due events once, leases them, and records failures and publication', async () => {
    const store = new PrismaOutboxStore(prisma, 60_000);
    // Drain anything left over from other tests.
    const now = new Date(Date.now() + 1_000);
    for (const record of await store.claimDue(1_000, now)) {
      await store.markPublished(record.id, now);
    }
    const event = createDomainEvent({
      eventType: 'identity.session.revoked',
      producer: 'identity-service',
      payload: { userId: randomUUID() },
    });
    await prisma.outboxEvent.create({
      data: { eventId: event.eventId, eventType: event.eventType, envelope: event },
    });

    const claimNow = new Date(Date.now() + 1_000);
    const [claimed, again] = await Promise.all([
      store.claimDue(10, claimNow),
      store.claimDue(10, claimNow),
    ]);
    const all = [...claimed, ...again];
    expect(all.map((record) => record.event.eventId)).toEqual([event.eventId]);
    const record = all[0]!;

    await store.markFailed(record.id, 'broker down', new Date(claimNow.getTime() + 5_000));
    expect(await store.claimDue(10, claimNow)).toEqual([]);
    const retry = await store.claimDue(10, new Date(claimNow.getTime() + 6_000));
    expect(retry.map((r) => r.attempts)).toEqual([1]);

    await store.markPublished(record.id, new Date());
    expect(await store.claimDue(10, new Date(claimNow.getTime() + 600_000))).toEqual([]);
  });
});
