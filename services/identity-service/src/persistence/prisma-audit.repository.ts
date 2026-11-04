import type { AuditEvent, DomainEventEnvelope, ListAuditEventsQuery } from '@cve/contracts';

import { Prisma, type PrismaClient } from '../generated/prisma/client.js';
import type { AuditEvent as AuditRow } from '../generated/prisma/client.js';
import type { AuditRepository, NewAuditEntry } from './ports.js';

const truncate = (value: string | undefined, max: number) =>
  value === undefined ? null : value.slice(0, max);

function toRow(entry: NewAuditEntry): Prisma.AuditEventCreateManyInput {
  return {
    occurredAt: entry.occurredAt,
    source: entry.source,
    sourceEventId: entry.sourceEventId ?? null,
    action: entry.action,
    outcome: entry.outcome,
    actorType: entry.actorType,
    actorId: truncate(entry.actorId, 128),
    actorUsername: truncate(entry.actorUsername, 255),
    resourceType: truncate(entry.resourceType, 64),
    resourceId: truncate(entry.resourceId, 128),
    ipAddress: truncate(entry.ipAddress, 64),
    userAgent: truncate(entry.userAgent, 512),
    correlationId: truncate(entry.correlationId, 128),
    details:
      entry.details === undefined
        ? Prisma.DbNull
        : (JSON.parse(JSON.stringify(entry.details)) as Prisma.InputJsonValue),
  };
}

function toAuditEvent(row: AuditRow): AuditEvent {
  return {
    id: row.id,
    occurredAt: row.occurredAt.toISOString(),
    recordedAt: row.recordedAt.toISOString(),
    source: row.source,
    action: row.action,
    outcome: row.outcome,
    actorType: row.actorType,
    actorId: row.actorId,
    actorUsername: row.actorUsername,
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    correlationId: row.correlationId,
    details:
      row.details !== null && typeof row.details === 'object' && !Array.isArray(row.details)
        ? row.details
        : null,
  };
}

export class PrismaAuditRepository implements AuditRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async append(entry: NewAuditEntry, events: readonly DomainEventEnvelope[] = []): Promise<void> {
    await this.prisma.$transaction([
      this.prisma.auditEvent.create({ data: toRow(entry) }),
      ...events.map((event) =>
        this.prisma.outboxEvent.create({
          data: {
            eventId: event.eventId,
            eventType: event.eventType,
            envelope: JSON.parse(JSON.stringify(event)) as Prisma.InputJsonValue,
          },
        }),
      ),
    ]);
  }

  async appendMany(entries: readonly NewAuditEntry[]): Promise<number> {
    if (entries.length === 0) return 0;
    const result = await this.prisma.auditEvent.createMany({
      data: entries.map(toRow),
      skipDuplicates: true,
    });
    return result.count;
  }

  async list(query: ListAuditEventsQuery): Promise<{ items: AuditEvent[]; total: number }> {
    const where: Prisma.AuditEventWhereInput = {
      ...(query.actorId === undefined ? {} : { actorId: query.actorId }),
      ...(query.action === undefined ? {} : { action: query.action }),
      ...(query.outcome === undefined ? {} : { outcome: query.outcome }),
      ...(query.source === undefined ? {} : { source: query.source }),
      ...(query.resourceType === undefined ? {} : { resourceType: query.resourceType }),
      ...(query.resourceId === undefined ? {} : { resourceId: query.resourceId }),
      ...(query.from === undefined && query.to === undefined
        ? {}
        : {
            occurredAt: {
              ...(query.from === undefined ? {} : { gte: new Date(query.from) }),
              ...(query.to === undefined ? {} : { lt: new Date(query.to) }),
            },
          }),
    };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.auditEvent.findMany({
        where,
        orderBy: [{ occurredAt: 'desc' }, { id: 'desc' }],
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.auditEvent.count({ where }),
    ]);
    return { items: rows.map(toAuditEvent), total };
  }

  async find(id: string): Promise<AuditEvent | null> {
    const row = await this.prisma.auditEvent.findUnique({ where: { id } });
    return row === null ? null : toAuditEvent(row);
  }
}
