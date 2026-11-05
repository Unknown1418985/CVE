import { createHash } from 'node:crypto';

import {
  POC_EVENT_TYPES,
  repositoryDiscoveredPayloadSchema,
  repositoryUpdatedPayloadSchema,
  type DomainEventEnvelope,
  type PocConnector,
  type REPOSITORY_CHANGE_FIELDS,
} from '@cve/contracts';

import type { RepositoryMetadata } from '../connectors/github/github-mapping.js';
import { pocEvent } from '../events/poc-events.js';
import type { Tx } from '../persistence/database.js';

type RepositoryChange = (typeof REPOSITORY_CHANGE_FIELDS)[number];

/** Fields whose change is reported as `metadata` (stars and forks change too often to count). */
export function metadataHash(meta: RepositoryMetadata): string {
  return createHash('sha256')
    .update(
      JSON.stringify([
        meta.description,
        meta.topics,
        meta.language,
        meta.isFork,
        meta.parentFullName,
        meta.isArchived,
        meta.defaultBranch,
        meta.sourceCreatedAt?.toISOString() ?? null,
      ]),
    )
    .digest('hex');
}

export interface RepositoryRow {
  readonly id: string;
  readonly source: string;
  readonly externalId: string;
  readonly fullName: string;
  readonly url: string;
  readonly status: 'active' | 'unavailable';
  readonly latestCommitSha: string | null;
  readonly version: number;
  readonly owner: { readonly login: string; readonly externalId: string };
}

export function repositorySnapshot(row: RepositoryRow) {
  return {
    repositoryId: row.id,
    source: 'github' as const,
    externalId: row.externalId,
    fullName: row.fullName,
    url: row.url,
    ownerLogin: row.owner.login,
    ownerExternalId: row.owner.externalId,
    status: row.status,
    latestCommitSha: row.latestCommitSha,
    version: row.version,
  };
}

export const REPOSITORY_SELECT = {
  id: true,
  source: true,
  externalId: true,
  fullName: true,
  url: true,
  status: true,
  latestCommitSha: true,
  version: true,
  owner: { select: { login: true, externalId: true } },
} as const;

export interface UpsertRepositoryResult {
  readonly repositoryId: string;
  readonly outcome: 'created' | 'updated' | 'unchanged';
  /** Whether the repository must be inspected (new, pushed since the last inspection, revived). */
  readonly inspectionNeeded: boolean;
  readonly events: readonly DomainEventEnvelope[];
}

/**
 * Creates or refreshes a repository and its owner from validated metadata. The row is locked
 * (`FOR UPDATE`) so concurrent discoveries of the same repository apply one after the other.
 */
export async function upsertRepository(
  tx: Tx,
  meta: RepositoryMetadata,
  context: {
    readonly connector: PocConnector;
    readonly runId: string | null;
    readonly correlationId: string | undefined;
    readonly now: Date;
  },
): Promise<UpsertRepositoryResult> {
  const { now } = context;
  const owner = await tx.repositoryOwner.upsert({
    where: { source_externalId: { source: 'github', externalId: meta.owner.externalId } },
    create: {
      source: 'github',
      externalId: meta.owner.externalId,
      login: meta.owner.login,
      loginKey: meta.owner.login.toLowerCase(),
      type: meta.owner.type,
      url: meta.owner.url,
      firstSeenAt: now,
      lastSeenAt: now,
    },
    update: {
      login: meta.owner.login,
      loginKey: meta.owner.login.toLowerCase(),
      type: meta.owner.type,
      url: meta.owner.url,
      lastSeenAt: now,
    },
  });
  const hash = metadataHash(meta);
  const fields = {
    ownerId: owner.id,
    name: meta.name,
    fullName: meta.fullName,
    fullNameKey: meta.fullName.toLowerCase(),
    url: meta.url,
    description: meta.description,
    topics: [...meta.topics],
    language: meta.language,
    stars: meta.stars,
    forks: meta.forks,
    isFork: meta.isFork,
    parentFullName: meta.parentFullName,
    isArchived: meta.isArchived,
    defaultBranch: meta.defaultBranch,
    sizeKb: meta.sizeKb,
    sourceCreatedAt: meta.sourceCreatedAt,
    sourcePushedAt: meta.sourcePushedAt,
    metadataHash: hash,
  };
  // Insert-or-lock: the unique key decides the winner of concurrent inserts.
  const inserted = await tx.$queryRaw<{ id: string }[]>`
    INSERT INTO "poc_repositories" ("id", "source", "external_id", "owner_id", "name", "full_name",
           "full_name_key", "url", "topics", "is_fork", "is_archived", "metadata_hash",
           "discovered_by", "first_discovered_at", "last_seen_at", "inspection_due_at",
           "created_at", "updated_at")
    VALUES (gen_random_uuid(), 'github', ${meta.externalId}, ${owner.id}::uuid, ${meta.name},
            ${meta.fullName}, ${fields.fullNameKey}, ${meta.url}, ${fields.topics}, ${meta.isFork},
            ${meta.isArchived}, ${hash}, ${context.connector}, ${now}, ${now}, ${now}, ${now}, ${now})
    ON CONFLICT ("source", "external_id") DO NOTHING
    RETURNING "id"`;
  if (inserted[0] !== undefined) {
    const row = await tx.pocRepository.update({
      where: { id: inserted[0].id },
      data: fields,
      select: REPOSITORY_SELECT,
    });
    return {
      repositoryId: row.id,
      outcome: 'created',
      inspectionNeeded: true,
      events: [
        pocEvent(
          POC_EVENT_TYPES.repositoryDiscovered,
          repositoryDiscoveredPayloadSchema,
          { ...repositorySnapshot(row), connector: context.connector, runId: context.runId },
          context.correlationId,
        ),
      ],
    };
  }

  const [locked] = await tx.$queryRaw<
    {
      id: string;
      ownerId: string;
      fullName: string;
      metadataHash: string;
      status: 'active' | 'unavailable';
      inspectedPushedAt: Date | null;
      lastInspectedAt: Date | null;
    }[]
  >`
    SELECT "id", "owner_id" AS "ownerId", "full_name" AS "fullName", "metadata_hash" AS "metadataHash",
           "status", "inspected_pushed_at" AS "inspectedPushedAt", "last_inspected_at" AS "lastInspectedAt"
      FROM "poc_repositories" WHERE "source" = 'github' AND "external_id" = ${meta.externalId}
       FOR UPDATE`;
  if (locked === undefined) throw new Error('repository vanished during upsert');

  const changed: RepositoryChange[] = [];
  if (locked.metadataHash !== hash) changed.push('metadata');
  if (locked.ownerId !== owner.id) changed.push('owner');
  if (locked.fullName !== meta.fullName) changed.push('name');
  if (locked.status !== 'active') changed.push('status');
  const pushedSinceInspection =
    meta.sourcePushedAt !== null &&
    (locked.inspectedPushedAt === null || meta.sourcePushedAt > locked.inspectedPushedAt);
  const inspectionNeeded =
    locked.lastInspectedAt === null || pushedSinceInspection || changed.includes('status');

  const row = await tx.pocRepository.update({
    where: { id: locked.id },
    data: {
      ...fields,
      status: 'active',
      lastSeenAt: now,
      ...(inspectionNeeded ? { inspectionDueAt: now } : {}),
      ...(changed.length > 0 ? { version: { increment: 1 } } : {}),
    },
    select: REPOSITORY_SELECT,
  });
  return {
    repositoryId: row.id,
    outcome: changed.length > 0 ? 'updated' : 'unchanged',
    inspectionNeeded,
    events:
      changed.length === 0
        ? []
        : [
            pocEvent(
              POC_EVENT_TYPES.repositoryUpdated,
              repositoryUpdatedPayloadSchema,
              { ...repositorySnapshot(row), changedFields: changed, runId: context.runId },
              context.correlationId,
            ),
          ],
  };
}

/** Marks a repository the source no longer serves; its history is kept. */
export async function markRepositoryUnavailable(
  tx: Tx,
  repositoryId: string,
  context: {
    readonly runId: string | null;
    readonly correlationId: string | undefined;
    readonly now: Date;
  },
): Promise<readonly DomainEventEnvelope[]> {
  const current = await tx.pocRepository.findUnique({
    where: { id: repositoryId },
    select: { status: true },
  });
  if (current === null) return [];
  if (current.status === 'unavailable') {
    await tx.pocRepository.update({
      where: { id: repositoryId },
      data: { inspectionDueAt: null, lastInspectedAt: context.now },
    });
    return [];
  }
  const row = await tx.pocRepository.update({
    where: { id: repositoryId },
    data: {
      status: 'unavailable',
      inspectionDueAt: null,
      lastInspectedAt: context.now,
      version: { increment: 1 },
    },
    select: REPOSITORY_SELECT,
  });
  return [
    pocEvent(
      POC_EVENT_TYPES.repositoryUpdated,
      repositoryUpdatedPayloadSchema,
      { ...repositorySnapshot(row), changedFields: ['status'], runId: context.runId },
      context.correlationId,
    ),
  ];
}
