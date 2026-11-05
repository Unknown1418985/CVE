import {
  associationChangedPayloadSchema,
  POC_EVENT_TYPES,
  type AssociationSignal,
  type DomainEventEnvelope,
  type EventActor,
} from '@cve/contracts';

import {
  candidateCveIds,
  collectMentions,
  scoreAssociation,
  type AssociationScore,
  type PairEvidence,
  type RepositoryEvidence,
} from '../domain/scoring.js';
import { pocEvent } from '../events/poc-events.js';
import { decimalToNumber, Prisma, toJson, type Tx } from '../persistence/database.js';

export interface ScoringSettings {
  readonly minConfidence: number;
  readonly maxAssociations: number;
}

export interface RescoreContext {
  readonly actor: EventActor;
  readonly correlationId: string | undefined;
  readonly now: Date;
}

export interface RescoreResult {
  readonly created: number;
  readonly updated: number;
  readonly discarded: number;
  readonly events: readonly DomainEventEnvelope[];
}

const MAX_SCORED_PATHS = 5_000;

/** Loads everything the scoring model needs about a repository. */
export async function loadRepositoryEvidence(
  tx: Tx,
  repositoryId: string,
): Promise<{ evidence: RepositoryEvidence; fullNameKey: string; url: string } | null> {
  const repo = await tx.pocRepository.findUnique({
    where: { id: repositoryId },
    select: {
      name: true,
      description: true,
      topics: true,
      isFork: true,
      sourceCreatedAt: true,
      sizeKb: true,
      isEmpty: true,
      latestArtifactId: true,
      fullNameKey: true,
      url: true,
    },
  });
  if (repo === null) return null;
  let snapshot: RepositoryEvidence['snapshot'] = null;
  if (repo.isEmpty) {
    snapshot = { paths: [], fileCount: 0, hasSourceCode: false };
  } else if (repo.latestArtifactId !== null) {
    const artifact = await tx.pocArtifact.findUnique({
      where: { id: repo.latestArtifactId },
      select: {
        fileCount: true,
        hasSourceCode: true,
        files: { select: { path: true }, take: MAX_SCORED_PATHS },
      },
    });
    if (artifact !== null) {
      snapshot = {
        paths: artifact.files.map((file) => file.path),
        fileCount: artifact.fileCount,
        hasSourceCode: artifact.hasSourceCode,
      };
    }
  }
  return {
    fullNameKey: repo.fullNameKey,
    url: repo.url,
    evidence: {
      name: repo.name,
      description: repo.description,
      topics: repo.topics,
      isFork: repo.isFork,
      sourceCreatedAt: repo.sourceCreatedAt,
      sizeKb: repo.sizeKb,
      snapshot,
    },
  };
}

const signalKinds = (signals: readonly AssociationSignal[]) => signals.map((signal) => signal.kind);

function sameScore(
  stored: { confidence: number; signals: unknown; penalties: unknown; scoringVersion: number },
  score: AssociationScore,
): boolean {
  return (
    stored.confidence === score.confidence &&
    stored.scoringVersion === score.scoringVersion &&
    JSON.stringify(stored.signals) === JSON.stringify(score.signals) &&
    JSON.stringify(stored.penalties) === JSON.stringify(score.penalties)
  );
}

/**
 * Recomputes every CVE association of a repository from the stored evidence: its text, the
 * latest snapshot's file names, CVE references pointing to it, search matches and analyst
 * decisions. New pairs below the minimum confidence are not stored; stored pairs are updated
 * (never deleted), and their review status is kept.
 */
export async function rescoreRepository(
  tx: Tx,
  repositoryId: string,
  settings: ScoringSettings,
  context: RescoreContext,
  /** CVE IDs the connector's search returned this repository for (persisted as evidence). */
  searchMatched: ReadonlySet<string> = new Set(),
): Promise<RescoreResult> {
  const loaded = await loadRepositoryEvidence(tx, repositoryId);
  if (loaded === null) return { created: 0, updated: 0, discarded: 0, events: [] };
  const { evidence } = loaded;
  const mentions = collectMentions(evidence, context.now);

  const references = await tx.pocReference.findMany({
    where: {
      removedAt: null,
      OR: [{ repositoryId }, { repositoryKey: loaded.fullNameKey }],
    },
    select: { cveId: true, url: true, tags: true },
    orderBy: { firstSeenAt: 'asc' },
  });
  const referencesByCve = new Map<string, PairEvidence['references'][number][]>();
  for (const reference of references) {
    const list = referencesByCve.get(reference.cveId) ?? [];
    list.push({
      url: reference.url,
      exploit: reference.tags.some((tag) => tag.toLowerCase() === 'exploit'),
    });
    referencesByCve.set(reference.cveId, list);
  }
  const existing = await tx.pocAssociation.findMany({ where: { repositoryId } });
  const existingByCve = new Map(existing.map((row) => [row.cveId, row]));

  const candidates = candidateCveIds(
    mentions,
    [...searchMatched, ...referencesByCve.keys(), ...existingByCve.keys()],
    settings.maxAssociations,
  );
  let created = 0;
  let updated = 0;
  let discarded = 0;
  const events: DomainEventEnvelope[] = [];
  for (const cveId of candidates) {
    const stored = existingByCve.get(cveId);
    const score = scoreAssociation(cveId, evidence, mentions, {
      references: referencesByCve.get(cveId) ?? [],
      searchMatched:
        searchMatched.has(cveId) ||
        (stored?.searchMatchedAt !== null && stored?.searchMatchedAt !== undefined),
      manual: stored?.manual ?? false,
    });
    const scoreFields = {
      confidence: new Prisma.Decimal(score.confidence),
      confidenceLevel: score.level,
      signals: toJson(score.signals),
      penalties: toJson(score.penalties),
      scoringVersion: score.scoringVersion,
      lastEvaluatedAt: context.now,
      ...(searchMatched.has(cveId) ? { searchMatchedAt: context.now } : {}),
    };
    if (stored === undefined) {
      if (score.confidence < settings.minConfidence) {
        discarded += 1;
        continue;
      }
      const row = await tx.pocAssociation.create({
        data: {
          repositoryId,
          cveId,
          ...scoreFields,
          origin: 'discovered',
          firstDiscoveredAt: context.now,
        },
      });
      created += 1;
      events.push(
        associationEvent(
          POC_EVENT_TYPES.associationDiscovered,
          row,
          loaded.url,
          score,
          null,
          context,
        ),
      );
      continue;
    }
    const previous = {
      confidence: decimalToNumber(stored.confidence) ?? 0,
      signals: stored.signals,
      penalties: stored.penalties,
      scoringVersion: stored.scoringVersion,
    };
    if (sameScore(previous, score)) {
      if (searchMatched.has(cveId) && stored.searchMatchedAt === null) {
        await tx.pocAssociation.update({
          where: { id: stored.id },
          data: { searchMatchedAt: context.now },
        });
      }
      continue;
    }
    const row = await tx.pocAssociation.update({
      where: { id: stored.id },
      data: { ...scoreFields, version: { increment: 1 } },
    });
    updated += 1;
    if (previous.confidence !== score.confidence || stored.confidenceLevel !== score.level) {
      events.push(
        associationEvent(
          POC_EVENT_TYPES.associationUpdated,
          row,
          loaded.url,
          score,
          previous.confidence,
          context,
        ),
      );
    }
  }
  await refreshMaxConfidence(tx, repositoryId);
  return { created, updated, discarded, events };
}

export async function refreshMaxConfidence(tx: Tx, repositoryId: string): Promise<void> {
  await tx.$executeRaw`
    UPDATE "poc_repositories" AS r
       SET "max_confidence" = (
             SELECT max(a."confidence") FROM "poc_cve_associations" AS a
              WHERE a."repository_id" = r."id" AND a."review_status" <> 'rejected')
     WHERE r."id" = ${repositoryId}::uuid`;
}

interface AssociationRow {
  readonly id: string;
  readonly repositoryId: string;
  readonly cveId: string;
  readonly origin: 'discovered' | 'manual';
  readonly reviewStatus: 'candidate' | 'confirmed' | 'rejected';
}

export function associationEvent(
  eventType: string,
  row: AssociationRow,
  repositoryUrl: string,
  score: {
    confidence: number;
    level: AssociationScore['level'];
    signals: readonly AssociationSignal[];
    scoringVersion: number;
  },
  previousConfidence: number | null,
  context: { readonly actor: EventActor; readonly correlationId: string | undefined },
): DomainEventEnvelope {
  return pocEvent(
    eventType,
    associationChangedPayloadSchema,
    {
      associationId: row.id,
      repositoryId: row.repositoryId,
      repositoryUrl,
      cveId: row.cveId,
      confidence: score.confidence,
      confidenceLevel: score.level,
      previousConfidence,
      signalKinds: signalKinds(score.signals),
      scoringVersion: score.scoringVersion,
      origin: row.origin,
      reviewStatus: row.reviewStatus,
      actor: context.actor,
    },
    context.correlationId,
  );
}
