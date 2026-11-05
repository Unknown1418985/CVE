import {
  parseCveId,
  type AssociationPenalty,
  type AssociationSignal,
  type AssociationSignalKind,
  type ConfidenceLevel,
} from '@cve/contracts';

import { excerpt, findCveMentions } from './text.js';

/** Bumped whenever weights or rules change; stored with every score. */
export const SCORING_VERSION = 1;

/**
 * Weight of each signal (probability-like, combined with a noisy-OR). Text written by the
 * repository owner is weighted low: a name or description can claim anything. References from
 * CVE records are curated by the CVE program and NVD and weigh more.
 */
export const SIGNAL_WEIGHTS: Readonly<Record<AssociationSignalKind, number>> = {
  name: 0.55,
  topic: 0.4,
  description: 0.25,
  'file-path': 0.35,
  'cve-reference': 0.5,
  'cve-exploit-reference': 0.7,
  'search-match': 0.05,
  manual: 0.95,
};

/** Signals derived from owner-controlled text; penalties apply only to these. */
const TEXT_SIGNALS: ReadonlySet<AssociationSignalKind> = new Set([
  'name',
  'topic',
  'description',
  'file-path',
  'search-match',
]);

export const PENALTY_FACTORS = {
  fork: 0.85,
  emptyRepository: 0.3,
  noSourceCode: 0.6,
  predatesCve: 0.6,
  /** A repository mentioning more CVE IDs than this is treated as a collection. */
  multiCveThreshold: 3,
  multiCveMinimumFactor: 0.25,
} as const;

/** Highest score discovery can assign; only analysts confirm. */
export const MAX_AUTOMATIC_CONFIDENCE = 0.99;

export const CONFIDENCE_THRESHOLDS = { high: 0.7, medium: 0.4 } as const;

export function confidenceLevel(confidence: number): ConfidenceLevel {
  if (confidence >= CONFIDENCE_THRESHOLDS.high) return 'high';
  if (confidence >= CONFIDENCE_THRESHOLDS.medium) return 'medium';
  return 'low';
}

/** What is known about a repository when its associations are (re)scored. */
export interface RepositoryEvidence {
  readonly name: string;
  readonly description: string | null;
  readonly topics: readonly string[];
  readonly isFork: boolean;
  readonly sourceCreatedAt: Date | null;
  readonly sizeKb: number;
  /** Latest inspected snapshot; null until the repository has been inspected. */
  readonly snapshot: {
    readonly paths: readonly string[];
    readonly fileCount: number;
    readonly hasSourceCode: boolean;
  } | null;
}

/** Evidence about one (repository, CVE) pair that does not come from the repository text. */
export interface PairEvidence {
  readonly references: readonly { readonly exploit: boolean; readonly url: string }[];
  readonly searchMatched: boolean;
  readonly manual: boolean;
}

export interface TextMentions {
  /** Per CVE ID, the strongest excerpt per text field. */
  readonly byCve: ReadonlyMap<
    string,
    Partial<Record<'name' | 'topic' | 'description' | 'file-path', string>>
  >;
  /** Distinct CVE IDs across all fields (collections mention many). */
  readonly distinctCount: number;
}

const MAX_PATHS_SCANNED = 5_000;

/** Finds the CVE IDs mentioned in a repository's name, topics, description and file paths. */
export function collectMentions(repo: RepositoryEvidence, now: Date = new Date()): TextMentions {
  const byCve = new Map<
    string,
    Partial<Record<'name' | 'topic' | 'description' | 'file-path', string>>
  >();
  const add = (field: 'name' | 'topic' | 'description' | 'file-path', text: string) => {
    for (const mention of findCveMentions(text, now)) {
      const entry = byCve.get(mention.cveId) ?? {};
      entry[field] ??= excerpt(text, mention.index, mention.length).slice(0, 300);
      byCve.set(mention.cveId, entry);
    }
  };
  add('name', repo.name);
  for (const topic of repo.topics) add('topic', topic);
  if (repo.description !== null) add('description', repo.description);
  for (const path of repo.snapshot?.paths.slice(0, MAX_PATHS_SCANNED) ?? []) add('file-path', path);
  return { byCve, distinctCount: byCve.size };
}

export interface AssociationScore {
  readonly confidence: number;
  readonly level: ConfidenceLevel;
  readonly signals: readonly AssociationSignal[];
  readonly penalties: readonly AssociationPenalty[];
  readonly scoringVersion: number;
}

const noisyOr = (weights: readonly number[]) =>
  1 - weights.reduce((product, weight) => product * (1 - weight), 1);

const round = (value: number) => Math.round(value * 1_000) / 1_000;

/**
 * Confidence that `repo` is a PoC for `cveId`, from 0 to 0.99. Text signals are combined with a
 * noisy-OR and multiplied by the penalties; curated signals (CVE references, analyst decisions)
 * are combined with the result without penalties.
 */
export function scoreAssociation(
  cveId: string,
  repo: RepositoryEvidence,
  mentions: TextMentions,
  pair: PairEvidence,
): AssociationScore {
  const signals: AssociationSignal[] = [];
  const found = mentions.byCve.get(cveId) ?? {};
  for (const field of ['name', 'topic', 'description', 'file-path'] as const) {
    const evidence = found[field];
    if (evidence !== undefined)
      signals.push({ kind: field, weight: SIGNAL_WEIGHTS[field], evidence });
  }
  if (pair.searchMatched && signals.length === 0) {
    signals.push({ kind: 'search-match', weight: SIGNAL_WEIGHTS['search-match'], evidence: null });
  }
  const exploitReference = pair.references.find((reference) => reference.exploit);
  if (exploitReference !== undefined) {
    signals.push({
      kind: 'cve-exploit-reference',
      weight: SIGNAL_WEIGHTS['cve-exploit-reference'],
      evidence: exploitReference.url.slice(0, 300),
    });
  } else if (pair.references.length > 0) {
    signals.push({
      kind: 'cve-reference',
      weight: SIGNAL_WEIGHTS['cve-reference'],
      evidence: pair.references[0]?.url.slice(0, 300) ?? null,
    });
  }
  if (pair.manual) signals.push({ kind: 'manual', weight: SIGNAL_WEIGHTS.manual, evidence: null });

  const penalties: AssociationPenalty[] = [];
  if (mentions.distinctCount > PENALTY_FACTORS.multiCveThreshold) {
    penalties.push({
      kind: 'multi-cve',
      factor: round(
        Math.max(
          PENALTY_FACTORS.multiCveMinimumFactor,
          PENALTY_FACTORS.multiCveThreshold / mentions.distinctCount,
        ),
      ),
      detail: `mentions ${String(mentions.distinctCount)} CVE IDs`,
    });
  }
  if (repo.isFork) penalties.push({ kind: 'fork', factor: PENALTY_FACTORS.fork, detail: null });
  if (repo.snapshot !== null ? repo.snapshot.fileCount === 0 : repo.sizeKb === 0) {
    penalties.push({
      kind: 'empty-repository',
      factor: PENALTY_FACTORS.emptyRepository,
      detail: null,
    });
  } else if (repo.snapshot !== null && !repo.snapshot.hasSourceCode) {
    penalties.push({ kind: 'no-source-code', factor: PENALTY_FACTORS.noSourceCode, detail: null });
  }
  const cveYear = parseCveId(cveId).year;
  const createdYear = repo.sourceCreatedAt?.getUTCFullYear();
  if (createdYear !== undefined && createdYear < cveYear - 1) {
    penalties.push({
      kind: 'predates-cve',
      factor: PENALTY_FACTORS.predatesCve,
      detail: `repository created in ${String(createdYear)}`,
    });
  }

  const factor = penalties.reduce((product, penalty) => product * penalty.factor, 1);
  const text =
    noisyOr(signals.filter((s) => TEXT_SIGNALS.has(s.kind)).map((s) => s.weight)) * factor;
  const curated = noisyOr(signals.filter((s) => !TEXT_SIGNALS.has(s.kind)).map((s) => s.weight));
  const confidence = round(Math.min(MAX_AUTOMATIC_CONFIDENCE, 1 - (1 - text) * (1 - curated)));
  return {
    confidence,
    level: confidenceLevel(confidence),
    signals,
    penalties,
    scoringVersion: SCORING_VERSION,
  };
}

/** Candidate CVE IDs of a repository: everything it mentions plus externally known pairs. */
export function candidateCveIds(
  mentions: TextMentions,
  external: Iterable<string>,
  limit: number,
): string[] {
  return [...new Set([...mentions.byCve.keys(), ...external])].slice(0, limit);
}
