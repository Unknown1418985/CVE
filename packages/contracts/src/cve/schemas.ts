import { z } from 'zod';

import { paginationQuerySchema } from '../api.js';
import {
  CVSS_VERSIONS,
  cvss31BaseScore,
  isCvssScore,
  MAX_CVSS_VECTOR_LENGTH,
  parseCvssVector,
  RECORD_SEVERITIES,
  SEVERITIES,
  severityForScore,
  type CvssVersion,
  type Severity,
} from './cvss.js';
import { cpe23Schema, cveIdSchema, cweIdSchema } from './identifiers.js';

// ---------------------------------------------------------------------------- primitives

export const CVE_STATES = ['published', 'rejected'] as const;
export const cveStateSchema = z.enum(CVE_STATES);
export type CveState = z.infer<typeof cveStateSchema>;

export const cvssVersionSchema = z.enum(CVSS_VERSIONS);
export const severitySchema = z.enum(SEVERITIES);
export const recordSeveritySchema = z.enum(RECORD_SEVERITIES);

/** Whether a metric comes from the record's primary scorer (e.g. NVD) or another party. */
export const CVSS_SOURCE_TYPES = ['primary', 'secondary'] as const;
export const cvssSourceTypeSchema = z.enum(CVSS_SOURCE_TYPES);
export type CvssSourceType = z.infer<typeof cvssSourceTypeSchema>;

export const AFFECTED_STATUSES = ['affected', 'unaffected', 'unknown'] as const;
export const affectedStatusSchema = z.enum(AFFECTED_STATUSES);
export type AffectedStatus = z.infer<typeof affectedStatusSchema>;

export const RANSOMWARE_USE_VALUES = ['known', 'unknown'] as const;
export const ransomwareUseSchema = z.enum(RANSOMWARE_USE_VALUES);

/**
 * Where a piece of data came from (provenance): a source name such as `nvd`, `cisa-kev`,
 * `first-epss`, `manual`, or a scorer identifier such as `nvd@nist.gov`.
 */
export const sourceIdentifierSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9@._:+/-]+$/, { message: 'may only contain letters, digits and @._:+/-' });

/** C0 controls except tab, line feed and carriage return, plus DEL. */
// eslint-disable-next-line no-control-regex -- matching control characters is the purpose
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

/** Free text without control characters other than tab and newline. */
function textSchema(max: number) {
  return z
    .string()
    .trim()
    .min(1)
    .max(max)
    .refine((value) => !CONTROL_CHARACTERS.test(value), { message: 'contains control characters' });
}

const versionTextSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[^\p{Cc}\s]+$/u, { message: 'must not contain whitespace or control characters' });

const productNameSchema = textSchema(128);

export const httpReferenceUrlSchema = z
  .string()
  .trim()
  .max(2048)
  .refine(
    (value) => {
      if (!URL.canParse(value)) return false;
      const url = new URL(value);
      return (
        (url.protocol === 'https:' || url.protocol === 'http:') &&
        url.hostname !== '' &&
        url.username === '' &&
        url.password === ''
      );
    },
    { message: 'must be an absolute http(s) URL without credentials' },
  )
  .transform((value) => new URL(value).href);

const timestampSchema = z.iso.datetime({ offset: true }).transform((value) => new Date(value));
const dateOnlySchema = z.iso.date();

// ---------------------------------------------------------------------------- write models

export interface NormalizedCvssMetric {
  readonly version: CvssVersion;
  readonly source: string;
  readonly type: CvssSourceType;
  readonly vectorString: string;
  readonly baseScore: number;
  readonly baseSeverity: Severity;
  readonly observedAt: Date | undefined;
}

/**
 * A CVSS metric reported by one source. The vector is validated and canonicalised. For v3.1 the
 * base score is computed from the vector (a supplied score must match it); for v4.0 the score is
 * required because it comes from FIRST's lookup tables, which this platform does not reimplement.
 */
export const cvssMetricInputSchema = z
  .strictObject({
    version: cvssVersionSchema,
    source: sourceIdentifierSchema,
    type: cvssSourceTypeSchema.default('secondary'),
    vectorString: z.string().trim().min(1).max(MAX_CVSS_VECTOR_LENGTH),
    baseScore: z.number().min(0).max(10).optional(),
    observedAt: timestampSchema.optional(),
  })
  .transform((input, ctx): NormalizedCvssMetric => {
    const parsed = parseCvssVector(input.vectorString, input.version);
    if (!parsed.ok) {
      ctx.addIssue({ code: 'custom', path: ['vectorString'], message: parsed.error });
      return z.NEVER;
    }
    let baseScore: number;
    if (parsed.vector.version === '3.1') {
      baseScore = cvss31BaseScore(parsed.vector);
      if (input.baseScore !== undefined && Math.abs(input.baseScore - baseScore) > 1e-9) {
        ctx.addIssue({
          code: 'custom',
          path: ['baseScore'],
          message: `does not match the vector (computed ${baseScore.toFixed(1)})`,
        });
        return z.NEVER;
      }
    } else {
      if (input.baseScore === undefined || !isCvssScore(input.baseScore)) {
        ctx.addIssue({
          code: 'custom',
          path: ['baseScore'],
          message: 'CVSS 4.0 metrics need the base score from the source (0.0–10.0, one decimal)',
        });
        return z.NEVER;
      }
      baseScore = input.baseScore;
    }
    return {
      version: parsed.vector.version,
      source: input.source,
      type: input.type,
      vectorString: parsed.vector.vectorString,
      baseScore,
      baseSeverity: severityForScore(baseScore),
      observedAt: input.observedAt,
    };
  });

export const weaknessInputSchema = z.strictObject({
  cweId: cweIdSchema,
  source: sourceIdentifierSchema,
});

export const referenceTagSchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9 ._/-]*$/, { message: 'invalid tag' });

export const referenceInputSchema = z.strictObject({
  url: httpReferenceUrlSchema,
  source: sourceIdentifierSchema,
  tags: z
    .array(referenceTagSchema)
    .max(20)
    .default([])
    .transform((tags) => [...new Set(tags)].sort()),
});

export const affectedProductInputSchema = z
  .strictObject({
    vendor: productNameSchema,
    product: productNameSchema,
    cpe: cpe23Schema.optional(),
    version: versionTextSchema.optional(),
    versionStartIncluding: versionTextSchema.optional(),
    versionStartExcluding: versionTextSchema.optional(),
    versionEndIncluding: versionTextSchema.optional(),
    versionEndExcluding: versionTextSchema.optional(),
    status: affectedStatusSchema.default('affected'),
    source: sourceIdentifierSchema,
  })
  .superRefine((value, ctx) => {
    if (value.versionStartIncluding !== undefined && value.versionStartExcluding !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['versionStartExcluding'],
        message: 'use either versionStartIncluding or versionStartExcluding',
      });
    }
    if (value.versionEndIncluding !== undefined && value.versionEndExcluding !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['versionEndExcluding'],
        message: 'use either versionEndIncluding or versionEndExcluding',
      });
    }
    const ranged = [
      value.versionStartIncluding,
      value.versionStartExcluding,
      value.versionEndIncluding,
      value.versionEndExcluding,
    ].some((bound) => bound !== undefined);
    if (value.version !== undefined && ranged) {
      ctx.addIssue({
        code: 'custom',
        path: ['version'],
        message: 'an exact version cannot be combined with a version range',
      });
    }
  });

export type CvssMetricInput = z.output<typeof cvssMetricInputSchema>;
export type WeaknessInput = z.output<typeof weaknessInputSchema>;
export type ReferenceInput = z.output<typeof referenceInputSchema>;
export type AffectedProductInput = z.output<typeof affectedProductInputSchema>;

/** Stable identity of an affected-product entry, used for duplicate detection. */
export function affectedProductKey(product: AffectedProductInput): string {
  return JSON.stringify([
    product.vendor.toLowerCase(),
    product.product.toLowerCase(),
    product.cpe ?? null,
    product.version ?? null,
    product.versionStartIncluding ?? null,
    product.versionStartExcluding ?? null,
    product.versionEndIncluding ?? null,
    product.versionEndExcluding ?? null,
    product.status,
  ]);
}

/** Reports entries whose key occurs more than once, as validation issues on `path`. */
function rejectDuplicates<T>(
  ctx: z.RefinementCtx,
  path: string,
  items: readonly T[] | undefined,
  key: (item: T) => string,
  describe: (item: T) => string,
): void {
  const seen = new Set<string>();
  (items ?? []).forEach((item, index) => {
    const k = key(item);
    if (seen.has(k)) {
      ctx.addIssue({ code: 'custom', path: [path, index], message: `duplicate ${describe(item)}` });
    }
    seen.add(k);
  });
}

const contentFields = {
  state: cveStateSchema,
  title: textSchema(256).nullable(),
  description: textSchema(32_000),
  assigner: sourceIdentifierSchema.nullable(),
  /** Publication and last modification time at the source (CVE Program / NVD), in UTC. */
  publishedAt: timestampSchema.nullable(),
  lastModifiedAt: timestampSchema.nullable(),
  /** Provenance of the record content (description, dates, state). */
  source: sourceIdentifierSchema,
  cvssMetrics: z.array(cvssMetricInputSchema).max(20),
  weaknesses: z.array(weaknessInputSchema).max(100),
  references: z.array(referenceInputSchema).max(1_000),
  affectedProducts: z.array(affectedProductInputSchema).max(2_000),
};

interface ContentLike {
  publishedAt?: Date | null | undefined;
  lastModifiedAt?: Date | null | undefined;
  cvssMetrics?: readonly CvssMetricInput[] | undefined;
  weaknesses?: readonly WeaknessInput[] | undefined;
  references?: readonly ReferenceInput[] | undefined;
  affectedProducts?: readonly AffectedProductInput[] | undefined;
}

function checkContent(value: ContentLike, ctx: z.RefinementCtx): void {
  if (
    value.publishedAt instanceof Date &&
    value.lastModifiedAt instanceof Date &&
    value.lastModifiedAt < value.publishedAt
  ) {
    ctx.addIssue({
      code: 'custom',
      path: ['lastModifiedAt'],
      message: 'must not be earlier than publishedAt',
    });
  }
  rejectDuplicates(
    ctx,
    'cvssMetrics',
    value.cvssMetrics,
    (m) => `${m.version}|${m.source}`,
    (m) => `CVSS ${m.version} metric from ${m.source}`,
  );
  rejectDuplicates(
    ctx,
    'weaknesses',
    value.weaknesses,
    (w) => `${w.cweId}|${w.source}`,
    (w) => `weakness ${w.cweId} from ${w.source}`,
  );
  rejectDuplicates(
    ctx,
    'references',
    value.references,
    (r) => r.url,
    (r) => `reference ${r.url}`,
  );
  rejectDuplicates(
    ctx,
    'affectedProducts',
    value.affectedProducts,
    affectedProductKey,
    (p) => `affected product ${p.vendor} ${p.product}`,
  );
}

/** Full CVE record content, used to create (POST) and to replace or upsert (PUT) a record. */
export const cveContentSchema = z
  .strictObject({
    ...contentFields,
    state: contentFields.state.default('published'),
    title: contentFields.title.default(null),
    assigner: contentFields.assigner.default(null),
    publishedAt: contentFields.publishedAt.default(null),
    lastModifiedAt: contentFields.lastModifiedAt.default(null),
    cvssMetrics: contentFields.cvssMetrics.default([]),
    weaknesses: contentFields.weaknesses.default([]),
    references: contentFields.references.default([]),
    affectedProducts: contentFields.affectedProducts.default([]),
  })
  .superRefine(checkContent);
export type CveContent = z.output<typeof cveContentSchema>;

/** `POST /api/v1/cves` */
export const createCveRequestSchema = z
  .strictObject({ cveId: cveIdSchema, ...cveContentSchema.shape })
  .superRefine(checkContent);
export type CreateCveRequest = z.output<typeof createCveRequestSchema>;

/** `PATCH /api/v1/cves/:cveId`: only the given fields change; lists are replaced as a whole. */
export const updateCveRequestSchema = z
  .strictObject({
    state: contentFields.state.optional(),
    title: contentFields.title.optional(),
    description: contentFields.description.optional(),
    assigner: contentFields.assigner.optional(),
    publishedAt: contentFields.publishedAt.optional(),
    lastModifiedAt: contentFields.lastModifiedAt.optional(),
    source: contentFields.source.optional(),
    cvssMetrics: contentFields.cvssMetrics.optional(),
    weaknesses: contentFields.weaknesses.optional(),
    references: contentFields.references.optional(),
    affectedProducts: contentFields.affectedProducts.optional(),
  })
  .superRefine(checkContent)
  .refine((value) => Object.keys(value).length > 0, { message: 'at least one field is required' });
export type UpdateCveRequest = z.output<typeof updateCveRequestSchema>;

/** `PUT /api/v1/cves/:cveId/kev`: CISA Known Exploited Vulnerabilities catalog entry. */
export const kevStatusInputSchema = z
  .strictObject({
    dateAdded: dateOnlySchema,
    dueDate: dateOnlySchema.nullable().default(null),
    vulnerabilityName: textSchema(256).nullable().default(null),
    requiredAction: textSchema(2_000).nullable().default(null),
    knownRansomwareCampaignUse: ransomwareUseSchema.default('unknown'),
    notes: textSchema(4_000).nullable().default(null),
    source: sourceIdentifierSchema,
    observedAt: timestampSchema.optional(),
  })
  .refine((value) => value.dueDate === null || value.dueDate >= value.dateAdded, {
    path: ['dueDate'],
    message: 'must not be earlier than dateAdded',
  });
export type KevStatusInput = z.output<typeof kevStatusInputSchema>;

const probabilitySchema = z
  .number()
  .min(0)
  .max(1)
  .refine((value) => Math.abs(Math.round(value * 1e9) - value * 1e9) < 1e-6, {
    message: 'at most nine decimal places',
  });

/** `POST /api/v1/cves/:cveId/epss`: one daily EPSS observation (FIRST). */
export const epssObservationInputSchema = z.strictObject({
  score: probabilitySchema,
  percentile: probabilitySchema,
  scoreDate: dateOnlySchema,
  modelVersion: z
    .string()
    .trim()
    .min(1)
    .max(32)
    .regex(/^[A-Za-z0-9._-]+$/)
    .nullable()
    .default(null),
  source: sourceIdentifierSchema,
  observedAt: timestampSchema.optional(),
});
export type EpssObservationInput = z.output<typeof epssObservationInputSchema>;

// ---------------------------------------------------------------------------- read models

export const cvssMetricSchema = z.object({
  id: z.uuid(),
  version: cvssVersionSchema,
  source: z.string(),
  type: cvssSourceTypeSchema,
  vectorString: z.string(),
  baseScore: z.number(),
  baseSeverity: severitySchema,
  /** Every metric in the vector, keyed by abbreviation (e.g. `AV: "N"`). */
  metrics: z.record(z.string(), z.string()),
  observedAt: z.iso.datetime(),
  /** Set when the same source later reported a different vector; kept for history. */
  supersededAt: z.iso.datetime().nullable(),
});
export type CvssMetric = z.infer<typeof cvssMetricSchema>;

export const weaknessSchema = z.object({ cweId: z.string(), source: z.string() });
export type Weakness = z.infer<typeof weaknessSchema>;

export const referenceSchema = z.object({
  url: z.string(),
  source: z.string(),
  tags: z.array(z.string()),
});
export type Reference = z.infer<typeof referenceSchema>;

export const affectedProductSchema = z.object({
  id: z.uuid(),
  vendor: z.string(),
  product: z.string(),
  cpe: z.string().nullable(),
  version: z.string().nullable(),
  versionStartIncluding: z.string().nullable(),
  versionStartExcluding: z.string().nullable(),
  versionEndIncluding: z.string().nullable(),
  versionEndExcluding: z.string().nullable(),
  status: affectedStatusSchema,
  source: z.string(),
});
export type AffectedProduct = z.infer<typeof affectedProductSchema>;

export const kevStatusSchema = z.object({
  dateAdded: z.iso.date(),
  dueDate: z.iso.date().nullable(),
  vulnerabilityName: z.string().nullable(),
  requiredAction: z.string().nullable(),
  knownRansomwareCampaignUse: ransomwareUseSchema,
  notes: z.string().nullable(),
  source: z.string(),
  observedAt: z.iso.datetime(),
});
export type KevStatus = z.infer<typeof kevStatusSchema>;

export const epssObservationSchema = z.object({
  score: z.number(),
  percentile: z.number(),
  scoreDate: z.iso.date(),
  modelVersion: z.string().nullable(),
  source: z.string(),
  observedAt: z.iso.datetime(),
});
export type EpssObservation = z.infer<typeof epssObservationSchema>;

export const cveRecordSchema = z.object({
  id: z.uuid(),
  cveId: z.string(),
  state: cveStateSchema,
  title: z.string().nullable(),
  description: z.string(),
  assigner: z.string().nullable(),
  publishedAt: z.iso.datetime().nullable(),
  lastModifiedAt: z.iso.datetime().nullable(),
  source: z.string(),
  /** Derived from the preferred current CVSS metric (see docs/cve-service.md). */
  severity: recordSeveritySchema,
  cvssScore: z.number().nullable(),
  cvssVersion: cvssVersionSchema.nullable(),
  kev: kevStatusSchema.nullable(),
  /** Most recent EPSS observation by score date. */
  epss: epssObservationSchema.nullable(),
  /** Current metrics only; superseded ones are listed by the metric history endpoint. */
  cvssMetrics: z.array(cvssMetricSchema),
  weaknesses: z.array(weaknessSchema),
  references: z.array(referenceSchema),
  affectedProducts: z.array(affectedProductSchema),
  /** Incremented on every change; also returned as the `ETag`. */
  version: z.number().int().min(1),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
export type CveRecord = z.infer<typeof cveRecordSchema>;

export const cveSummarySchema = z.object({
  id: z.uuid(),
  cveId: z.string(),
  state: cveStateSchema,
  title: z.string().nullable(),
  description: z.string(),
  severity: recordSeveritySchema,
  cvssScore: z.number().nullable(),
  cvssVersion: cvssVersionSchema.nullable(),
  inKev: z.boolean(),
  epssScore: z.number().nullable(),
  epssPercentile: z.number().nullable(),
  cweIds: z.array(z.string()),
  publishedAt: z.iso.datetime().nullable(),
  lastModifiedAt: z.iso.datetime().nullable(),
  updatedAt: z.iso.datetime(),
});
export type CveSummary = z.infer<typeof cveSummarySchema>;

// ---------------------------------------------------------------------------- search

export const CVE_SORT_FIELDS = [
  'publishedAt',
  'lastModifiedAt',
  'cvssScore',
  'epssScore',
  'cveId',
  'updatedAt',
] as const;
export type CveSortField = (typeof CVE_SORT_FIELDS)[number];

/** Accepts `a,b` or repeated query parameters. */
function listParam<T extends z.ZodType>(item: T, max: number) {
  return z.preprocess(
    (value: unknown): unknown[] =>
      (Array.isArray(value) ? (value as unknown[]) : [value])
        .flatMap((entry): unknown[] => (typeof entry === 'string' ? entry.split(',') : [entry]))
        .map((entry) => (typeof entry === 'string' ? entry.trim() : entry))
        .filter((entry) => entry !== ''),
    z.array(item).min(1).max(max),
  );
}

const booleanParam = z.enum(['true', 'false']).transform((value) => value === 'true');
const scoreParam = z.coerce.number().min(0).max(10);
const probabilityParam = z.coerce.number().min(0).max(1);

/** `GET /api/v1/cves`. Unknown parameters are rejected so typos do not silently widen results. */
export const listCvesQuerySchema = z
  .strictObject({
    ...paginationQuerySchema.shape,
    /** Matches the CVE ID, title or description (case-insensitive substring). */
    q: z.string().trim().min(2).max(200).optional(),
    severity: listParam(recordSeveritySchema, RECORD_SEVERITIES.length).optional(),
    state: cveStateSchema.optional(),
    cvssVersion: cvssVersionSchema.optional(),
    cvssScoreMin: scoreParam.optional(),
    cvssScoreMax: scoreParam.optional(),
    epssScoreMin: probabilityParam.optional(),
    epssPercentileMin: probabilityParam.optional(),
    kev: booleanParam.optional(),
    cweId: listParam(cweIdSchema, 20).optional(),
    vendor: productNameSchema.optional(),
    product: productNameSchema.optional(),
    year: z.coerce.number().int().min(1999).max(9999).optional(),
    publishedFrom: timestampSchema.optional(),
    publishedTo: timestampSchema.optional(),
    modifiedFrom: timestampSchema.optional(),
    modifiedTo: timestampSchema.optional(),
    sort: z.enum(CVE_SORT_FIELDS).default('publishedAt'),
    order: z.enum(['asc', 'desc']).default('desc'),
  })
  .refine(
    (q) =>
      q.cvssScoreMin === undefined ||
      q.cvssScoreMax === undefined ||
      q.cvssScoreMin <= q.cvssScoreMax,
    { path: ['cvssScoreMax'], message: 'must not be lower than cvssScoreMin' },
  );
export type ListCvesQuery = z.output<typeof listCvesQuerySchema>;
