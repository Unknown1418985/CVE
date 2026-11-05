import { z } from 'zod';

import { paginationQuerySchema } from '../api.js';
import { RECORD_SEVERITIES } from '../cve/cvss.js';
import { cpe23Schema, cveIdSchema } from '../cve/identifiers.js';
import {
  affectedStatusSchema,
  booleanParam,
  cveStateSchema,
  httpReferenceUrlSchema,
  listParam,
  productNameSchema,
  recordSeveritySchema,
  sourceIdentifierSchema,
  textSchema,
  versionTextSchema,
} from '../cve/schemas.js';

// ---------------------------------------------------------------------------- primitives

/**
 * Stable, URL-safe identifier of a vendor (globally unique) or product (unique per vendor),
 * in the style of CPE vendor and product names: `microsoft`, `http_server`, `node.js`.
 */
export const SLUG_PATTERN = /^[a-z0-9][a-z0-9._+-]{0,127}$/;
export const slugSchema = z.string().trim().toLowerCase().regex(SLUG_PATTERN, {
  message: 'must be 1–128 characters of a-z, 0-9 and ._+- starting with a letter or digit',
});

/**
 * Derives a slug from a display name: diacritics removed, lower case, whitespace runs become `_`,
 * other characters outside `[a-z0-9._+-]` are dropped. Returns `null` when nothing is left (for
 * example a name written entirely in a non-Latin script); the caller must then supply a slug.
 */
export function slugify(name: string): string | null {
  const slug = name
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9._+-]/g, '')
    .replace(/^[._+-]+/, '')
    .slice(0, 128);
  return SLUG_PATTERN.test(slug) ? slug : null;
}

/** Whether a catalog entry was entered by a user (`curated`) or created from CVE data. */
export const CATALOG_ORIGINS = ['curated', 'discovered'] as const;
export const catalogOriginSchema = z.enum(CATALOG_ORIGINS);
export type CatalogOrigin = z.infer<typeof catalogOriginSchema>;

/** Product kinds; they correspond to the CPE parts `a`, `o` and `h`. */
export const PRODUCT_TYPES = ['application', 'operating-system', 'hardware', 'unknown'] as const;
export const productTypeSchema = z.enum(PRODUCT_TYPES);
export type ProductType = z.infer<typeof productTypeSchema>;

export function productTypeForCpePart(part: string): ProductType {
  switch (part) {
    case 'a':
      return 'application';
    case 'o':
      return 'operating-system';
    case 'h':
      return 'hardware';
    default:
      return 'unknown';
  }
}

/**
 * Product identifiers other than CPE names: Package URLs, ISO/IEC 19770-2 SWID tag IDs, and
 * vendor-specific identifiers such as SKUs.
 */
export const PRODUCT_IDENTIFIER_TYPES = ['purl', 'swid', 'vendor-sku', 'other'] as const;
export const productIdentifierTypeSchema = z.enum(PRODUCT_IDENTIFIER_TYPES);
export type ProductIdentifierType = z.infer<typeof productIdentifierTypeSchema>;

/** `pkg:type/namespace/name` per the Package URL specification, without version qualifiers. */
const PURL_PATTERN = /^pkg:[a-z][a-z0-9.+-]*\/[^\s?#@]+$/;

export const productIdentifierInputSchema = z
  .strictObject({
    type: productIdentifierTypeSchema,
    value: z
      .string()
      .trim()
      .min(1)
      .max(512)
      .regex(/^[^\p{Cc}]+$/u, { message: 'must not contain control characters' }),
    source: sourceIdentifierSchema.default('manual'),
  })
  .superRefine((value, ctx) => {
    if (value.type === 'purl' && !PURL_PATTERN.test(value.value)) {
      ctx.addIssue({
        code: 'custom',
        path: ['value'],
        message: 'must be a Package URL without version, e.g. pkg:npm/%40scope/name',
      });
    }
  });
export type ProductIdentifierInput = z.output<typeof productIdentifierInputSchema>;

export const productCpeInputSchema = z.strictObject({
  cpe: cpe23Schema,
  source: sourceIdentifierSchema.default('manual'),
});
export type ProductCpeInput = z.output<typeof productCpeInputSchema>;

const descriptionSchema = textSchema(4_000);

// ---------------------------------------------------------------------------- write models

export const createVendorRequestSchema = z.strictObject({
  name: productNameSchema,
  /** Derived from the name when omitted. Immutable once created. */
  slug: slugSchema.optional(),
  description: descriptionSchema.nullable().default(null),
  website: httpReferenceUrlSchema.nullable().default(null),
  source: sourceIdentifierSchema.default('manual'),
});
export type CreateVendorRequest = z.output<typeof createVendorRequestSchema>;

export const updateVendorRequestSchema = z
  .strictObject({
    name: productNameSchema,
    description: descriptionSchema.nullable(),
    website: httpReferenceUrlSchema.nullable(),
  })
  .partial()
  .refine((value) => Object.keys(value).length > 0, { message: 'at least one field is required' });
export type UpdateVendorRequest = z.output<typeof updateVendorRequestSchema>;

export const createProductRequestSchema = z.strictObject({
  vendorId: z.uuid(),
  name: productNameSchema,
  /** Derived from the name when omitted; unique per vendor. Immutable once created. */
  slug: slugSchema.optional(),
  type: productTypeSchema.default('unknown'),
  description: descriptionSchema.nullable().default(null),
  website: httpReferenceUrlSchema.nullable().default(null),
  source: sourceIdentifierSchema.default('manual'),
  cpes: z.array(productCpeInputSchema).max(50).default([]),
  identifiers: z.array(productIdentifierInputSchema).max(50).default([]),
});
export type CreateProductRequest = z.output<typeof createProductRequestSchema>;

export const updateProductRequestSchema = z
  .strictObject({
    name: productNameSchema,
    type: productTypeSchema,
    description: descriptionSchema.nullable(),
    website: httpReferenceUrlSchema.nullable(),
  })
  .partial()
  .refine((value) => Object.keys(value).length > 0, { message: 'at least one field is required' });
export type UpdateProductRequest = z.output<typeof updateProductRequestSchema>;

/** One affected-version range of a CVE-to-product association. */
export const versionRangeInputSchema = z
  .strictObject({
    status: affectedStatusSchema.default('affected'),
    /** CPE 2.3 name the source matched, often version-specific. */
    cpe: cpe23Schema.optional(),
    version: versionTextSchema.optional(),
    versionStartIncluding: versionTextSchema.optional(),
    versionStartExcluding: versionTextSchema.optional(),
    versionEndIncluding: versionTextSchema.optional(),
    versionEndExcluding: versionTextSchema.optional(),
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
export type VersionRangeInput = z.output<typeof versionRangeInputSchema>;

/** Canonical identity of a range, for duplicate detection and change tracking. */
export function versionRangeKey(range: VersionRangeInput): string {
  return JSON.stringify([
    range.status,
    range.cpe ?? null,
    range.version ?? null,
    range.versionStartIncluding ?? null,
    range.versionStartExcluding ?? null,
    range.versionEndIncluding ?? null,
    range.versionEndExcluding ?? null,
  ]);
}

/** `PUT /products/:productId/vulnerabilities/:cveId`: an analyst-maintained association. */
export const setManualAssociationRequestSchema = z
  .strictObject({
    ranges: z.array(versionRangeInputSchema).min(1).max(100),
    note: textSchema(2_000).nullable().default(null),
  })
  .superRefine((value, ctx) => {
    const seen = new Set<string>();
    value.ranges.forEach((range, index) => {
      const key = versionRangeKey(range);
      if (seen.has(key)) {
        ctx.addIssue({ code: 'custom', path: ['ranges', index], message: 'duplicate range' });
      }
      seen.add(key);
    });
  });
export type SetManualAssociationRequest = z.output<typeof setManualAssociationRequestSchema>;

// ---------------------------------------------------------------------------- read models

export const productCpeSchema = z.object({
  id: z.uuid(),
  cpe: z.string(),
  part: z.string(),
  vendor: z.string(),
  product: z.string(),
  version: z.string(),
  source: z.string(),
  createdAt: z.iso.datetime(),
});
export type ProductCpe = z.infer<typeof productCpeSchema>;

export const productIdentifierSchema = z.object({
  id: z.uuid(),
  type: productIdentifierTypeSchema,
  value: z.string(),
  source: z.string(),
  createdAt: z.iso.datetime(),
});
export type ProductIdentifier = z.infer<typeof productIdentifierSchema>;

export const vendorSchema = z.object({
  id: z.uuid(),
  slug: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  website: z.string().nullable(),
  origin: catalogOriginSchema,
  source: z.string(),
  productCount: z.number().int().min(0),
  /** Distinct CVEs with at least one active `affected` association on the vendor's products. */
  cveCount: z.number().int().min(0),
  version: z.number().int().min(1),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
export type Vendor = z.infer<typeof vendorSchema>;

export const vendorRefSchema = z.object({ id: z.uuid(), slug: z.string(), name: z.string() });
export type VendorRef = z.infer<typeof vendorRefSchema>;

export const productSummarySchema = z.object({
  id: z.uuid(),
  slug: z.string(),
  name: z.string(),
  type: productTypeSchema,
  origin: catalogOriginSchema,
  vendor: vendorRefSchema,
  cveCount: z.number().int().min(0),
  updatedAt: z.iso.datetime(),
});
export type ProductSummary = z.infer<typeof productSummarySchema>;

export const productSchema = productSummarySchema.extend({
  description: z.string().nullable(),
  website: z.string().nullable(),
  source: z.string(),
  cpes: z.array(productCpeSchema),
  identifiers: z.array(productIdentifierSchema),
  version: z.number().int().min(1),
  createdAt: z.iso.datetime(),
});
export type Product = z.infer<typeof productSchema>;

export const versionRangeSchema = z.object({
  status: affectedStatusSchema,
  cpe: z.string().nullable(),
  version: z.string().nullable(),
  versionStartIncluding: z.string().nullable(),
  versionStartExcluding: z.string().nullable(),
  versionEndIncluding: z.string().nullable(),
  versionEndExcluding: z.string().nullable(),
});
export type VersionRange = z.infer<typeof versionRangeSchema>;

/** CVE facts mirrored from `cve.record.*` events; `null` until the CVE Service reports the CVE. */
export const cveFactsSchema = z.object({
  state: cveStateSchema,
  severity: recordSeveritySchema,
  cvssScore: z.number().nullable(),
  inKev: z.boolean(),
  epssScore: z.number().nullable(),
  epssPercentile: z.number().nullable(),
  publishedAt: z.iso.datetime().nullable(),
});
export type CveFacts = z.infer<typeof cveFactsSchema>;

export const ASSOCIATION_ORIGINS = ['observation', 'manual'] as const;
export const associationOriginSchema = z.enum(ASSOCIATION_ORIGINS);
export type AssociationOrigin = z.infer<typeof associationOriginSchema>;

export const cveProductAssociationSchema = z.object({
  id: z.uuid(),
  cveId: z.string(),
  product: productSummarySchema.pick({ id: true, slug: true, name: true, type: true }),
  vendor: vendorRefSchema,
  /** Provenance: an intelligence source (`nvd`, `github-advisory`, …) or `manual`. */
  source: z.string(),
  /** Item at the source that reported the association (CVE ID, GHSA ID, …). */
  sourceRecordId: z.string(),
  sourceUrl: z.string().nullable(),
  attribution: z.string().nullable(),
  origin: associationOriginSchema,
  /** `affected` if any range is affected, else `unknown` if any is unknown, else `unaffected`. */
  status: affectedStatusSchema,
  ranges: z.array(versionRangeSchema),
  note: z.string().nullable(),
  firstSeenAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime(),
  /** Set when the source stopped reporting the association (kept for history). */
  withdrawnAt: z.iso.datetime().nullable(),
  cve: cveFactsSchema.nullable(),
  /** Only with `?version=`: whether that version is in an affected range (`null` = unknown). */
  versionAffected: z.boolean().nullable().optional(),
});
export type CveProductAssociation = z.infer<typeof cveProductAssociationSchema>;

export const PRODUCT_HISTORY_CHANGES = [
  'added',
  'ranges-changed',
  'withdrawn',
  'restored',
] as const;
export const productHistoryChangeSchema = z.enum(PRODUCT_HISTORY_CHANGES);
export type ProductHistoryChange = z.infer<typeof productHistoryChangeSchema>;

export const productHistoryEntrySchema = z.object({
  id: z.uuid(),
  productId: z.uuid(),
  cveId: z.string(),
  associationId: z.uuid(),
  change: productHistoryChangeSchema,
  source: z.string(),
  sourceRecordId: z.string(),
  /** Ranges after the change (before it, for `withdrawn`). */
  ranges: z.array(versionRangeSchema),
  occurredAt: z.iso.datetime(),
});
export type ProductHistoryEntry = z.infer<typeof productHistoryEntrySchema>;

const severityCountsShape = Object.fromEntries(
  RECORD_SEVERITIES.map((severity) => [severity, z.number().int().min(0)]),
) as Record<(typeof RECORD_SEVERITIES)[number], z.ZodNumber>;
export const severityCountsSchema = z.object(severityCountsShape);
export type SeverityCounts = z.infer<typeof severityCountsSchema>;

/**
 * Vulnerability analytics of a vendor, computed on request from active `affected` associations.
 * Severity, KEV, CVSS and EPSS come from the mirrored CVE facts; CVEs the CVE Service has not
 * reported yet count as `unknown` severity and are listed in `cvesWithoutFacts`.
 */
export const vendorAnalyticsSchema = z.object({
  vendor: vendorRefSchema,
  productCount: z.number().int().min(0),
  affectedProductCount: z.number().int().min(0),
  cveCount: z.number().int().min(0),
  cvesWithoutFacts: z.number().int().min(0),
  bySeverity: severityCountsSchema,
  kevCount: z.number().int().min(0),
  averageCvssScore: z.number().nullable(),
  maxCvssScore: z.number().nullable(),
  maxEpssScore: z.number().nullable(),
  /** By the year in the CVE ID (always known, unlike the publication date). */
  byCveYear: z.array(z.object({ year: z.number().int(), cveCount: z.number().int() })),
  bySource: z.array(z.object({ source: z.string(), cveCount: z.number().int() })),
  topProducts: z.array(
    z.object({
      id: z.uuid(),
      slug: z.string(),
      name: z.string(),
      cveCount: z.number().int(),
      criticalCount: z.number().int(),
      highCount: z.number().int(),
      kevCount: z.number().int(),
    }),
  ),
  firstAssociatedAt: z.iso.datetime().nullable(),
  lastAssociatedAt: z.iso.datetime().nullable(),
  generatedAt: z.iso.datetime(),
});
export type VendorAnalytics = z.infer<typeof vendorAnalyticsSchema>;

// ---------------------------------------------------------------------------- queries

const orderParam = z.enum(['asc', 'desc']);
const searchText = z.string().trim().min(1).max(200);

export const VENDOR_SORT_FIELDS = [
  'name',
  'createdAt',
  'updatedAt',
  'productCount',
  'cveCount',
] as const;
export const listVendorsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  /** Case-insensitive substring of the name or slug. */
  q: searchText.optional(),
  origin: catalogOriginSchema.optional(),
  sort: z.enum(VENDOR_SORT_FIELDS).default('name'),
  order: orderParam.default('asc'),
});
export type ListVendorsQuery = z.output<typeof listVendorsQuerySchema>;

export const PRODUCT_SORT_FIELDS = ['name', 'createdAt', 'updatedAt', 'cveCount'] as const;
export const listProductsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  q: searchText.optional(),
  vendorId: z.uuid().optional(),
  /** Vendor slug. */
  vendor: slugSchema.optional(),
  type: productTypeSchema.optional(),
  origin: catalogOriginSchema.optional(),
  /** Products with a registered CPE name of the same part, vendor and product. */
  cpe: cpe23Schema.optional(),
  /** Exact product identifier value (a Package URL, SWID tag ID, …). */
  identifier: z.string().trim().min(1).max(512).optional(),
  sort: z.enum(PRODUCT_SORT_FIELDS).default('name'),
  order: orderParam.default('asc'),
});
export type ListProductsQuery = z.output<typeof listProductsQuerySchema>;

export const ASSOCIATION_SORT_FIELDS = [
  'cveId',
  'cvssScore',
  'epssScore',
  'firstSeenAt',
  'lastSeenAt',
] as const;
export type AssociationSortField = (typeof ASSOCIATION_SORT_FIELDS)[number];

const associationFilters = {
  ...paginationQuerySchema.shape,
  source: sourceIdentifierSchema.optional(),
  status: affectedStatusSchema.optional(),
  severity: listParam(recordSeveritySchema, RECORD_SEVERITIES.length).optional(),
  kev: booleanParam.optional(),
  includeWithdrawn: booleanParam.default(false),
  sort: z.enum(ASSOCIATION_SORT_FIELDS).default('cveId'),
  order: orderParam.default('desc'),
};

/** `GET /products/:productId/vulnerabilities`. */
export const listProductVulnerabilitiesQuerySchema = z.strictObject({
  ...associationFilters,
  /** Only associations whose affected ranges contain this version (or cannot tell). */
  version: versionTextSchema.optional(),
});
export type ListProductVulnerabilitiesQuery = z.output<
  typeof listProductVulnerabilitiesQuerySchema
>;

/** `GET /cve-associations`: associations across the catalog. */
export const listCveAssociationsQuerySchema = z.strictObject({
  ...associationFilters,
  cveId: cveIdSchema.optional(),
  productId: z.uuid().optional(),
  vendorId: z.uuid().optional(),
});
export type ListCveAssociationsQuery = z.output<typeof listCveAssociationsQuerySchema>;

export const productHistoryQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  cveId: cveIdSchema.optional(),
  change: productHistoryChangeSchema.optional(),
  order: orderParam.default('desc'),
});
export type ProductHistoryQuery = z.output<typeof productHistoryQuerySchema>;

export const vendorAnalyticsQuerySchema = z.strictObject({
  topProducts: z.coerce.number().int().min(1).max(50).default(10),
});
export type VendorAnalyticsQuery = z.output<typeof vendorAnalyticsQuerySchema>;
