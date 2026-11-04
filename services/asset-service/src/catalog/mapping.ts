import type {
  ProductHistoryChange,
  ProductIdentifierType,
  ProductType,
  Product as ProductView,
  ProductSummary,
  Vendor as VendorView,
  VendorRef,
} from '@cve/contracts';

import type {
  HistoryChange as DbHistoryChange,
  ProductIdentifierType as DbIdentifierType,
  ProductType as DbProductType,
  Prisma,
} from '../generated/prisma/client.js';

// Prisma enum member names cannot contain `-`; the database values (via @map) match the API.

const PRODUCT_TYPES_TO_DB: Readonly<Record<ProductType, DbProductType>> = {
  application: 'application',
  'operating-system': 'operating_system',
  hardware: 'hardware',
  unknown: 'unknown',
};
const IDENTIFIER_TYPES_TO_DB: Readonly<Record<ProductIdentifierType, DbIdentifierType>> = {
  purl: 'purl',
  swid: 'swid',
  'vendor-sku': 'vendor_sku',
  other: 'other',
};
const HISTORY_CHANGES_TO_DB: Readonly<Record<ProductHistoryChange, DbHistoryChange>> = {
  added: 'added',
  'ranges-changed': 'ranges_changed',
  withdrawn: 'withdrawn',
  restored: 'restored',
};

function invert<K extends string, V extends string>(map: Readonly<Record<K, V>>): Record<V, K> {
  return Object.fromEntries(Object.entries(map).map(([k, v]) => [v, k])) as Record<V, K>;
}

const PRODUCT_TYPES_FROM_DB = invert(PRODUCT_TYPES_TO_DB);
const IDENTIFIER_TYPES_FROM_DB = invert(IDENTIFIER_TYPES_TO_DB);
const HISTORY_CHANGES_FROM_DB = invert(HISTORY_CHANGES_TO_DB);

export const toDbProductType = (value: ProductType): DbProductType => PRODUCT_TYPES_TO_DB[value];
export const fromDbProductType = (value: DbProductType): ProductType =>
  PRODUCT_TYPES_FROM_DB[value];
export const toDbIdentifierType = (value: ProductIdentifierType): DbIdentifierType =>
  IDENTIFIER_TYPES_TO_DB[value];
export const fromDbIdentifierType = (value: DbIdentifierType): ProductIdentifierType =>
  IDENTIFIER_TYPES_FROM_DB[value];
export const toDbHistoryChange = (value: ProductHistoryChange): DbHistoryChange =>
  HISTORY_CHANGES_TO_DB[value];
export const fromDbHistoryChange = (value: DbHistoryChange): ProductHistoryChange =>
  HISTORY_CHANGES_FROM_DB[value];

export const productInclude = {
  vendor: { select: { id: true, slug: true, name: true } },
  cpes: { orderBy: { cpe: 'asc' } },
  identifiers: { orderBy: [{ type: 'asc' }, { value: 'asc' }] },
} satisfies Prisma.ProductInclude;

export type ProductRow = Prisma.ProductGetPayload<{ include: typeof productInclude }>;
export type ProductSummaryRow = Prisma.ProductGetPayload<{
  include: { vendor: { select: { id: true; slug: true; name: true } } };
}>;
export type VendorRow = Prisma.VendorGetPayload<object>;

export function toVendorRef(row: { id: string; slug: string; name: string }): VendorRef {
  return { id: row.id, slug: row.slug, name: row.name };
}

export function toVendor(row: VendorRow): VendorView {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    description: row.description,
    website: row.website,
    origin: row.origin,
    source: row.source,
    productCount: row.productCount,
    cveCount: row.cveCount,
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function toProductSummary(row: ProductSummaryRow): ProductSummary {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    type: fromDbProductType(row.type),
    origin: row.origin,
    vendor: toVendorRef(row.vendor),
    cveCount: row.cveCount,
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function toProduct(row: ProductRow): ProductView {
  return {
    ...toProductSummary(row),
    description: row.description,
    website: row.website,
    source: row.source,
    cpes: row.cpes.map((cpe) => ({
      id: cpe.id,
      cpe: cpe.cpe,
      part: cpe.part,
      vendor: cpe.cpeVendor,
      product: cpe.cpeProduct,
      version: cpe.cpeVersion,
      source: cpe.source,
      createdAt: cpe.createdAt.toISOString(),
    })),
    identifiers: row.identifiers.map((identifier) => ({
      id: identifier.id,
      type: fromDbIdentifierType(identifier.type),
      value: identifier.value,
      source: identifier.source,
      createdAt: identifier.createdAt.toISOString(),
    })),
    version: row.version,
    createdAt: row.createdAt.toISOString(),
  };
}
