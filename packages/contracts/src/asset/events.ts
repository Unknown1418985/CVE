import { z } from 'zod';

import { eventActorSchema } from '../cve/events.js';
import { affectedStatusSchema } from '../cve/schemas.js';
import {
  associationOriginSchema,
  catalogOriginSchema,
  productHistoryChangeSchema,
  productTypeSchema,
  versionRangeSchema,
} from './schemas.js';

/** Domain events published by the Asset Service (routing key = event type). */
export const ASSET_EVENT_TYPES = {
  vendorCreated: 'asset.vendor.created',
  vendorUpdated: 'asset.vendor.updated',
  vendorDeleted: 'asset.vendor.deleted',
  productCreated: 'asset.product.created',
  productUpdated: 'asset.product.updated',
  productDeleted: 'asset.product.deleted',
  associationAdded: 'asset.cve-association.added',
  associationUpdated: 'asset.cve-association.updated',
  associationWithdrawn: 'asset.cve-association.withdrawn',
} as const;
export type AssetEventType = (typeof ASSET_EVENT_TYPES)[keyof typeof ASSET_EVENT_TYPES];

export const VENDOR_CHANGE_FIELDS = ['name', 'description', 'website', 'origin'] as const;
export const PRODUCT_CHANGE_FIELDS = [
  'name',
  'type',
  'description',
  'website',
  'origin',
  'cpes',
  'identifiers',
] as const;

export const vendorSnapshotSchema = z.object({
  vendorId: z.uuid(),
  slug: z.string(),
  name: z.string(),
  origin: catalogOriginSchema,
  source: z.string(),
  version: z.number().int().min(1),
});
export type VendorSnapshot = z.infer<typeof vendorSnapshotSchema>;

export const vendorCreatedPayloadSchema = vendorSnapshotSchema.extend({ actor: eventActorSchema });
export const vendorUpdatedPayloadSchema = vendorSnapshotSchema.extend({
  actor: eventActorSchema,
  changedFields: z.array(z.enum(VENDOR_CHANGE_FIELDS)).min(1),
});
export const vendorDeletedPayloadSchema = vendorSnapshotSchema.extend({ actor: eventActorSchema });
export type VendorCreatedPayload = z.infer<typeof vendorCreatedPayloadSchema>;
export type VendorUpdatedPayload = z.infer<typeof vendorUpdatedPayloadSchema>;
export type VendorDeletedPayload = z.infer<typeof vendorDeletedPayloadSchema>;

export const productSnapshotSchema = z.object({
  productId: z.uuid(),
  slug: z.string(),
  name: z.string(),
  type: productTypeSchema,
  origin: catalogOriginSchema,
  source: z.string(),
  vendorId: z.uuid(),
  vendorSlug: z.string(),
  /** Registered CPE 2.3 names, so consumers can match without a lookup. */
  cpes: z.array(z.string()),
  version: z.number().int().min(1),
});
export type ProductSnapshot = z.infer<typeof productSnapshotSchema>;

export const productCreatedPayloadSchema = productSnapshotSchema.extend({
  actor: eventActorSchema,
});
export const productUpdatedPayloadSchema = productSnapshotSchema.extend({
  actor: eventActorSchema,
  changedFields: z.array(z.enum(PRODUCT_CHANGE_FIELDS)).min(1),
});
export const productDeletedPayloadSchema = productSnapshotSchema.extend({
  actor: eventActorSchema,
});
export type ProductCreatedPayload = z.infer<typeof productCreatedPayloadSchema>;
export type ProductUpdatedPayload = z.infer<typeof productUpdatedPayloadSchema>;
export type ProductDeletedPayload = z.infer<typeof productDeletedPayloadSchema>;

/**
 * A CVE-to-product association changed. `change` mirrors the product vulnerability history:
 * `added` and `restored` are published as `…added`, `ranges-changed` as `…updated`, and
 * `withdrawn` as `…withdrawn`.
 */
export const cveAssociationChangedPayloadSchema = z.object({
  associationId: z.uuid(),
  cveId: z.string(),
  productId: z.uuid(),
  productSlug: z.string(),
  vendorId: z.uuid(),
  vendorSlug: z.string(),
  source: z.string(),
  sourceRecordId: z.string(),
  origin: associationOriginSchema,
  change: productHistoryChangeSchema,
  status: affectedStatusSchema,
  ranges: z.array(versionRangeSchema),
  actor: eventActorSchema,
});
export type CveAssociationChangedPayload = z.infer<typeof cveAssociationChangedPayloadSchema>;
