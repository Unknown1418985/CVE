import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  apiErrorResponseSchema,
  cveProductAssociationSchema,
  domainEventEnvelopeSchema,
  paginationMetaSchema,
  productHistoryEntrySchema,
  productSchema,
  productSummarySchema,
  vendorAnalyticsSchema,
  vendorSchema,
  type CveProductAssociation,
  type Product,
  type Role,
  type Vendor,
} from '@cve/contracts';
import { createLogger } from '@cve/logger';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';
import { z } from 'zod';

import { ObservationApplier } from '../../src/associations/observation-applier.js';
import { CveFactsProjector } from '../../src/events/cve-facts.projector.js';
import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { removeExpiredProcessedEvents } from '../../src/runtime.js';
import { startAssetApp } from '../support.js';
import {
  assetDatabaseUrl,
  cveDeletedEvent,
  cveRecordEvent,
  migrate,
  observationEvent,
  removeSyntheticData,
  syntheticCveId,
} from './support.js';

// Everything here is synthetic test data (see support.ts), not real vulnerability data.

let prisma: PrismaClient;
let issuer: TestTokenIssuer;
let t: HttpTestApp;
let analyst: Record<string, string>;
let viewer: Record<string, string>;
let observations: ObservationApplier;
let facts: CveFactsProjector;

const logger = createLogger({ service: 'asset-service', level: 'silent' });
const errorOf = (body: unknown) => apiErrorResponseSchema.parse(body).error;
const dataOf = <T extends z.ZodType>(schema: T, body: unknown): z.infer<T> =>
  schema.parse((body as { data: unknown }).data);
const pageOf = <T extends z.ZodType>(schema: T, body: unknown) =>
  z.object({ data: z.array(schema), meta: paginationMetaSchema }).parse(body);

async function headersFor(roles: Role[], username: string) {
  const token = await issuer.tokenFor(randomUUID(), roles, { preferred_username: username });
  return { authorization: `Bearer ${token}` };
}

async function outboxTypes(): Promise<string[]> {
  const rows = await prisma.outboxEvent.findMany({ orderBy: { createdAt: 'asc' } });
  return rows
    .filter((row) => /zz_test|CVE-2026-9\d{5}/.test(JSON.stringify(row.envelope)))
    .map((row) => row.eventType);
}

async function createVendor(name: string, extra: Record<string, unknown> = {}): Promise<Vendor> {
  const res = await t.http
    .post('/api/v1/vendors')
    .set(analyst)
    .send({ name, ...extra })
    .expect(201);
  return dataOf(vendorSchema, res.body);
}

async function createProduct(
  vendorId: string,
  name: string,
  extra: Record<string, unknown> = {},
): Promise<Product> {
  const res = await t.http
    .post('/api/v1/products')
    .set(analyst)
    .send({ vendorId, name, ...extra })
    .expect(201);
  return dataOf(productSchema, res.body);
}

async function vulnerabilities(productId: string, query = ''): Promise<CveProductAssociation[]> {
  const res = await t.http
    .get(`/api/v1/products/${productId}/vulnerabilities${query}`)
    .set(viewer)
    .expect(200);
  return pageOf(cveProductAssociationSchema, res.body).data;
}

beforeAll(async () => {
  const url = assetDatabaseUrl();
  migrate(url);
  prisma = createPrismaClient(url);
  await prisma.$connect();
  issuer = await createTestTokenIssuer();
  t = await startAssetApp(issuer, { prisma });
  analyst = await headersFor(['security-analyst'], 'analyst-user');
  viewer = await headersFor(['viewer'], 'viewer-user');
  observations = new ObservationApplier(prisma, logger);
  facts = new CveFactsProjector(prisma, logger);
});

afterAll(async () => {
  await removeSyntheticData(prisma);
  await t.close();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await removeSyntheticData(prisma);
});

describe('vendor management', () => {
  it('creates, reads, updates and deletes a vendor with outbox events', async () => {
    const res = await t.http
      .post('/api/v1/vendors')
      .set(analyst)
      .set('x-correlation-id', 'corr-vendor-1')
      .send({ name: 'ZZ Test Acme', website: 'https://acme.example' })
      .expect(201);
    const vendor = dataOf(vendorSchema, res.body);
    expect(vendor).toMatchObject({
      slug: 'zz_test_acme',
      origin: 'curated',
      source: 'manual',
      version: 1,
      productCount: 0,
      cveCount: 0,
      website: 'https://acme.example/',
    });
    expect(res.headers['location']).toBe(`/api/v1/vendors/${vendor.id}`);
    expect(res.headers['etag']).toBe('"1"');

    const got = await t.http.get(`/api/v1/vendors/${vendor.id}`).set(viewer).expect(200);
    expect(dataOf(vendorSchema, got.body).name).toBe('ZZ Test Acme');

    await t.http
      .patch(`/api/v1/vendors/${vendor.id}`)
      .set(analyst)
      .set('if-match', '"7"')
      .send({ description: 'Synthetic vendor' })
      .expect(412);
    const patched = await t.http
      .patch(`/api/v1/vendors/${vendor.id}`)
      .set(analyst)
      .set('if-match', '"1"')
      .send({ description: 'Synthetic vendor' })
      .expect(200);
    expect(patched.headers['etag']).toBe('"2"');
    // An identical patch is a no-op.
    const again = await t.http
      .patch(`/api/v1/vendors/${vendor.id}`)
      .set(analyst)
      .send({ description: 'Synthetic vendor' })
      .expect(200);
    expect(again.headers['etag']).toBe('"2"');

    await t.http.delete(`/api/v1/vendors/${vendor.id}`).set(analyst).expect(204);
    await t.http.get(`/api/v1/vendors/${vendor.id}`).set(viewer).expect(404);

    expect(await outboxTypes()).toEqual([
      'asset.vendor.created',
      'asset.vendor.updated',
      'asset.vendor.deleted',
    ]);
    const created = await prisma.outboxEvent.findFirstOrThrow({
      where: { eventType: 'asset.vendor.created' },
      orderBy: { createdAt: 'desc' },
    });
    const envelope = domainEventEnvelopeSchema.parse(created.envelope);
    expect(envelope).toMatchObject({ producer: 'asset-service', correlationId: 'corr-vendor-1' });
    expect(envelope.payload).toMatchObject({
      slug: 'zz_test_acme',
      actor: { type: 'user', username: 'analyst-user' },
    });
  });

  it('rejects duplicate slugs and slugs that cannot be derived', async () => {
    await createVendor('ZZ Test Dup');
    const res = await t.http
      .post('/api/v1/vendors')
      .set(analyst)
      .send({ name: 'zz test DUP' })
      .expect(409);
    expect(errorOf(res.body).details?.[0]?.path).toBe('slug');
    await t.http.post('/api/v1/vendors').set(analyst).send({ name: '中文' }).expect(400);
    await createVendor('中文', { slug: 'zz_test_zhongwen' });
  });

  it('searches, filters and sorts vendors', async () => {
    await createVendor('ZZ Test Beta 100%');
    await createVendor('ZZ Test Alpha');
    await createVendor('ZZ Test Gamma');
    const res = await t.http
      .get('/api/v1/vendors?q=zz test&sort=name&order=desc&pageSize=2')
      .set(viewer)
      .expect(200);
    const page = pageOf(vendorSchema, res.body);
    expect(page.data.map((v) => v.name)).toEqual(['ZZ Test Gamma', 'ZZ Test Beta 100%']);
    expect(page.meta).toEqual({ page: 1, pageSize: 2, totalItems: 3, totalPages: 2 });
    // LIKE wildcards in the search text are literal.
    const literal = await t.http.get('/api/v1/vendors?q=100%25').set(viewer).expect(200);
    expect(pageOf(vendorSchema, literal.body).data.map((v) => v.name)).toEqual([
      'ZZ Test Beta 100%',
    ]);
    const bySlug = await t.http.get('/api/v1/vendors?q=zz_test_al').set(viewer).expect(200);
    expect(pageOf(vendorSchema, bySlug.body).data).toHaveLength(1);
  });

  it('refuses to delete a vendor that has products', async () => {
    const vendor = await createVendor('ZZ Test Keep');
    await createProduct(vendor.id, 'ZZ Test Thing');
    const res = await t.http.delete(`/api/v1/vendors/${vendor.id}`).set(analyst).expect(409);
    expect(errorOf(res.body).message).toMatch(/1 product/);
  });
});

describe('product management, CPE names and identifiers', () => {
  it('creates a product with CPE names and identifiers and derives its type', async () => {
    const vendor = await createVendor('ZZ Test Acme');
    const product = await createProduct(vendor.id, 'ZZ Test Widget', {
      cpes: [{ cpe: 'cpe:2.3:o:ZZ_TEST_ACME:zz_test_widget:*:*:*:*:*:*:*:*' }],
      identifiers: [
        { type: 'purl', value: 'pkg:npm/zz-test-widget' },
        { type: 'vendor-sku', value: 'ZZ-SKU-1' },
      ],
    });
    expect(product).toMatchObject({
      slug: 'zz_test_widget',
      type: 'operating-system',
      vendor: { id: vendor.id, slug: 'zz_test_acme' },
      cpes: [{ cpe: 'cpe:2.3:o:zz_test_acme:zz_test_widget:*:*:*:*:*:*:*:*', part: 'o' }],
    });
    expect(product.identifiers.map((i) => i.type).sort()).toEqual(['purl', 'vendor-sku']);

    const got = await t.http.get(`/api/v1/vendors/${vendor.id}`).set(viewer).expect(200);
    expect(dataOf(vendorSchema, got.body).productCount).toBe(1);

    // Duplicate slug for the vendor, CPE or identifier owned by another product: 409.
    await t.http
      .post('/api/v1/products')
      .set(analyst)
      .send({ vendorId: vendor.id, name: 'zz test widget' })
      .expect(409);
    const other = await createProduct(vendor.id, 'ZZ Test Gadget');
    const taken = await t.http
      .post(`/api/v1/products/${other.id}/cpes`)
      .set(analyst)
      .send({ cpe: 'cpe:2.3:o:zz_test_acme:zz_test_widget:*:*:*:*:*:*:*:*' })
      .expect(409);
    expect(errorOf(taken.body).details?.[0]?.path).toBe('cpe');
    await t.http
      .post(`/api/v1/products/${other.id}/identifiers`)
      .set(analyst)
      .send({ type: 'purl', value: 'pkg:npm/zz-test-widget' })
      .expect(409);
    // The failed request left no partial writes behind.
    const unchanged = await t.http.get(`/api/v1/products/${other.id}`).set(viewer).expect(200);
    expect(dataOf(productSchema, unchanged.body)).toMatchObject({ version: 1, cpes: [] });

    await t.http
      .post('/api/v1/products')
      .set(analyst)
      .send({ vendorId: randomUUID(), name: 'ZZ Test Orphan' })
      .expect(400);
  });

  it('adds and removes CPE names and identifiers idempotently', async () => {
    const vendor = await createVendor('ZZ Test Acme');
    const product = await createProduct(vendor.id, 'ZZ Test Widget');
    const cpe = 'cpe:2.3:a:zz_test_acme:zz_test_widget:*:*:*:*:*:*:*:*';
    const added = await t.http
      .post(`/api/v1/products/${product.id}/cpes`)
      .set(analyst)
      .send({ cpe })
      .expect(201);
    expect(added.headers['etag']).toBe('"2"');
    const repeated = await t.http
      .post(`/api/v1/products/${product.id}/cpes`)
      .set(analyst)
      .send({ cpe })
      .expect(200);
    expect(repeated.headers['etag']).toBe('"2"');
    const cpeId = dataOf(productSchema, repeated.body).cpes[0]?.id ?? '';
    const removed = await t.http
      .delete(`/api/v1/products/${product.id}/cpes/${cpeId}`)
      .set(analyst)
      .expect(200);
    expect(dataOf(productSchema, removed.body).cpes).toEqual([]);
    await t.http.delete(`/api/v1/products/${product.id}/cpes/${cpeId}`).set(analyst).expect(404);

    const withId = await t.http
      .post(`/api/v1/products/${product.id}/identifiers`)
      .set(analyst)
      .send({ type: 'swid', value: 'zz-test-swid-tag' })
      .expect(201);
    const identifierId = dataOf(productSchema, withId.body).identifiers[0]?.id ?? '';
    await t.http
      .delete(`/api/v1/products/${product.id}/identifiers/${identifierId}`)
      .set(analyst)
      .expect(200);

    expect((await outboxTypes()).filter((type) => type === 'asset.product.updated')).toHaveLength(
      4,
    );
  });

  it('searches products by name, vendor, type, CPE and identifier', async () => {
    const acme = await createVendor('ZZ Test Acme');
    const globex = await createVendor('ZZ Test Globex');
    const widget = await createProduct(acme.id, 'ZZ Test Widget', {
      cpes: [{ cpe: 'cpe:2.3:a:zz_test_acme:zz_test_widget:*:*:*:*:*:*:*:*' }],
      identifiers: [{ type: 'purl', value: 'pkg:npm/zz-test-widget' }],
    });
    await createProduct(acme.id, 'ZZ Test Router', { type: 'hardware' });
    await createProduct(globex.id, 'ZZ Test Widget');

    const search = async (query: string) => {
      const res = await t.http.get(`/api/v1/products?${query}`).set(viewer).expect(200);
      return pageOf(productSummarySchema, res.body);
    };
    expect((await search('q=widget')).meta.totalItems).toBe(2);
    expect((await search('q=widget&vendor=zz_test_acme')).data.map((p) => p.id)).toEqual([
      widget.id,
    ]);
    expect((await search(`vendorId=${acme.id}&type=hardware`)).data.map((p) => p.name)).toEqual([
      'ZZ Test Router',
    ]);
    // A version-specific CPE name matches the product-level registration.
    const byCpe = await search(
      `cpe=${encodeURIComponent('cpe:2.3:a:zz_test_acme:zz_test_widget:1.2.3:*:*:*:*:*:*:*')}`,
    );
    expect(byCpe.data.map((p) => p.id)).toEqual([widget.id]);
    expect(
      (
        await search(
          `cpe=${encodeURIComponent('cpe:2.3:h:zz_test_acme:zz_test_widget:*:*:*:*:*:*:*:*')}`,
        )
      ).data,
    ).toEqual([]);
    expect(
      (await search(`identifier=${encodeURIComponent('pkg:npm/zz-test-widget')}`)).data,
    ).toHaveLength(1);

    const vendorProducts = await t.http
      .get(`/api/v1/vendors/${acme.id}/products?sort=name&order=desc`)
      .set(viewer)
      .expect(200);
    expect(pageOf(productSummarySchema, vendorProducts.body).data.map((p) => p.name)).toEqual([
      'ZZ Test Widget',
      'ZZ Test Router',
    ]);
    await t.http.get(`/api/v1/vendors/${randomUUID()}/products`).set(viewer).expect(404);
  });

  it('updates a product with optimistic concurrency', async () => {
    const vendor = await createVendor('ZZ Test Acme');
    const product = await createProduct(vendor.id, 'ZZ Test Widget');
    await t.http
      .patch(`/api/v1/products/${product.id}`)
      .set(analyst)
      .set('if-match', '"2"')
      .send({ type: 'application' })
      .expect(412);
    const res = await t.http
      .patch(`/api/v1/products/${product.id}`)
      .set(analyst)
      .set('if-match', '"1"')
      .send({ type: 'application', website: 'https://widget.example' })
      .expect(200);
    expect(dataOf(productSchema, res.body)).toMatchObject({
      type: 'application',
      website: 'https://widget.example/',
      version: 2,
    });
  });
});

describe('CVE-to-product associations from intelligence observations', () => {
  it('discovers vendors and products and records version ranges', async () => {
    const cveId = syntheticCveId(1);
    const outcome = await observations.apply(
      observationEvent({
        cveId,
        revision: 1,
        products: [
          {
            vendor: 'zz_test_acme',
            product: 'zz_test_widget',
            cpe: 'cpe:2.3:a:zz_test_acme:zz_test_widget:*:*:*:*:*:*:*:*',
            versionStartIncluding: '1.0.0',
            versionEndExcluding: '1.4.2',
          },
          {
            vendor: 'zz_test_acme',
            product: 'zz_test_widget',
            cpe: 'cpe:2.3:a:zz_test_acme:zz_test_widget:2.0:*:*:*:*:*:*:*',
            version: '2.0',
          },
          {
            vendor: 'zz_test_acme',
            product: 'zz_test_firmware',
            cpe: 'cpe:2.3:o:zz_test_acme:zz_test_firmware:*:*:*:*:*:*:*:*',
            status: 'unaffected',
          },
          { vendor: 'n/a', product: 'zz_test_unknown_vendor' },
        ],
      }),
    );
    expect(outcome).toEqual({ kind: 'applied', changes: 2, products: 2, skipped: 1 });

    const vendors = await t.http.get('/api/v1/vendors?q=zz_test_acme').set(viewer).expect(200);
    const [vendor] = pageOf(vendorSchema, vendors.body).data;
    expect(vendor).toMatchObject({
      origin: 'discovered',
      source: 'nvd',
      productCount: 2,
      cveCount: 1,
    });
    const products = await t.http
      .get(`/api/v1/products?vendorId=${vendor?.id ?? ''}&sort=name`)
      .set(viewer)
      .expect(200);
    const [firmware, widget] = pageOf(productSummarySchema, products.body).data;
    expect(widget).toMatchObject({ slug: 'zz_test_widget', type: 'application', cveCount: 1 });
    expect(firmware).toMatchObject({ type: 'operating-system', cveCount: 0 });
    const widgetDetail = await t.http
      .get(`/api/v1/products/${widget?.id ?? ''}`)
      .set(viewer)
      .expect(200);
    expect(dataOf(productSchema, widgetDetail.body).cpes.map((c) => c.cpe)).toEqual([
      'cpe:2.3:a:zz_test_acme:zz_test_widget:*:*:*:*:*:*:*:*',
    ]);

    const [association] = await vulnerabilities(widget?.id ?? '');
    expect(association).toMatchObject({
      cveId,
      source: 'nvd',
      sourceRecordId: cveId,
      origin: 'observation',
      status: 'affected',
      attribution: 'Synthetic integration test data',
      withdrawnAt: null,
      cve: null,
    });
    expect(association?.ranges).toHaveLength(2);

    // The firmware association is stored with status unaffected and excluded from counts.
    const firmwareVulns = await vulnerabilities(firmware?.id ?? '');
    expect(firmwareVulns.map((a) => a.status)).toEqual(['unaffected']);

    expect(await outboxTypes()).toEqual([
      'asset.vendor.created',
      'asset.product.created',
      'asset.product.created',
      'asset.cve-association.added',
      'asset.cve-association.added',
    ]);
  });

  it('matches observations to curated products by CPE name before names', async () => {
    const vendor = await createVendor('ZZ Test Curated Vendor');
    const product = await createProduct(vendor.id, 'ZZ Test Curated Name', {
      cpes: [{ cpe: 'cpe:2.3:a:zz_test_cpe_vendor:zz_test_cpe_product:*:*:*:*:*:*:*:*' }],
    });
    await observations.apply(
      observationEvent({
        cveId: syntheticCveId(2),
        revision: 1,
        products: [
          {
            vendor: 'zz_test_cpe_vendor',
            product: 'zz_test_cpe_product',
            cpe: 'cpe:2.3:a:zz_test_cpe_vendor:zz_test_cpe_product:3.1:*:*:*:*:*:*:*',
          },
        ],
      }),
    );
    expect((await vulnerabilities(product.id)).map((a) => a.cveId)).toEqual([syntheticCveId(2)]);
    expect(await prisma.vendor.count({ where: { slug: 'zz_test_cpe_vendor' } })).toBe(0);
  });

  it('registers Package URLs for GitHub advisory packages and matches by them', async () => {
    const first = observationEvent({
      cveId: syntheticCveId(3),
      source: 'github-advisory',
      sourceRecordId: 'GHSA-zzzz-test-0001',
      revision: 1,
      products: [{ vendor: 'npm', product: 'zz_test-pkg', versionEndExcluding: '4.17.21' }],
    });
    await observations.apply(first);
    const found = await t.http
      .get(`/api/v1/products?identifier=${encodeURIComponent('pkg:npm/zz_test-pkg')}`)
      .set(viewer)
      .expect(200);
    const [product] = pageOf(productSummarySchema, found.body).data;
    expect(product).toMatchObject({ type: 'application', vendor: { slug: 'npm' } });
    const [association] = await vulnerabilities(product?.id ?? '');
    expect(association).toMatchObject({
      source: 'github-advisory',
      sourceRecordId: 'GHSA-zzzz-test-0001',
    });
  });

  it('replaces the set on a newer revision, withdraws and restores, and keeps history', async () => {
    const cveId = syntheticCveId(4);
    const widget = {
      vendor: 'zz_test_acme',
      product: 'zz_test_widget',
      versionEndExcluding: '2.0',
    };
    const gadget = { vendor: 'zz_test_acme', product: 'zz_test_gadget' };
    await observations.apply(observationEvent({ cveId, revision: 1, products: [widget, gadget] }));

    // Revision 2: widget range changes, gadget disappears.
    await observations.apply(
      observationEvent({
        cveId,
        revision: 2,
        products: [{ ...widget, versionEndExcluding: '2.1' }],
      }),
    );
    // Revision 1 again (late delivery) and an exact redelivery are ignored.
    const late = observationEvent({ cveId, revision: 1, products: [] });
    expect(await observations.apply(late)).toEqual({ kind: 'stale', storedRevision: 2 });
    expect(await observations.apply(late)).toEqual({ kind: 'duplicate' });

    const widgetId = (await prisma.product.findFirstOrThrow({ where: { slug: 'zz_test_widget' } }))
      .id;
    const gadgetId = (await prisma.product.findFirstOrThrow({ where: { slug: 'zz_test_gadget' } }))
      .id;
    const [current] = await vulnerabilities(widgetId);
    expect(current?.ranges.map((r) => r.versionEndExcluding)).toEqual(['2.1']);
    expect(await vulnerabilities(gadgetId)).toEqual([]);
    const withdrawn = await vulnerabilities(gadgetId, '?includeWithdrawn=true');
    expect(withdrawn[0]?.withdrawnAt).not.toBeNull();

    // Revision 3: gadget comes back.
    await observations.apply(observationEvent({ cveId, revision: 3, products: [widget, gadget] }));
    expect(await vulnerabilities(gadgetId)).toHaveLength(1);

    const history = await t.http
      .get(`/api/v1/products/${gadgetId}/vulnerability-history?order=asc`)
      .set(viewer)
      .expect(200);
    expect(pageOf(productHistoryEntrySchema, history.body).data.map((h) => h.change)).toEqual([
      'added',
      'withdrawn',
      'restored',
    ]);
    const widgetHistory = await t.http
      .get(`/api/v1/products/${widgetId}/vulnerability-history?change=ranges-changed`)
      .set(viewer)
      .expect(200);
    const changes = pageOf(productHistoryEntrySchema, widgetHistory.body).data;
    expect(changes.map((h) => h.ranges[0]?.versionEndExcluding)).toEqual(['2.0', '2.1']);

    const types = await outboxTypes();
    expect(types.filter((type) => type === 'asset.cve-association.withdrawn')).toHaveLength(1);
    expect(types.filter((type) => type === 'asset.cve-association.updated')).toHaveLength(2);
  });

  it('keeps associations of different sources apart', async () => {
    const cveId = syntheticCveId(5);
    const product = { vendor: 'zz_test_acme', product: 'zz_test_widget' };
    await observations.apply(observationEvent({ cveId, revision: 1, products: [product] }));
    await observations.apply(
      observationEvent({ cveId, source: 'mitre-cve', revision: 1, products: [product] }),
    );
    // NVD drops the product; MITRE still reports it.
    await observations.apply(observationEvent({ cveId, revision: 2, products: [] }));
    const res = await t.http.get(`/api/v1/cve-associations?cveId=${cveId}`).set(viewer).expect(200);
    expect(pageOf(cveProductAssociationSchema, res.body).data.map((a) => a.source)).toEqual([
      'mitre-cve',
    ]);
    const all = await t.http
      .get(`/api/v1/cve-associations?cveId=${cveId}&includeWithdrawn=true&source=nvd`)
      .set(viewer)
      .expect(200);
    expect(pageOf(cveProductAssociationSchema, all.body).data).toHaveLength(1);
    const vendor = await prisma.vendor.findUniqueOrThrow({ where: { slug: 'zz_test_acme' } });
    expect(vendor.cveCount).toBe(1);
  });
});

describe('CVE facts, filters and version matching', () => {
  async function seed(): Promise<string> {
    const products = (end: string) => [
      { vendor: 'zz_test_acme', product: 'zz_test_widget', versionEndExcluding: end },
    ];
    await observations.apply(
      observationEvent({ cveId: syntheticCveId(10), revision: 1, products: products('1.5') }),
    );
    await observations.apply(
      observationEvent({ cveId: syntheticCveId(11), revision: 1, products: products('3.0') }),
    );
    await observations.apply(
      observationEvent({ cveId: syntheticCveId(12), revision: 1, products: products('*') }),
    );
    const recordId = randomUUID();
    await facts.apply(
      cveRecordEvent(syntheticCveId(10), {
        recordId,
        version: 1,
        severity: 'critical',
        cvssScore: 9.8,
        inKev: true,
        epssScore: 0.5,
        epssPercentile: 0.9,
      }),
    );
    await facts.apply(
      cveRecordEvent(syntheticCveId(11), {
        recordId: randomUUID(),
        version: 1,
        severity: 'medium',
        cvssScore: 5.4,
      }),
    );
    return (await prisma.product.findFirstOrThrow({ where: { slug: 'zz_test_widget' } })).id;
  }

  it('joins mirrored CVE facts and filters and sorts by them', async () => {
    const productId = await seed();
    const all = await vulnerabilities(productId, '?sort=cvssScore&order=desc');
    expect(all.map((a) => [a.cveId, a.cve?.severity ?? null])).toEqual([
      [syntheticCveId(10), 'critical'],
      [syntheticCveId(11), 'medium'],
      [syntheticCveId(12), null],
    ]);
    expect((await vulnerabilities(productId, '?kev=true')).map((a) => a.cveId)).toEqual([
      syntheticCveId(10),
    ]);
    expect(
      (await vulnerabilities(productId, '?severity=medium,unknown&sort=cveId&order=asc')).map(
        (a) => a.cveId,
      ),
    ).toEqual([syntheticCveId(11), syntheticCveId(12)]);
  });

  it('filters by an installed version', async () => {
    const productId = await seed();
    const affected = await vulnerabilities(productId, '?version=2.0&sort=cveId&order=asc');
    expect(affected.map((a) => [a.cveId, a.versionAffected])).toEqual([
      [syntheticCveId(11), true],
      // `*` as a bound cannot be compared: listed with versionAffected null, not hidden.
      [syntheticCveId(12), null],
    ]);
    const res = await t.http
      .get(`/api/v1/products/${productId}/vulnerabilities?version=1.0&pageSize=1`)
      .set(viewer)
      .expect(200);
    expect(pageOf(cveProductAssociationSchema, res.body).meta.totalItems).toBe(3);
  });

  it('applies CVE record events in order and honours deletions', async () => {
    const cveId = syntheticCveId(20);
    const recordId = randomUUID();
    expect(
      await facts.apply(cveRecordEvent(cveId, { recordId, version: 2, severity: 'high' })),
    ).toBe('applied');
    // An older version arriving late is ignored.
    expect(
      await facts.apply(cveRecordEvent(cveId, { recordId, version: 1, severity: 'low' })),
    ).toBe('stale');
    const duplicate = cveRecordEvent(cveId, { recordId, version: 3, severity: 'critical' });
    expect(await facts.apply(duplicate)).toBe('applied');
    expect(await facts.apply(duplicate)).toBe('duplicate');
    expect(await facts.apply(cveDeletedEvent(cveId, recordId, 3))).toBe('applied');
    const stored = await prisma.cveFact.findUniqueOrThrow({ where: { cveId } });
    expect(stored).toMatchObject({ severity: 'critical', recordVersion: 3 });
    expect(stored.deletedAt).not.toBeNull();
    // A deleted-then-recreated CVE has a new record ID and a later event time.
    expect(
      await facts.apply(
        cveRecordEvent(cveId, { recordId: randomUUID(), version: 1, severity: 'low' }),
      ),
    ).toBe('applied');
    expect((await prisma.cveFact.findUniqueOrThrow({ where: { cveId } })).deletedAt).toBeNull();
    // A deletion of an unknown CVE leaves a tombstone.
    expect(await facts.apply(cveDeletedEvent(syntheticCveId(21), randomUUID(), 1))).toBe('applied');
  });
});

describe('vendor vulnerability analytics', () => {
  it('aggregates severity, KEV, CVSS, EPSS, years, sources and top products', async () => {
    await observations.apply(
      observationEvent({
        cveId: syntheticCveId(30),
        revision: 1,
        products: [
          { vendor: 'zz_test_acme', product: 'zz_test_widget' },
          { vendor: 'zz_test_acme', product: 'zz_test_gadget' },
        ],
      }),
    );
    await observations.apply(
      observationEvent({
        cveId: syntheticCveId(31),
        revision: 1,
        products: [{ vendor: 'zz_test_acme', product: 'zz_test_widget' }],
      }),
    );
    await observations.apply(
      observationEvent({
        cveId: syntheticCveId(31),
        source: 'mitre-cve',
        revision: 1,
        products: [{ vendor: 'zz_test_acme', product: 'zz_test_widget' }],
      }),
    );
    await observations.apply(
      observationEvent({
        cveId: syntheticCveId(32),
        revision: 1,
        products: [{ vendor: 'zz_test_acme', product: 'zz_test_gadget', status: 'unaffected' }],
      }),
    );
    await facts.apply(
      cveRecordEvent(syntheticCveId(30), {
        recordId: randomUUID(),
        version: 1,
        severity: 'critical',
        cvssScore: 9.8,
        inKev: true,
        epssScore: 0.75,
      }),
    );
    await facts.apply(
      cveRecordEvent(syntheticCveId(31), {
        recordId: randomUUID(),
        version: 1,
        severity: 'high',
        cvssScore: 7.5,
        epssScore: 0.1,
      }),
    );
    const vendor = await prisma.vendor.findUniqueOrThrow({ where: { slug: 'zz_test_acme' } });
    const res = await t.http
      .get(`/api/v1/vendors/${vendor.id}/analytics?topProducts=1`)
      .set(viewer)
      .expect(200);
    const analytics = dataOf(vendorAnalyticsSchema, res.body);
    expect(analytics).toMatchObject({
      productCount: 2,
      affectedProductCount: 2,
      cveCount: 2,
      cvesWithoutFacts: 0,
      bySeverity: { critical: 1, high: 1, medium: 0, low: 0, none: 0, unknown: 0 },
      kevCount: 1,
      averageCvssScore: 8.65,
      maxCvssScore: 9.8,
      maxEpssScore: 0.75,
      byCveYear: [{ year: 2026, cveCount: 2 }],
      bySource: [
        { source: 'nvd', cveCount: 2 },
        { source: 'mitre-cve', cveCount: 1 },
      ],
      topProducts: [
        {
          slug: 'zz_test_widget',
          cveCount: 2,
          criticalCount: 1,
          highCount: 1,
          kevCount: 1,
        },
      ],
    });
    expect(analytics.firstAssociatedAt).not.toBeNull();

    const sorted = await t.http
      .get('/api/v1/vendors?q=zz_test&sort=cveCount&order=desc')
      .set(viewer);
    expect(pageOf(vendorSchema, sorted.body).data[0]).toMatchObject({ cveCount: 2 });
    await t.http.get(`/api/v1/vendors/${randomUUID()}/analytics`).set(viewer).expect(404);
  });

  it('returns zeros for a vendor without associations', async () => {
    const vendor = await createVendor('ZZ Test Empty');
    const res = await t.http.get(`/api/v1/vendors/${vendor.id}/analytics`).set(viewer).expect(200);
    expect(dataOf(vendorAnalyticsSchema, res.body)).toMatchObject({
      cveCount: 0,
      averageCvssScore: null,
      byCveYear: [],
      topProducts: [],
      firstAssociatedAt: null,
    });
  });
});

describe('manual associations', () => {
  it('sets, replaces and withdraws an analyst-maintained association', async () => {
    const vendor = await createVendor('ZZ Test Acme');
    const product = await createProduct(vendor.id, 'ZZ Test Widget');
    const cveId = syntheticCveId(40);
    const path = `/api/v1/products/${product.id}/vulnerabilities/${cveId.toLowerCase()}`;

    const created = await t.http
      .put(path)
      .set(analyst)
      .send({ ranges: [{ versionEndExcluding: '5.0' }], note: 'Confirmed in lab' })
      .expect(201);
    expect(dataOf(cveProductAssociationSchema, created.body)).toMatchObject({
      cveId,
      source: 'manual',
      origin: 'manual',
      note: 'Confirmed in lab',
    });
    // Same ranges again: 200 and no new history entry.
    await t.http
      .put(path)
      .set(analyst)
      .send({ ranges: [{ versionEndExcluding: '5.0' }], note: 'Confirmed in lab' })
      .expect(200);
    const replaced = await t.http
      .put(path)
      .set(analyst)
      .send({ ranges: [{ versionEndExcluding: '5.1' }, { version: '6.0-beta' }] })
      .expect(200);
    expect(dataOf(cveProductAssociationSchema, replaced.body).ranges).toHaveLength(2);

    await t.http.delete(path).set(viewer).expect(403);
    await t.http.delete(path).set(analyst).expect(204);
    await t.http.delete(path).set(analyst).expect(404);
    expect(await vulnerabilities(product.id)).toEqual([]);

    const history = await t.http
      .get(`/api/v1/products/${product.id}/vulnerability-history?order=asc`)
      .set(viewer)
      .expect(200);
    expect(pageOf(productHistoryEntrySchema, history.body).data.map((h) => h.change)).toEqual([
      'added',
      'ranges-changed',
      'withdrawn',
    ]);
    // A product with associations (even withdrawn ones) keeps its history: delete is refused.
    await t.http.delete(`/api/v1/products/${product.id}`).set(analyst).expect(409);
    await t.http
      .put(`/api/v1/products/${randomUUID()}/vulnerabilities/${cveId}`)
      .set(analyst)
      .send({ ranges: [{ version: '1.0' }] })
      .expect(404);
  });
});

describe('maintenance', () => {
  it('removes expired processed-event entries only', async () => {
    const old = randomUUID();
    const recent = randomUUID();
    await prisma.processedEvent.createMany({
      data: [
        { consumer: 'zz-test', eventId: old, processedAt: new Date('2020-01-01T00:00:00Z') },
        { consumer: 'zz-test', eventId: recent },
      ],
    });
    expect(await removeExpiredProcessedEvents(prisma, 30)).toBeGreaterThanOrEqual(1);
    const left = await prisma.processedEvent.findMany({ where: { consumer: 'zz-test' } });
    expect(left.map((row) => row.eventId)).toEqual([recent]);
    await prisma.processedEvent.deleteMany({ where: { consumer: 'zz-test' } });
  });
});
