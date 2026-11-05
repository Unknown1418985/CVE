import { describe, expect, it } from 'vitest';

import {
  compareVersions,
  cpe23ProductName,
  createProductRequestSchema,
  createVendorRequestSchema,
  cveAssociationChangedPayloadSchema,
  formatCpe23,
  listCveAssociationsQuerySchema,
  listProductsQuerySchema,
  listProductVulnerabilitiesQuerySchema,
  parseCpe23,
  productIdentifierInputSchema,
  productTypeForCpePart,
  rangeContains,
  setManualAssociationRequestSchema,
  slugify,
  updateVendorRequestSchema,
  versionRangeInputSchema,
  versionRangeKey,
} from './index.js';

describe('slugify', () => {
  it.each([
    ['Microsoft', 'microsoft'],
    ['Apache Software Foundation', 'apache_software_foundation'],
    ['  Node.js  ', 'node.js'],
    ['Société Générale', 'societe_generale'],
    ['F5, Inc.', 'f5_inc.'],
    ['-leading', 'leading'],
    ['C++ Builder', 'c++_builder'],
  ])('%s → %s', (name, slug) => {
    expect(slugify(name)).toBe(slug);
  });

  it('returns null when nothing usable is left', () => {
    expect(slugify('中文')).toBeNull();
    expect(slugify('!!!')).toBeNull();
  });

  it('truncates to 128 characters', () => {
    expect(slugify('a'.repeat(300))).toHaveLength(128);
  });
});

describe('parseCpe23', () => {
  it('splits and lower-cases the components', () => {
    const parts = parseCpe23('cpe:2.3:a:Apache:HTTP_Server:2.4.58:*:*:*:*:*:*:*');
    expect(parts).toMatchObject({
      part: 'a',
      vendor: 'apache',
      product: 'http_server',
      version: '2.4.58',
      targetHw: '*',
    });
    expect(parts && formatCpe23(parts)).toBe('cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*');
  });

  it('keeps escaped colons inside a component', () => {
    expect(parseCpe23('cpe:2.3:a:acme:widget\\:pro:1.0:*:*:*:*:*:*:*')?.product).toBe(
      'widget\\:pro',
    );
  });

  it('rejects invalid names', () => {
    expect(parseCpe23('cpe:/a:acme:widget')).toBeNull();
    expect(parseCpe23('cpe:2.3:x:acme:widget:*:*:*:*:*:*:*:*')).toBeNull();
  });

  it('builds the product-level name', () => {
    expect(cpe23ProductName({ part: 'o', vendor: 'linux', product: 'linux_kernel' })).toBe(
      'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*',
    );
  });

  it('maps CPE parts to product types', () => {
    expect(productTypeForCpePart('a')).toBe('application');
    expect(productTypeForCpePart('o')).toBe('operating-system');
    expect(productTypeForCpePart('h')).toBe('hardware');
    expect(productTypeForCpePart('*')).toBe('unknown');
  });
});

describe('compareVersions', () => {
  it.each([
    ['1.0', '1.0.0', 0],
    ['1.2', '1.10', -1],
    ['2.0.0', '10.0', -1],
    ['v1.4.2', '1.4.2', 0],
    ['1.0.0+build.7', '1.0.0', 0],
    ['1.0-rc1', '1.0', -1],
    ['1.0.0-beta', '1.0.0-rc', -1],
    ['1.0.1', '1.0.beta', 1],
    ['2.4.58', '2.4.6', 1],
    ['1.1.1w', '1.1.1v', 1],
    ['2023.10.01', '2023.9.30', 1],
    ['1.0.0', '1.0.0.1', -1],
  ] as const)('%s vs %s → %d', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
    expect(compareVersions(b, a)).toBe(expected === 0 ? 0 : -expected);
  });

  it.each([['*'], ['-'], [''], ['1 0'], ['...']])('%j is not comparable', (value) => {
    expect(compareVersions(value, '1.0')).toBeNull();
  });

  it('compares very large numeric segments exactly', () => {
    expect(compareVersions('1.99999999999999999999', '1.99999999999999999998')).toBe(1);
  });
});

describe('rangeContains', () => {
  it('handles inclusive and exclusive bounds', () => {
    const range = { versionStartIncluding: '1.0', versionEndExcluding: '2.0' };
    expect(rangeContains(range, '1.0')).toBe(true);
    expect(rangeContains(range, '1.9.9')).toBe(true);
    expect(rangeContains(range, '2.0')).toBe(false);
    expect(rangeContains(range, '0.9')).toBe(false);
    expect(rangeContains({ versionStartExcluding: '1.0' }, '1.0')).toBe(false);
    expect(rangeContains({ versionEndIncluding: '1.0' }, '1.0.0')).toBe(true);
  });

  it('matches exact versions case-insensitively', () => {
    expect(rangeContains({ version: '1.0-RC1' }, '1.0-rc1')).toBe(true);
    expect(rangeContains({ version: '1.0' }, '1.0.0')).toBe(true);
    expect(rangeContains({ version: '1.0' }, '1.1')).toBe(false);
  });

  it('treats a range without bounds as every version', () => {
    expect(rangeContains({}, '3.2')).toBe(true);
    expect(rangeContains({ version: '*' }, '3.2')).toBe(true);
  });

  it('returns null instead of guessing', () => {
    expect(rangeContains({ version: '-' }, '1.0')).toBeNull();
    expect(rangeContains({ versionEndExcluding: '2.0' }, '*')).toBeNull();
  });

  it('a definite miss beats an incomparable bound', () => {
    expect(rangeContains({ versionStartIncluding: '*', versionEndExcluding: '2.0' }, '3.0')).toBe(
      false,
    );
  });
});

describe('vendor and product write models', () => {
  it('applies defaults and normalises the website', () => {
    expect(
      createVendorRequestSchema.parse({ name: 'Acme', website: 'https://ACME.example' }),
    ).toEqual({
      name: 'Acme',
      description: null,
      website: 'https://acme.example/',
      source: 'manual',
    });
  });

  it('lower-cases a supplied slug and rejects invalid ones', () => {
    expect(createVendorRequestSchema.parse({ name: 'Acme', slug: 'ACME' }).slug).toBe('acme');
    expect(createVendorRequestSchema.safeParse({ name: 'Acme', slug: '_acme' }).success).toBe(
      false,
    );
  });

  it('allows clearing optional fields but not empty patches', () => {
    expect(updateVendorRequestSchema.parse({ website: null })).toEqual({ website: null });
    expect(updateVendorRequestSchema.safeParse({}).success).toBe(false);
  });

  it('validates CPE names and identifiers of a product', () => {
    const product = createProductRequestSchema.parse({
      vendorId: '00000000-0000-4000-8000-000000000001',
      name: 'Widget',
      cpes: [{ cpe: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*' }],
      identifiers: [{ type: 'purl', value: 'pkg:npm/%40acme/widget' }],
    });
    expect(product.type).toBe('unknown');
    expect(product.cpes[0]?.source).toBe('manual');
    expect(
      productIdentifierInputSchema.safeParse({ type: 'purl', value: 'pkg:npm/widget@1.0.0' })
        .success,
    ).toBe(false);
    expect(
      productIdentifierInputSchema.safeParse({ type: 'swid', value: 'any tag id' }).success,
    ).toBe(true);
  });
});

describe('version ranges', () => {
  it('rejects contradictory bounds', () => {
    expect(
      versionRangeInputSchema.safeParse({ versionEndIncluding: '2', versionEndExcluding: '3' })
        .success,
    ).toBe(false);
    expect(
      versionRangeInputSchema.safeParse({ version: '1', versionStartIncluding: '0' }).success,
    ).toBe(false);
    expect(versionRangeInputSchema.safeParse({ version: '1 0' }).success).toBe(false);
  });

  it('keys equal ranges identically', () => {
    const a = versionRangeInputSchema.parse({ versionEndExcluding: '2.0' });
    const b = versionRangeInputSchema.parse({ status: 'affected', versionEndExcluding: '2.0' });
    expect(versionRangeKey(a)).toBe(versionRangeKey(b));
  });

  it('rejects duplicate ranges in a manual association', () => {
    const result = setManualAssociationRequestSchema.safeParse({
      ranges: [{ version: '1.0' }, { status: 'affected', version: '1.0' }],
    });
    expect(result.success).toBe(false);
  });
});

describe('queries', () => {
  it('parses list and boolean parameters', () => {
    const query = listProductVulnerabilitiesQuerySchema.parse({
      severity: 'critical,high',
      kev: 'true',
      includeWithdrawn: 'true',
      version: '1.2.3',
    });
    expect(query).toMatchObject({
      severity: ['critical', 'high'],
      kev: true,
      includeWithdrawn: true,
      version: '1.2.3',
      sort: 'cveId',
      order: 'desc',
      page: 1,
      pageSize: 25,
    });
  });

  it('normalises CVE IDs and rejects unknown parameters', () => {
    expect(listCveAssociationsQuerySchema.parse({ cveId: 'cve-2026-0001' }).cveId).toBe(
      'CVE-2026-0001',
    );
    expect(listProductsQuerySchema.safeParse({ vendorSlug: 'acme' }).success).toBe(false);
  });
});

describe('association events', () => {
  it('requires a known change kind', () => {
    const base = {
      associationId: '00000000-0000-4000-8000-000000000001',
      cveId: 'CVE-2026-0001',
      productId: '00000000-0000-4000-8000-000000000002',
      productSlug: 'widget',
      vendorId: '00000000-0000-4000-8000-000000000003',
      vendorSlug: 'acme',
      source: 'nvd',
      sourceRecordId: 'CVE-2026-0001',
      origin: 'observation',
      status: 'affected',
      ranges: [],
      actor: { type: 'service', id: 'asset-service', username: null },
    };
    expect(cveAssociationChangedPayloadSchema.safeParse({ ...base, change: 'added' }).success).toBe(
      true,
    );
    expect(
      cveAssociationChangedPayloadSchema.safeParse({ ...base, change: 'deleted' }).success,
    ).toBe(false);
  });
});
