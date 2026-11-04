import { describe, expect, it } from 'vitest';

import {
  createCveRequestSchema,
  cveIdSchema,
  cvss31BaseScore,
  cvssMetricInputSchema,
  epssObservationInputSchema,
  isCpe23,
  kevStatusInputSchema,
  listCvesQuerySchema,
  normalizeCweId,
  parseCvssVector,
  roundUp31,
  severityForScore,
  updateCveRequestSchema,
  validateCveId,
  type ParsedCvssVector,
} from './index.js';

// All identifiers and records below are synthetic test values, not real CVE data.

describe('CVE identifiers', () => {
  const now = new Date('2026-06-01T00:00:00Z');

  it.each([
    'CVE-2026-0001',
    'CVE-1999-0001',
    'CVE-2027-1234',
    'CVE-2026-12345',
    'CVE-2026-1000000',
  ])('accepts %s', (id) => {
    expect(validateCveId(id, now)).toMatchObject({ ok: true, cveId: id });
  });

  it('normalises case and whitespace', () => {
    expect(validateCveId('  cve-2026-0042 ', now)).toMatchObject({
      ok: true,
      cveId: 'CVE-2026-0042',
      parts: { year: 2026, sequence: 42n },
    });
  });

  it.each([
    ['CVE-2026-123', 'too short'],
    ['CVE-26-1234', 'two-digit year'],
    ['CVE-1998-0001', 'before 1999'],
    ['CVE-2028-0001', 'more than a year in the future'],
    ['CVE-2026-01234', 'leading zero in a long sequence'],
    ['CVE-2026-0000', 'zero sequence'],
    ['CAN-2026-0001', 'wrong prefix'],
    ['CVE-2026-0001x', 'trailing garbage'],
    ['CVE-2026-1234\nCVE-2026-5678', 'two IDs'],
  ])('rejects %s (%s)', (id) => {
    expect(validateCveId(id, now).ok).toBe(false);
  });

  it('exposes a zod schema that normalises', () => {
    expect(cveIdSchema.parse('cve-2026-0001')).toBe('CVE-2026-0001');
    expect(cveIdSchema.safeParse('CVE-2026-1').success).toBe(false);
  });
});

describe('CWE identifiers', () => {
  it('normalises CWE IDs and NVD placeholders', () => {
    expect(normalizeCweId('cwe-79')).toBe('CWE-79');
    expect(normalizeCweId('nvd-cwe-noinfo')).toBe('NVD-CWE-noinfo');
    expect(normalizeCweId('NVD-CWE-Other')).toBe('NVD-CWE-Other');
  });

  it.each(['CWE-0', 'CWE-079', 'CWE-', 'CWE-1234567', '79', 'CWE-79 '.repeat(2)])(
    'rejects %j',
    (value) => {
      expect(normalizeCweId(value)).toBeNull();
    },
  );
});

describe('CPE 2.3', () => {
  it.each([
    'cpe:2.3:a:example_vendor:example_product:1.0.0:*:*:*:*:*:*:*',
    'cpe:2.3:o:example:example_os:-:*:*:*:*:*:*:*',
    'cpe:2.3:h:example:device\\:model:*:*:*:*:*:*:*:*',
    'cpe:2.3:a:example:product:2.0\\(beta\\):*:*:*:*:*:*:*',
  ])('accepts %s', (cpe) => {
    expect(isCpe23(cpe)).toBe(true);
  });

  it.each([
    'cpe:/a:example:product:1.0',
    'cpe:2.3:x:example:product:1.0:*:*:*:*:*:*:*',
    'cpe:2.3:a:example:product:1.0:*:*:*:*:*:*',
    'cpe:2.3:a:example:prod uct:1.0:*:*:*:*:*:*:*',
    'cpe:2.3:a:example::1.0:*:*:*:*:*:*:*',
  ])('rejects %s', (cpe) => {
    expect(isCpe23(cpe)).toBe(false);
  });
});

function v31(vector: string): ParsedCvssVector {
  const result = parseCvssVector(vector, '3.1');
  if (!result.ok) throw new Error(result.error);
  return result.vector;
}

describe('CVSS v3.1', () => {
  // Expected scores follow from the specification formulas (section 7.1) and match the FIRST
  // calculator; the vectors are generic metric combinations, not tied to any CVE.
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s scores %d', (vector, expected) => {
    expect(cvss31BaseScore(v31(vector))).toBe(expected);
  });

  it('rounds up as defined in Appendix A, without floating point artefacts', () => {
    expect(roundUp31(4.0)).toBe(4.0);
    expect(roundUp31(4.02)).toBe(4.1);
    expect(roundUp31(4.00001)).toBe(4.1);
    // Below the five-decimal precision the specification rounds to.
    expect(roundUp31(4.000001)).toBe(4.0);
  });

  it('canonicalises metric order and keeps optional metrics', () => {
    const vector = v31('CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H/E:P');
    expect(vector.vectorString).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P');
    expect(vector.metrics).toMatchObject({ AV: 'N', E: 'P' });
  });

  it.each([
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /must start with/],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', /missing base metrics: A/],
    ['CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /duplicate metric/],
    ['CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /invalid value/],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1', /unknown metric/],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/', /malformed/],
    ['CVSS:3.1/AV:N:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', /malformed/],
  ])('rejects %s', (vector, error) => {
    const result = parseCvssVector(vector);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(error);
  });
});

describe('CVSS v4.0', () => {
  const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

  it('accepts a complete base vector and optional metrics in order', () => {
    expect(parseCvssVector(base, '4.0').ok).toBe(true);
    const full = parseCvssVector(`${base}/E:A/CR:H/MSI:S/S:P/U:Amber`, '4.0');
    expect(full).toMatchObject({ ok: true, vector: { metrics: { U: 'Amber', MSI: 'S' } } });
  });

  it.each([
    [base.replace('/AT:N', ''), /missing base metrics: AT/],
    [base.replace('AV:N/AC:L', 'AC:L/AV:N'), /out of order/],
    [`${base}/U:amber`, /invalid value/],
    [`${base}/MSI:S/E:A`, /out of order/],
    [base.replace('UI:N', 'UI:R'), /invalid value/],
  ])('rejects %s', (vector, error) => {
    const result = parseCvssVector(vector, '4.0');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(error);
  });

  it('refuses a vector of the other version', () => {
    expect(parseCvssVector(base, '3.1')).toMatchObject({ ok: false });
  });
});

describe('severity scale', () => {
  it.each([
    [0, 'none'],
    [0.1, 'low'],
    [3.9, 'low'],
    [4, 'medium'],
    [6.9, 'medium'],
    [7, 'high'],
    [8.9, 'high'],
    [9, 'critical'],
    [10, 'critical'],
  ] as const)('%d is %s', (score, severity) => {
    expect(severityForScore(score)).toBe(severity);
  });

  it('rejects out-of-range scores', () => {
    expect(() => severityForScore(10.1)).toThrow();
    expect(() => severityForScore(Number.NaN)).toThrow();
  });
});

describe('CVSS metric input', () => {
  it('computes the v3.1 score and severity', () => {
    const metric = cvssMetricInputSchema.parse({
      version: '3.1',
      source: 'test-source',
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    });
    expect(metric).toMatchObject({ baseScore: 9.8, baseSeverity: 'critical', type: 'secondary' });
  });

  it('rejects a v3.1 score that contradicts the vector', () => {
    const result = cvssMetricInputSchema.safeParse({
      version: '3.1',
      source: 'test-source',
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      baseScore: 7.5,
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(['baseScore']);
  });

  it('requires the source score for v4.0', () => {
    const input = {
      version: '4.0',
      source: 'test-source',
      vectorString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    };
    expect(cvssMetricInputSchema.safeParse(input).success).toBe(false);
    expect(cvssMetricInputSchema.safeParse({ ...input, baseScore: 9.33 }).success).toBe(false);
    expect(cvssMetricInputSchema.parse({ ...input, baseScore: 9.3 })).toMatchObject({
      baseSeverity: 'critical',
    });
  });

  it('rejects a version that does not match the vector', () => {
    expect(
      cvssMetricInputSchema.safeParse({
        version: '4.0',
        source: 'test-source',
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        baseScore: 9.8,
      }).success,
    ).toBe(false);
  });
});

describe('CVE record requests', () => {
  const minimal = {
    cveId: 'cve-2026-90001',
    description: 'Synthetic test record.',
    source: 'test-source',
  };

  it('applies defaults and normalises identifiers', () => {
    expect(createCveRequestSchema.parse(minimal)).toMatchObject({
      cveId: 'CVE-2026-90001',
      state: 'published',
      title: null,
      cvssMetrics: [],
      references: [],
    });
  });

  it('rejects unknown fields', () => {
    expect(createCveRequestSchema.safeParse({ ...minimal, severity: 'high' }).success).toBe(false);
  });

  it('detects duplicate list entries', () => {
    const result = createCveRequestSchema.safeParse({
      ...minimal,
      weaknesses: [
        { cweId: 'CWE-79', source: 'a' },
        { cweId: 'cwe-79', source: 'a' },
        { cweId: 'CWE-79', source: 'b' },
      ],
      references: [
        { url: 'https://example.com/advisory', source: 'a' },
        { url: 'https://EXAMPLE.com/advisory', source: 'b' },
      ],
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.path.join('.'))).toEqual([
      'weaknesses.1',
      'references.1',
    ]);
  });

  it('rejects non-http references, credentials in URLs and control characters', () => {
    for (const url of ['javascript:alert(1)', 'ftp://example.com/x', 'https://u:p@example.com/']) {
      expect(
        createCveRequestSchema.safeParse({ ...minimal, references: [{ url, source: 'a' }] })
          .success,
      ).toBe(false);
    }
    expect(
      createCveRequestSchema.safeParse({ ...minimal, description: 'bad\u0000text' }).success,
    ).toBe(false);
  });

  it('validates affected product version ranges', () => {
    const product = { vendor: 'Example', product: 'Widget', source: 'a' };
    expect(
      createCveRequestSchema.safeParse({
        ...minimal,
        affectedProducts: [
          { ...product, versionStartIncluding: '1.0', versionEndExcluding: '2.0' },
        ],
      }).success,
    ).toBe(true);
    expect(
      createCveRequestSchema.safeParse({
        ...minimal,
        affectedProducts: [{ ...product, versionEndIncluding: '2.0', versionEndExcluding: '2.1' }],
      }).success,
    ).toBe(false);
    expect(
      createCveRequestSchema.safeParse({
        ...minimal,
        affectedProducts: [{ ...product, version: '1.0', versionEndExcluding: '2.0' }],
      }).success,
    ).toBe(false);
  });

  it('rejects modification before publication', () => {
    expect(
      createCveRequestSchema.safeParse({
        ...minimal,
        publishedAt: '2026-02-01T00:00:00Z',
        lastModifiedAt: '2026-01-01T00:00:00Z',
      }).success,
    ).toBe(false);
  });

  it('requires at least one field for a partial update', () => {
    expect(updateCveRequestSchema.safeParse({}).success).toBe(false);
    expect(updateCveRequestSchema.parse({ title: null })).toEqual({ title: null });
  });
});

describe('KEV and EPSS input', () => {
  it('validates KEV dates', () => {
    expect(
      kevStatusInputSchema.safeParse({
        dateAdded: '2026-03-01',
        dueDate: '2026-02-01',
        source: 'a',
      }).success,
    ).toBe(false);
    expect(kevStatusInputSchema.parse({ dateAdded: '2026-03-01', source: 'a' })).toMatchObject({
      knownRansomwareCampaignUse: 'unknown',
      dueDate: null,
    });
  });

  it('bounds EPSS probabilities', () => {
    const base = { scoreDate: '2026-03-01', source: 'a' };
    expect(
      epssObservationInputSchema.safeParse({ ...base, score: 1.2, percentile: 0.5 }).success,
    ).toBe(false);
    expect(
      epssObservationInputSchema.safeParse({ ...base, score: 0.00043, percentile: 0.1 }).success,
    ).toBe(true);
  });
});

describe('CVE search query', () => {
  it('applies defaults', () => {
    expect(listCvesQuerySchema.parse({})).toEqual({
      page: 1,
      pageSize: 25,
      sort: 'publishedAt',
      order: 'desc',
    });
  });

  it('parses lists, booleans and numbers from query strings', () => {
    expect(
      listCvesQuerySchema.parse({
        severity: 'critical,high',
        cweId: ['cwe-79', 'CWE-89'],
        kev: 'true',
        cvssScoreMin: '7.0',
      }),
    ).toMatchObject({
      severity: ['critical', 'high'],
      cweId: ['CWE-79', 'CWE-89'],
      kev: true,
      cvssScoreMin: 7,
    });
  });

  it('rejects unknown parameters and inverted ranges', () => {
    expect(listCvesQuerySchema.safeParse({ sevrity: 'high' }).success).toBe(false);
    expect(listCvesQuerySchema.safeParse({ cvssScoreMin: '8', cvssScoreMax: '5' }).success).toBe(
      false,
    );
    expect(listCvesQuerySchema.safeParse({ kev: 'yes' }).success).toBe(false);
  });
});
