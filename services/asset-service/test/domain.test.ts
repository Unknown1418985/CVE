import { describe, expect, it } from 'vitest';

import { versionRangeInputSchema } from '@cve/contracts';
import { consumerTopology } from '@cve/messaging';

import {
  associationStatus,
  canonicalRanges,
  fromStoredRange,
  toVersionRange,
} from '../src/associations/association-writer.js';
import { versionAffected } from '../src/associations/associations.service.js';
import { packageUrl } from '../src/associations/product-resolver.js';
import { cpeMatchWhere } from '../src/catalog/products.service.js';
import { checkPrecondition, parsePrecondition } from '../src/common/http.js';
import type { ObservationApplier } from '../src/associations/observation-applier.js';
import { isNewer, type CveFactsProjector } from '../src/events/cve-facts.projector.js';
import { assetSubscriptions } from '../src/events/subscriptions.js';
import { escapeLike } from '../src/persistence/database.js';

const range = (input: Record<string, unknown>) => versionRangeInputSchema.parse(input);
const stored = (input: Record<string, unknown>) => toVersionRange(range(input));

describe('associationStatus', () => {
  it('is affected when any range is affected', () => {
    expect(associationStatus([{ status: 'unaffected' }, { status: 'affected' }])).toBe('affected');
  });
  it('is unknown before unaffected', () => {
    expect(associationStatus([{ status: 'unaffected' }, { status: 'unknown' }])).toBe('unknown');
    expect(associationStatus([{ status: 'unaffected' }])).toBe('unaffected');
  });
});

describe('canonicalRanges', () => {
  it('removes duplicates and orders ranges deterministically', () => {
    const a = range({ versionStartIncluding: '1.0', versionEndExcluding: '1.5' });
    const b = range({ version: '2.0' });
    expect(canonicalRanges([a, b, a])).toEqual(canonicalRanges([b, a]));
    expect(canonicalRanges([a, b, a])).toHaveLength(2);
  });

  it('round-trips through the stored representation', () => {
    const input = range({ cpe: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', versionEndIncluding: '3' });
    expect(fromStoredRange(toVersionRange(input))).toEqual(input);
  });
});

describe('versionAffected', () => {
  it('evaluates bounded ranges', () => {
    const ranges = [stored({ versionStartIncluding: '1.0.0', versionEndExcluding: '1.4.2' })];
    expect(versionAffected(ranges, '1.2.0')).toBe(true);
    expect(versionAffected(ranges, '1.4.2')).toBe(false);
    expect(versionAffected(ranges, '0.9')).toBe(false);
  });

  it('ignores unaffected ranges', () => {
    expect(versionAffected([stored({ status: 'unaffected', version: '1.0' })], '1.0')).toBe(false);
  });

  it('treats a range without bounds as all versions', () => {
    expect(versionAffected([stored({})], '42')).toBe(true);
  });

  it('uses the version component of a CPE-only range', () => {
    const ranges = [stored({ cpe: 'cpe:2.3:a:acme:widget:2.1:*:*:*:*:*:*:*' })];
    expect(versionAffected(ranges, '2.1')).toBe(true);
    expect(versionAffected(ranges, '2.2')).toBe(false);
    expect(versionAffected([stored({ cpe: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*' })], '9')).toBe(
      true,
    );
  });

  it('reports null when a bound cannot be compared', () => {
    expect(versionAffected([stored({ versionEndExcluding: 'beta' })], '1.0')).toBe(false);
    expect(versionAffected([stored({ versionEndExcluding: '*' })], '1.0')).toBeNull();
    expect(versionAffected([stored({ version: '-' })], '1.0')).toBeNull();
  });

  it('prefers a definite match over an unknown one', () => {
    const ranges = [stored({ version: '-' }), stored({ versionEndIncluding: '2.0' })];
    expect(versionAffected(ranges, '1.0')).toBe(true);
  });
});

describe('packageUrl', () => {
  it.each([
    ['npm', 'lodash', 'pkg:npm/lodash'],
    ['npm', '@angular/core', 'pkg:npm/%40angular/core'],
    ['pip', 'Django_REST.framework', 'pkg:pypi/django-rest-framework'],
    [
      'maven',
      'org.apache.logging.log4j:log4j-core',
      'pkg:maven/org.apache.logging.log4j/log4j-core',
    ],
    ['go', 'github.com/gin-gonic/gin', 'pkg:golang/github.com/gin-gonic/gin'],
    ['rubygems', 'rails', 'pkg:gem/rails'],
    ['rust', 'tokio', 'pkg:cargo/tokio'],
  ])('%s %s → %s', (ecosystem, name, expected) => {
    expect(packageUrl(ecosystem, name)).toBe(expected);
  });

  it('returns null for unknown ecosystems and malformed names', () => {
    expect(packageUrl('cobol', 'x')).toBeNull();
    expect(packageUrl('maven', 'no-group')).toBeNull();
    expect(packageUrl('npm', 'has space')).toBeNull();
    expect(packageUrl('npm', '')).toBeNull();
  });
});

describe('cpeMatchWhere', () => {
  it('matches part, vendor and product; wildcards widen the match', () => {
    expect(cpeMatchWhere('cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*')).toEqual({
      cpeVendor: 'acme',
      cpeProduct: 'widget',
      part: { in: ['a', '*'] },
    });
    expect(cpeMatchWhere('cpe:2.3:*:ACME:*:*:*:*:*:*:*:*:*')).toEqual({ cpeVendor: 'acme' });
    expect(cpeMatchWhere('not a cpe')).toBeNull();
  });
});

describe('isNewer (CVE fact ordering)', () => {
  const t0 = new Date('2026-01-01T00:00:00Z');
  const t1 = new Date('2026-01-02T00:00:00Z');
  const stored = { recordId: 'r1', recordVersion: 3, deletedAt: null, eventOccurredAt: t1 };

  it('applies the first event', () => {
    expect(isNewer(null, { recordId: 'r1', version: 1, deleted: false, occurredAt: t0 })).toBe(
      true,
    );
  });
  it('orders events of one record by version', () => {
    expect(isNewer(stored, { recordId: 'r1', version: 4, deleted: false, occurredAt: t0 })).toBe(
      true,
    );
    expect(isNewer(stored, { recordId: 'r1', version: 3, deleted: false, occurredAt: t1 })).toBe(
      false,
    );
    expect(isNewer(stored, { recordId: 'r1', version: 2, deleted: false, occurredAt: t1 })).toBe(
      false,
    );
  });
  it('applies a deletion at the current version, once', () => {
    expect(isNewer(stored, { recordId: 'r1', version: 3, deleted: true, occurredAt: t1 })).toBe(
      true,
    );
    const tombstone = { ...stored, deletedAt: t1 };
    expect(isNewer(tombstone, { recordId: 'r1', version: 3, deleted: true, occurredAt: t1 })).toBe(
      false,
    );
    expect(isNewer(tombstone, { recordId: 'r1', version: 4, deleted: false, occurredAt: t1 })).toBe(
      false,
    );
  });
  it('orders a recreated record by event time', () => {
    const later = new Date('2026-01-03T00:00:00Z');
    expect(isNewer(stored, { recordId: 'r2', version: 1, deleted: false, occurredAt: later })).toBe(
      true,
    );
    expect(isNewer(stored, { recordId: 'r2', version: 1, deleted: false, occurredAt: t0 })).toBe(
      false,
    );
  });
});

describe('HTTP helpers', () => {
  it('parses If-Match', () => {
    expect(parsePrecondition(undefined)).toBeUndefined();
    expect(parsePrecondition('*')).toBe('*');
    expect(parsePrecondition(' "12" ')).toBe(12);
    expect(() => parsePrecondition('"01"')).toThrow();
  });
  it('checks numeric preconditions only', () => {
    expect(() => {
      checkPrecondition(2, 2);
    }).not.toThrow();
    expect(() => {
      checkPrecondition('*', 7);
    }).not.toThrow();
    expect(() => {
      checkPrecondition(undefined, 7);
    }).not.toThrow();
    expect(() => {
      checkPrecondition(1, 2);
    }).toThrow(/version 2/);
  });
  it('escapes LIKE wildcards', () => {
    expect(escapeLike('100%_a\\b')).toBe('100\\%\\_a\\\\b');
  });
});

describe('event subscriptions', () => {
  const [observationsSub, factsSub] = assetSubscriptions({
    observations: {} as ObservationApplier,
    facts: {} as CveFactsProjector,
  });
  const actor = { type: 'service', id: 'cve-service', username: null };
  const snapshot = {
    recordId: '00000000-0000-4000-8000-000000000001',
    cveId: 'CVE-2026-0001',
    version: 2,
    state: 'published',
    severity: 'high',
    cvssScore: 7.5,
    cvssVersion: '3.1',
    inKev: false,
    epssScore: null,
    epssPercentile: null,
    cweIds: [],
    publishedAt: null,
    lastModifiedAt: null,
    actor,
  };

  it('binds the documented event types with valid consumer names', () => {
    expect(observationsSub.eventTypes).toEqual(['intelligence.cve-observation.recorded']);
    expect(factsSub.eventTypes).toEqual([
      'cve.record.created',
      'cve.record.updated',
      'cve.record.deleted',
    ]);
    for (const sub of [observationsSub, factsSub]) {
      expect(() => consumerTopology('asset-service', sub.consumer, 3)).not.toThrow();
    }
  });

  it('keeps the facts of created and updated payloads and accepts deletions', () => {
    expect(factsSub.payloadSchema.parse(snapshot)).toMatchObject({ severity: 'high' });
    expect(
      factsSub.payloadSchema.parse({
        ...snapshot,
        changedFields: ['cvssMetrics'],
        previousSeverity: 'low',
      }),
    ).toMatchObject({ severity: 'high', changedFields: ['cvssMetrics'] });
    const deleted = factsSub.payloadSchema.parse({
      recordId: snapshot.recordId,
      cveId: snapshot.cveId,
      version: 3,
      actor,
    });
    expect('severity' in deleted).toBe(false);
  });
});
