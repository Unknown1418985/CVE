import { describe, expect, it } from 'vitest';

import { boundedLabel, counter, gauge, histogram, platformRegistry } from './index.js';

describe('platform instruments', () => {
  it('returns the same instrument for the same name', () => {
    const a = counter({ name: 'test_things_total', help: 'h', labelNames: ['kind'] });
    const b = counter({ name: 'test_things_total', help: 'h', labelNames: ['kind'] });
    expect(a).toBe(b);
    a.inc({ kind: 'x' });
    b.inc({ kind: 'x' });
  });

  it('exposes the values in the Prometheus text format', async () => {
    counter({ name: 'test_exposed_total', help: 'h', labelNames: ['kind'] }).inc({ kind: 'y' }, 3);
    histogram({ name: 'test_duration_seconds', help: 'h', labelNames: [] }).observe(0.2);
    const text = await platformRegistry.metrics();
    expect(text).toContain('test_exposed_total{kind="y"} 3');
    expect(text).toContain('test_duration_seconds_count 1');
  });

  it('refuses to reuse a name for a different instrument type', () => {
    counter({ name: 'test_conflict', help: 'h', labelNames: [] });
    expect(() => gauge({ name: 'test_conflict', help: 'h', labelNames: [] })).toThrow(
      /different type/,
    );
  });

  it('runs asynchronous gauge collectors at scrape time', async () => {
    let calls = 0;
    gauge({
      name: 'test_collected',
      help: 'h',
      labelNames: [],
      collect() {
        calls += 1;
        this.set(calls);
        return Promise.resolve();
      },
    });
    expect(await platformRegistry.getSingleMetricAsString('test_collected')).toContain(
      'test_collected 1',
    );
  });
});

describe('boundedLabel', () => {
  it('keeps safe values and collapses unsafe or unknown ones', () => {
    expect(boundedLabel('cve.record.created')).toBe('cve.record.created');
    expect(boundedLabel(undefined)).toBe('unknown');
    expect(boundedLabel('a b"c')).toBe('other');
    expect(boundedLabel('x'.repeat(65))).toBe('other');
    expect(boundedLabel('github', new Set(['github']))).toBe('github');
    expect(boundedLabel('evil', new Set(['github']))).toBe('other');
  });
});
