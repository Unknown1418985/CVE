import { describe, expect, it } from 'vitest';

import {
  formatBytes,
  formatDate,
  formatDateTime,
  formatPercent,
  formatRelative,
  formatScore,
  humanize,
  shortHash,
} from './format';

describe('format helpers', () => {
  it('formats dates in UTC and handles missing values', () => {
    expect(formatDate('2026-03-01T23:30:00Z')).toBe('Mar 01, 2026');
    expect(formatDateTime('2026-03-01T23:30:00Z')).toBe('Mar 01, 2026, 23:30 UTC');
    expect(formatDate(null)).toBe('—');
    expect(formatDate('not a date')).toBe('—');
  });

  it('formats relative times', () => {
    const now = new Date('2026-03-10T00:00:00Z');
    expect(formatRelative('2026-03-09T00:00:00Z', now)).toBe('yesterday');
    expect(formatRelative('2026-03-10T00:00:30Z', now)).toBe('in 30 seconds');
  });

  it('formats scores, percentages and sizes', () => {
    expect(formatScore(9.8)).toBe('9.8');
    expect(formatScore(null)).toBe('—');
    expect(formatPercent(0.97123)).toBe('97.12%');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(50 * 1024 * 1024)).toBe('50 MiB');
  });

  it('humanizes identifiers and shortens hashes', () => {
    expect(humanize('proof-of-concept')).toBe('Proof of concept');
    expect(humanize('in-review')).toBe('In review');
    expect(shortHash('a'.repeat(64))).toBe(`${'a'.repeat(12)}…`);
  });
});
