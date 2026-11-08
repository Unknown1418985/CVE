import { describe, expect, it } from 'vitest';

import { parseSearchInput } from './parse-search';

describe('parseSearchInput', () => {
  it('recognises CVE IDs case-insensitively', () => {
    expect(parseSearchInput('  cve-2026-90001 ')).toEqual({ kind: 'cve', cveId: 'CVE-2026-90001' });
  });

  it('recognises CPE names', () => {
    expect(parseSearchInput('cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*')).toEqual({
      kind: 'cpe',
      cpe: 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*',
    });
  });

  it('treats everything else as text', () => {
    expect(parseSearchInput('openssl buffer')).toEqual({ kind: 'text', query: 'openssl buffer' });
    expect(parseSearchInput('CVE-2026')).toEqual({ kind: 'text', query: 'CVE-2026' });
    expect(parseSearchInput('   ')).toEqual({ kind: 'empty' });
  });
});
