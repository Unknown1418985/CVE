import { describe, expect, it } from 'vitest';

import { NAVIGATION } from './navigation';

describe('navigation', () => {
  it('contains every main section from the specification in order', () => {
    expect(NAVIGATION.map((item) => item.label)).toEqual([
      'Overview',
      'CVE Explorer',
      'Vulnerability Analysis',
      'PoC Repository',
      'Exploit Intelligence',
      'Vendors & Products',
      'Threat Intelligence',
      'Download Manager',
      'Data Sources',
      'Reports',
      'User Management',
      'Audit Logs',
      'Settings',
    ]);
  });

  it('only marks implemented sections as available', () => {
    expect(NAVIGATION.filter((item) => item.available).map((item) => item.href)).toEqual(['/']);
  });

  it('uses unique routes', () => {
    expect(new Set(NAVIGATION.map((item) => item.href)).size).toBe(NAVIGATION.length);
  });
});
