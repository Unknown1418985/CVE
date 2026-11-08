import { describe, expect, it } from 'vitest';

import { isActiveSection, NAVIGATION, visibleNavigation } from './navigation';

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

  it('uses unique routes', () => {
    expect(new Set(NAVIGATION.map((item) => item.href)).size).toBe(NAVIGATION.length);
  });

  it('only shows sections the user is permitted to see', () => {
    const viewer = visibleNavigation(new Set(['cve:read', 'poc:read']));
    expect(viewer.map((item) => item.href)).toEqual(['/', '/cves', '/analysis', '/pocs', '/settings']);
    expect(visibleNavigation(undefined).map((item) => item.href)).toEqual(['/', '/settings']);
  });

  it('matches nested routes to their section', () => {
    expect(isActiveSection('/cves', '/cves/CVE-2026-90001')).toBe(true);
    expect(isActiveSection('/', '/cves')).toBe(false);
    expect(isActiveSection('/vendors', '/products/abc')).toBe(true);
    expect(isActiveSection('/pocs', '/pocsx')).toBe(false);
  });
});
