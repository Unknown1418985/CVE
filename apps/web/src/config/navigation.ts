export interface NavigationItem {
  readonly label: string;
  readonly href: string;
  /** Phase in which the section is delivered (CLAUDE.md §14). */
  readonly phase: number;
  /** Only available sections are linked; the rest are shown as planned. */
  readonly available: boolean;
}

export const NAVIGATION: readonly NavigationItem[] = [
  { label: 'Overview', href: '/', phase: 0, available: true },
  { label: 'CVE Explorer', href: '/cves', phase: 2, available: false },
  { label: 'Vulnerability Analysis', href: '/analysis', phase: 2, available: false },
  { label: 'PoC Repository', href: '/pocs', phase: 5, available: false },
  { label: 'Exploit Intelligence', href: '/exploits', phase: 7, available: false },
  { label: 'Vendors & Products', href: '/vendors', phase: 4, available: false },
  { label: 'Threat Intelligence', href: '/threat-intelligence', phase: 3, available: false },
  { label: 'Download Manager', href: '/downloads', phase: 6, available: false },
  { label: 'Data Sources', href: '/data-sources', phase: 3, available: false },
  { label: 'Reports', href: '/reports', phase: 9, available: false },
  { label: 'User Management', href: '/users', phase: 1, available: false },
  { label: 'Audit Logs', href: '/audit-logs', phase: 1, available: false },
  { label: 'Settings', href: '/settings', phase: 1, available: false },
];
