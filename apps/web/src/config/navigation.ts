import type { Permission } from '@cve/contracts';
import {
  Activity,
  BarChart3,
  Bug,
  Building2,
  Database,
  Download,
  FileText,
  FolderGit2,
  LayoutDashboard,
  Radar,
  ScrollText,
  Settings,
  Users,
  type LucideIcon,
} from 'lucide-react';

export interface NavigationItem {
  readonly label: string;
  readonly href: string;
  readonly icon: LucideIcon;
  /** Permission needed to see the section; the services enforce the same permission. */
  readonly permission: Permission | null;
  readonly group: 'Intelligence' | 'Operations' | 'Administration';
}

export const NAVIGATION: readonly NavigationItem[] = [
  { label: 'Overview', href: '/', icon: LayoutDashboard, permission: null, group: 'Intelligence' },
  {
    label: 'CVE Explorer',
    href: '/cves',
    icon: Bug,
    permission: 'cve:read',
    group: 'Intelligence',
  },
  {
    label: 'Vulnerability Analysis',
    href: '/analysis',
    icon: BarChart3,
    permission: 'cve:read',
    group: 'Intelligence',
  },
  {
    label: 'PoC Repository',
    href: '/pocs',
    icon: FolderGit2,
    permission: 'poc:read',
    group: 'Intelligence',
  },
  {
    label: 'Exploit Intelligence',
    href: '/exploits',
    icon: Activity,
    permission: 'exploit:read',
    group: 'Intelligence',
  },
  {
    label: 'Vendors & Products',
    href: '/vendors',
    icon: Building2,
    permission: 'asset:read',
    group: 'Intelligence',
  },
  {
    label: 'Threat Intelligence',
    href: '/threat-intelligence',
    icon: Radar,
    permission: 'threat-intel:read',
    group: 'Intelligence',
  },
  {
    label: 'Download Manager',
    href: '/downloads',
    icon: Download,
    permission: 'download:read',
    group: 'Operations',
  },
  {
    label: 'Data Sources',
    href: '/data-sources',
    icon: Database,
    permission: 'data-source:read',
    group: 'Operations',
  },
  {
    label: 'Reports',
    href: '/reports',
    icon: FileText,
    permission: 'report:read',
    group: 'Operations',
  },
  {
    label: 'User Management',
    href: '/users',
    icon: Users,
    permission: 'user:read',
    group: 'Administration',
  },
  {
    label: 'Audit Logs',
    href: '/audit-logs',
    icon: ScrollText,
    permission: 'audit:read',
    group: 'Administration',
  },
  {
    label: 'Settings',
    href: '/settings',
    icon: Settings,
    permission: null,
    group: 'Administration',
  },
];

export function visibleNavigation(
  permissions: ReadonlySet<Permission> | undefined,
): NavigationItem[] {
  return NAVIGATION.filter(
    (item) => item.permission === null || permissions?.has(item.permission) === true,
  );
}

/** Whether `pathname` belongs to the section at `href`. */
export function isActiveSection(href: string, pathname: string): boolean {
  if (href === '/') return pathname === '/';
  if (href === '/vendors' && pathname.startsWith('/products')) return true;
  return pathname === href || pathname.startsWith(`${href}/`);
}
