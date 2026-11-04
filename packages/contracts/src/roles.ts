/** Platform roles (see CLAUDE.md §8). Enforcement is implemented by the Identity Service. */
export const ROLES = [
  'super-admin',
  'administrator',
  'security-analyst',
  'vulnerability-researcher',
  'viewer',
] as const;

export type Role = (typeof ROLES)[number];

export const ROLE_LABELS: Readonly<Record<Role, string>> = {
  'super-admin': 'Super Admin',
  administrator: 'Administrator',
  'security-analyst': 'Security Analyst',
  'vulnerability-researcher': 'Vulnerability Researcher',
  viewer: 'Viewer',
};
