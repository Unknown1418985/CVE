import type { PocReferenceKind } from '@cve/contracts';

/** GitHub owner (user or organisation) login. */
export const GITHUB_LOGIN_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
/** GitHub repository name. */
export const GITHUB_REPOSITORY_NAME_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

/** First path segments of github.com that are not user or organisation pages. */
const RESERVED_GITHUB_PATHS = new Set([
  'about',
  'advisories',
  'apps',
  'collections',
  'contact',
  'customer-stories',
  'enterprise',
  'events',
  'explore',
  'features',
  'login',
  'marketplace',
  'new',
  'notifications',
  'orgs',
  'organizations',
  'pricing',
  'pulls',
  'issues',
  'search',
  'security',
  'sessions',
  'settings',
  'site',
  'sponsors',
  'topics',
  'trending',
]);

export interface GithubRepositoryRef {
  readonly owner: string;
  readonly name: string;
  /** Canonical `owner/name` (case preserved; GitHub compares case-insensitively). */
  readonly fullName: string;
  readonly url: string;
}

/** Parses `https://github.com/<owner>/<repo>[/…]`; null for anything else. */
export function parseGithubRepositoryUrl(url: string): GithubRepositoryRef | null {
  if (!URL.canParse(url)) return null;
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  if (
    parsed.hostname.toLowerCase() !== 'github.com' &&
    parsed.hostname.toLowerCase() !== 'www.github.com'
  )
    return null;
  if (parsed.username !== '' || parsed.password !== '') return null;
  const [owner = '', rawName = ''] = parsed.pathname.split('/').filter((part) => part !== '');
  const name = rawName.replace(/\.git$/i, '');
  if (RESERVED_GITHUB_PATHS.has(owner.toLowerCase())) return null;
  if (!GITHUB_LOGIN_PATTERN.test(owner) || !GITHUB_REPOSITORY_NAME_PATTERN.test(name)) return null;
  if (name === '.' || name === '..') return null;
  return githubRepositoryRef(owner, name);
}

export function githubRepositoryRef(owner: string, name: string): GithubRepositoryRef {
  return { owner, name, fullName: `${owner}/${name}`, url: `https://github.com/${owner}/${name}` };
}

export interface ClassifiedReference {
  readonly kind: PocReferenceKind;
  readonly repository: GithubRepositoryRef | null;
}

const hostIs = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);

/**
 * Decides whether a CVE reference points to a public PoC. Known PoC hosts are recognised by
 * URL shape; any other URL counts only when the source tagged it as an exploit.
 */
export function classifyReference(
  url: string,
  tags: readonly string[],
): ClassifiedReference | null {
  if (!URL.canParse(url)) return null;
  const parsed = new URL(url);
  const host = parsed.hostname.toLowerCase();
  const exploitTag = tags.some((tag) => tag.toLowerCase() === 'exploit');
  if (host === 'github.com' || host === 'www.github.com') {
    const repository = parseGithubRepositoryUrl(url);
    if (repository !== null) return { kind: 'github-repository', repository };
    return exploitTag ? { kind: 'other', repository: null } : null;
  }
  if (host === 'gist.github.com') return { kind: 'github-gist', repository: null };
  if (hostIs(host, 'exploit-db.com') && /^\/(?:exploits|download|raw)\/\d+/.test(parsed.pathname)) {
    return { kind: 'exploit-db', repository: null };
  }
  if (hostIs(host, 'packetstormsecurity.com') && parsed.pathname.startsWith('/files/')) {
    return { kind: 'packet-storm', repository: null };
  }
  return exploitTag ? { kind: 'other', repository: null } : null;
}

export function isExploitTagged(tags: readonly string[]): boolean {
  return tags.some((tag) => tag.toLowerCase() === 'exploit');
}
