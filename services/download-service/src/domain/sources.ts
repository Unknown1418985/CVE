import type { DetectedFileType, DownloadSource } from '@cve/contracts';

/** What a source accepts and where it may connect. Built from configuration at startup. */
export interface SourcePolicy {
  readonly source: DownloadSource;
  readonly name: string;
  readonly description: string;
  readonly enabled: boolean;
  /** Downloads are scheduled automatically from PoC Service events. */
  readonly automatic: boolean;
  /** Origin canonical URLs are built on, e.g. `https://codeload.github.com`. */
  readonly baseUrl: URL;
  /** Hosts every hop (the first request and each redirect) must match, lower-case. */
  readonly allowedHosts: readonly string[];
  /** Content types the response may declare (`application/octet-stream` and so on). */
  readonly allowedContentTypes: readonly string[];
  /** Types the content must be recognised as (sniffed from the first bytes). */
  readonly allowedFileTypes: readonly DetectedFileType[];
  readonly maxBytes: number;
  readonly termsUrl: string | null;
}

/** A download target resolved from an event or a URL; `url` is always canonical. */
export interface DownloadTarget {
  readonly source: DownloadSource;
  readonly url: string;
  readonly sourceRepository: string | null;
  readonly commitSha: string | null;
}

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const COMMIT_SHA = /^[0-9a-f]{40}$/;
const EXPLOIT_DB_ID = /^[1-9][0-9]{0,8}$/;

function joinUrl(base: URL, path: string): string {
  const url = new URL(base.href);
  url.pathname = `${url.pathname.replace(/\/+$/, '')}${path}`;
  url.search = '';
  url.hash = '';
  return url.href;
}

/** `owner/name` with GitHub's character rules; `.` and `..` are never a repository name. */
export function isRepositoryFullName(value: string): boolean {
  const [owner, name, ...rest] = value.split('/');
  return (
    rest.length === 0 &&
    owner !== undefined &&
    name !== undefined &&
    OWNER.test(owner) &&
    REPOSITORY.test(name) &&
    name !== '.' &&
    name !== '..'
  );
}

/** Canonical tarball URL of a repository at a commit (`codeload.github.com/o/r/tar.gz/sha`). */
export function githubArchiveTarget(
  policy: SourcePolicy,
  fullName: string,
  commitSha: string,
): DownloadTarget | null {
  if (!isRepositoryFullName(fullName) || !COMMIT_SHA.test(commitSha)) return null;
  const [owner = '', name = ''] = fullName.split('/');
  return {
    source: 'github-archive',
    url: joinUrl(
      policy.baseUrl,
      `/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/tar.gz/${commitSha}`,
    ),
    sourceRepository: `${owner}/${name}`,
    commitSha,
  };
}

export function exploitDbTarget(policy: SourcePolicy, exploitId: string): DownloadTarget | null {
  if (!EXPLOIT_DB_ID.test(exploitId)) return null;
  return {
    source: 'exploit-db',
    url: joinUrl(policy.baseUrl, `/download/${exploitId}`),
    sourceRepository: null,
    commitSha: null,
  };
}

const segments = (url: URL) => url.pathname.split('/').filter((segment) => segment !== '');

/**
 * Maps a URL a user submitted to a canonical target of an enabled source, or null. Only
 * immutable content is accepted: GitHub archives must name a full commit SHA (branch and tag
 * names can be moved to other content). The user's URL itself is never fetched.
 */
export function resolveUserUrl(
  policies: readonly SourcePolicy[],
  input: string,
): DownloadTarget | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') return null;
  const host = url.hostname.toLowerCase();
  const parts = segments(url);
  for (const policy of policies) {
    if (!policy.enabled) continue;
    if (policy.source === 'github-archive') {
      // https://github.com/<o>/<r>/archive/<sha>.tar.gz | /commit/<sha> | /tree/<sha>
      if (host === 'github.com' && parts.length === 4) {
        const [owner = '', name = '', kind = '', ref = ''] = parts;
        const sha =
          kind === 'archive' ? ref.replace(/\.tar\.gz$/, '') : ['commit', 'tree'].includes(kind) ? ref : '';
        const target = githubArchiveTarget(policy, `${owner}/${name}`, sha);
        if (target !== null) return target;
      }
      // https://codeload.github.com/<o>/<r>/tar.gz/<sha>
      if (policy.allowedHosts.includes(host) && parts.length === 4 && parts[2] === 'tar.gz') {
        const [owner = '', name = '', , sha = ''] = parts;
        const target = githubArchiveTarget(policy, `${owner}/${name}`, sha);
        if (target !== null) return target;
      }
    }
    if (policy.source === 'exploit-db' && policy.allowedHosts.includes(host)) {
      // https://www.exploit-db.com/exploits/<id> | /download/<id> | /raw/<id>
      const [kind = '', id = '', ...rest] = parts;
      if (rest.length === 0 && ['exploits', 'download', 'raw'].includes(kind)) {
        const target = exploitDbTarget(policy, id);
        if (target !== null) return target;
      }
    }
  }
  return null;
}

/** Exploit-DB entry ID of a reference URL the PoC Service collected, or null. */
export function exploitDbIdFromReference(policy: SourcePolicy, reference: string): string | null {
  // Older CVE references use plain http; the canonical download URL is always https.
  const upgraded = reference.replace(/^http:\/\//i, 'https://');
  const target = resolveUserUrl([{ ...policy, enabled: true }], upgraded);
  if (target === null) return null;
  return segments(new URL(target.url)).at(-1) ?? null;
}
