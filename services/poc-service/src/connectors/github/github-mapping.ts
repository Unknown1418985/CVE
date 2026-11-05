import type { OwnerType } from '@cve/contracts';

import {
  GITHUB_LOGIN_PATTERN,
  GITHUB_REPOSITORY_NAME_PATTERN,
  githubRepositoryRef,
} from '../../domain/references.js';
import { sanitizeText } from '../../domain/text.js';
import { githubRepositorySchema } from './github-schemas.js';

const TOPIC_PATTERN = /^[a-z0-9][a-z0-9-]{0,49}$/;
const BRANCH_PATTERN = /^[^\s~^:?*[\\\p{Cc}]{1,255}$/u;
const LANGUAGE_PATTERN = /^[\p{L}\p{N} #+.'-]{1,64}$/u;

/** A repository as the PoC Service stores it: validated and sanitised. */
export interface RepositoryMetadata {
  readonly externalId: string;
  readonly owner: {
    readonly externalId: string;
    readonly login: string;
    readonly type: OwnerType;
    readonly url: string;
  };
  readonly name: string;
  readonly fullName: string;
  readonly url: string;
  readonly description: string | null;
  readonly topics: readonly string[];
  readonly language: string | null;
  readonly stars: number;
  readonly forks: number;
  readonly isFork: boolean;
  readonly parentFullName: string | null;
  readonly isArchived: boolean;
  readonly defaultBranch: string | null;
  readonly sizeKb: number;
  readonly sourceCreatedAt: Date | null;
  readonly sourcePushedAt: Date | null;
}

export type MappedRepository =
  | { readonly ok: true; readonly repository: RepositoryMetadata }
  | { readonly ok: false; readonly externalId: string | null; readonly issue: string };

function ownerType(type: string | undefined): OwnerType {
  switch (type) {
    case 'User':
      return 'user';
    case 'Organization':
      return 'organization';
    case 'Bot':
      return 'bot';
    default:
      return 'unknown';
  }
}

function timestamp(value: string | null | undefined): Date | null {
  if (value === null || value === undefined) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : new Date(parsed);
}

/**
 * Validates a GitHub repository payload. The canonical URL is built from the validated owner
 * and name instead of trusting `html_url`; private repositories are refused.
 */
export function mapGithubRepository(raw: unknown): MappedRepository {
  const parsed = githubRepositorySchema.safeParse(raw);
  const rawId =
    raw !== null && typeof raw === 'object' && 'id' in raw && typeof raw.id === 'number'
      ? String(raw.id)
      : null;
  if (!parsed.success) {
    return {
      ok: false,
      externalId: rawId,
      issue: `unexpected repository format: ${parsed.error.issues[0]?.message ?? ''}`,
    };
  }
  const repo = parsed.data;
  const externalId = String(repo.id);
  if (repo.private === true) return { ok: false, externalId, issue: 'private repository' };
  const login = repo.owner.login;
  if (!GITHUB_LOGIN_PATTERN.test(login) && !/^[A-Za-z0-9-]+\[bot\]$/.test(login)) {
    return { ok: false, externalId, issue: 'invalid owner login' };
  }
  if (!GITHUB_REPOSITORY_NAME_PATTERN.test(repo.name) || repo.name === '.' || repo.name === '..') {
    return { ok: false, externalId, issue: 'invalid repository name' };
  }
  if (repo.full_name.toLowerCase() !== `${login}/${repo.name}`.toLowerCase()) {
    return { ok: false, externalId, issue: 'full_name does not match owner and name' };
  }
  const ref = githubRepositoryRef(login, repo.name);
  const parent = repo.parent?.full_name;
  return {
    ok: true,
    repository: {
      externalId,
      owner: {
        externalId: String(repo.owner.id),
        login,
        type: ownerType(repo.owner.type),
        url: `https://github.com/${login}`,
      },
      name: repo.name,
      fullName: ref.fullName,
      url: ref.url,
      description: sanitizeText(repo.description, 1_000),
      topics: [...new Set((repo.topics ?? []).filter((topic) => TOPIC_PATTERN.test(topic)))].slice(
        0,
        30,
      ),
      language:
        repo.language !== null &&
        repo.language !== undefined &&
        LANGUAGE_PATTERN.test(repo.language)
          ? repo.language
          : null,
      stars: repo.stargazers_count ?? 0,
      forks: repo.forks_count ?? 0,
      isFork: repo.fork,
      parentFullName:
        parent !== undefined && /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(parent) ? parent : null,
      isArchived: repo.archived ?? false,
      defaultBranch:
        repo.default_branch !== null &&
        repo.default_branch !== undefined &&
        BRANCH_PATTERN.test(repo.default_branch)
          ? repo.default_branch
          : null,
      sizeKb: repo.size ?? 0,
      sourceCreatedAt: timestamp(repo.created_at),
      sourcePushedAt: timestamp(repo.pushed_at),
    },
  };
}
