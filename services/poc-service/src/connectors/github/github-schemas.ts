import { z } from 'zod';

/** Fields of a repository as returned by search and `GET /repositories/{id}`. */
export const githubRepositorySchema = z.looseObject({
  id: z.number().int().positive(),
  name: z.string(),
  full_name: z.string(),
  private: z.boolean().optional(),
  owner: z.looseObject({
    login: z.string(),
    id: z.number().int().positive(),
    type: z.string().optional(),
  }),
  description: z.string().nullable().optional(),
  fork: z.boolean(),
  created_at: z.string().nullable().optional(),
  pushed_at: z.string().nullable().optional(),
  size: z.number().int().min(0).optional(),
  stargazers_count: z.number().int().min(0).optional(),
  forks_count: z.number().int().min(0).optional(),
  language: z.string().nullable().optional(),
  topics: z.array(z.string()).optional(),
  archived: z.boolean().optional(),
  disabled: z.boolean().optional(),
  default_branch: z.string().nullable().optional(),
  parent: z.looseObject({ full_name: z.string() }).optional(),
});
export type GithubRepositoryPayload = z.infer<typeof githubRepositorySchema>;

export const githubSearchResponseSchema = z.looseObject({
  total_count: z.number().int().min(0),
  incomplete_results: z.boolean(),
  /** Items are validated one by one so a single odd item does not fail the page. */
  items: z.array(z.unknown()),
});

export const githubCommitSchema = z.looseObject({
  sha: z.string().regex(/^[0-9a-f]{40}$/),
  commit: z.looseObject({
    tree: z.looseObject({ sha: z.string().regex(/^[0-9a-f]{40}$/) }),
    committer: z.looseObject({ date: z.string().optional() }).nullable().optional(),
  }),
});

export const githubTreeSchema = z.looseObject({
  sha: z.string().regex(/^[0-9a-f]{40}$/),
  truncated: z.boolean(),
  tree: z.array(
    z.looseObject({
      path: z.string().min(1).max(4_096),
      mode: z.string().regex(/^[0-7]{5,6}$/),
      type: z.enum(['blob', 'tree', 'commit']),
      sha: z.string().regex(/^[0-9a-f]{40}$/),
      size: z.number().int().min(0).optional(),
    }),
  ),
});
