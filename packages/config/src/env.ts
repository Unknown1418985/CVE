import type { z } from 'zod';

export interface EnvIssue {
  readonly variable: string;
  readonly message: string;
}

/**
 * Raised when environment validation fails. The message lists variable names and
 * validation problems only; received values are never included because they may be secrets.
 */
export class EnvValidationError extends Error {
  readonly issues: readonly EnvIssue[];

  constructor(issues: readonly EnvIssue[]) {
    super(
      `Invalid environment configuration:\n${issues
        .map((issue) => `  - ${issue.variable}: ${issue.message}`)
        .join('\n')}`,
    );
    this.name = 'EnvValidationError';
    this.issues = issues;
  }
}

export type EnvSource = Readonly<Record<string, string | undefined>>;

/**
 * Validates `source` (defaults to `process.env`) against `schema` and returns the typed result.
 * Empty strings are treated as unset so that optional variables with defaults behave predictably.
 */
export function loadEnv<TSchema extends z.ZodType>(
  schema: TSchema,
  source: EnvSource = process.env,
): z.infer<TSchema> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined && value.trim() !== '') {
      normalized[key] = value;
    }
  }

  const result = schema.safeParse(normalized);
  if (!result.success) {
    throw new EnvValidationError(
      result.error.issues.map((issue) => ({
        variable: issue.path.map(String).join('.') || '(root)',
        message: issue.message,
      })),
    );
  }
  return result.data;
}
