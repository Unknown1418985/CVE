import {
  API_PREFIX,
  apiDataResponseSchema,
  apiErrorResponseSchema,
  apiPaginatedResponseSchema,
  type ApiErrorDetail,
  type PaginationMeta,
} from '@cve/contracts';
import type { z } from 'zod';

/** Same-origin backend-for-frontend prefix; the web server attaches the access token. */
export const BFF_PREFIX = `/bff/${API_PREFIX}`;
const CLIENT_HEADER = 'x-cve-client';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: readonly ApiErrorDetail[] = [],
    readonly correlationId: string | null = null,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
}

export type QueryValue = string | number | boolean | readonly string[] | null | undefined;
export type QueryParams = Readonly<Record<string, QueryValue>>;

/** Serialises query parameters, dropping empty values; lists become comma-separated. */
export function buildQueryString(params: QueryParams | undefined): string {
  if (params === undefined) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      const list = value as readonly string[];
      if (list.length > 0) search.set(key, list.join(','));
      continue;
    }
    search.set(key, String(value));
  }
  const text = search.toString();
  return text === '' ? '' : `?${text}`;
}

/** Encodes each path segment so user input can never add separators or dot segments. */
export function apiPath(...segments: readonly (string | number)[]): string {
  return segments.map((segment) => encodeURIComponent(String(segment))).join('/');
}

export interface RequestOptions<T extends z.ZodType> {
  readonly method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  readonly query?: QueryParams | undefined;
  readonly body?: unknown;
  readonly schema: T;
  readonly headers?: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal | undefined;
}

let redirectingToLogin = false;

function redirectToLogin(): void {
  if (typeof window === 'undefined' || redirectingToLogin) return;
  redirectingToLogin = true;
  const returnTo = `${window.location.pathname}${window.location.search}`;
  // /session/login is a route handler (OIDC redirect), so it needs a full document navigation.
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination
  window.location.assign(`/session/login?returnTo=${encodeURIComponent(returnTo)}`);
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Calls the API through the BFF and validates the response against the shared contract, so
 * the UI only ever renders data the backend actually returned in the expected shape.
 */
export async function apiRequest<T extends z.ZodType>(
  path: string,
  options: RequestOptions<T>,
): Promise<z.output<T>> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = {
    accept: 'application/json',
    [CLIENT_HEADER]: 'web',
    ...options.headers,
  };
  if (options.body !== undefined) headers['content-type'] = 'application/json';

  let response: Response;
  try {
    response = await fetch(`${BFF_PREFIX}/${path}${buildQueryString(options.query)}`, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(0, 'network_error', 'The platform could not be reached. Check your connection.');
  }

  const payload = await readJson(response);
  if (!response.ok) {
    const parsed = apiErrorResponseSchema.safeParse(payload);
    if (response.status === 401) redirectToLogin();
    if (parsed.success) {
      throw new ApiError(
        response.status,
        parsed.data.error.code,
        parsed.data.error.message,
        parsed.data.error.details ?? [],
        parsed.data.correlationId ?? null,
      );
    }
    throw new ApiError(response.status, 'http_error', `The request failed with HTTP ${response.status}.`);
  }

  const parsed = options.schema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiError(
      response.status,
      'invalid_response',
      'The service returned data in an unexpected format.',
      parsed.error.issues.slice(0, 5).map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    );
  }
  return parsed.data;
}

export function dataSchema<T extends z.ZodType>(item: T) {
  return apiDataResponseSchema(item);
}

export function pageSchema<T extends z.ZodType>(item: T) {
  return apiPaginatedResponseSchema(item);
}

export interface Page<T> {
  readonly data: T[];
  readonly meta: PaginationMeta;
}

/** Random idempotency key accepted by the services (`[A-Za-z0-9._-]{1,64}`). */
export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return 'You do not have permission to view or change this.';
    if (error.status === 0) return error.message;
    const details = error.details.map((detail) => `${detail.path}: ${detail.message}`).join('; ');
    return details === '' ? error.message : `${error.message} (${details})`;
  }
  if (error instanceof Error) return error.message;
  return 'An unexpected error occurred.';
}
