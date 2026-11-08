'use client';

import { paginationMetaSchema } from '@cve/contracts';
import {
  keepPreviousData,
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
  type QueryKey,
  type UseMutationResult,
  type UseQueryResult,
} from '@tanstack/react-query';
import { z } from 'zod';

import { apiRequest, type ApiError, type QueryParams } from './client';

export interface ApiQueryOptions<T extends z.ZodType> {
  readonly path: string;
  readonly schema: T;
  readonly query?: QueryParams;
  readonly enabled?: boolean;
  /** Milliseconds; use for live views such as running downloads or sync runs. */
  readonly refetchInterval?: number | false;
  /** Keep showing the previous page while the next one loads (tables). */
  readonly keepPrevious?: boolean;
}

export function apiQueryKey(path: string, query?: QueryParams): QueryKey {
  return ['api', ...path.split('/'), query ?? {}];
}

export function useApiQuery<T extends z.ZodType>(
  options: ApiQueryOptions<T>,
): UseQueryResult<z.output<T>, ApiError> {
  return useQuery<z.output<T>, ApiError>({
    queryKey: apiQueryKey(options.path, options.query),
    queryFn: ({ signal }) =>
      apiRequest(options.path, { schema: options.schema, query: options.query, signal }),
    enabled: options.enabled ?? true,
    refetchInterval: options.refetchInterval ?? false,
    ...(options.keepPrevious === true ? { placeholderData: keepPreviousData } : {}),
  });
}

const countSchema = z.object({ data: z.array(z.unknown()), meta: paginationMetaSchema });

/**
 * Total number of matching items reported by a paginated endpoint (`meta.totalItems`). Used for
 * dashboard counts so that every number shown comes from the service that owns the data.
 */
export function useApiCount(
  path: string,
  query: QueryParams = {},
  enabled = true,
): UseQueryResult<number, ApiError> {
  return useQuery<number, ApiError>({
    queryKey: [...apiQueryKey(path, query), 'count'],
    queryFn: async ({ signal }) => {
      const page = await apiRequest(path, {
        schema: countSchema,
        query: { ...query, page: 1, pageSize: 1 },
        signal,
      });
      return page.meta.totalItems;
    },
    enabled,
    staleTime: 60_000,
  });
}

export interface ApiMutationOptions<TVariables, T extends z.ZodType> {
  readonly request: (variables: TVariables) => {
    path: string;
    method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    body?: unknown;
    headers?: Record<string, string>;
  };
  readonly schema: T;
  /** Query key prefixes (paths) to refresh after success. */
  readonly invalidate?: readonly string[];
  readonly onSuccess?: (data: z.output<T>, variables: TVariables) => void;
}

export function useApiMutation<TVariables, T extends z.ZodType>(
  options: ApiMutationOptions<TVariables, T>,
): UseMutationResult<z.output<T>, ApiError, TVariables> {
  const client = useQueryClient();
  return useMutation<z.output<T>, ApiError, TVariables>({
    mutationFn: (variables) => {
      const request = options.request(variables);
      return apiRequest(request.path, {
        method: request.method,
        body: request.body,
        schema: options.schema,
        ...(request.headers === undefined ? {} : { headers: request.headers }),
      });
    },
    onSuccess: async (data, variables) => {
      await Promise.all(
        (options.invalidate ?? []).map((path) =>
          client.invalidateQueries({ queryKey: ['api', ...path.split('/')] }),
        ),
      );
      options.onSuccess?.(data, variables);
    },
  });
}

export interface CountsResult {
  readonly counts: (number | undefined)[];
  readonly isPending: boolean;
  readonly error: ApiError | null;
  refetch: () => void;
}

/** Several `meta.totalItems` counts of one endpoint (one request each, run in parallel). */
export function useApiCounts(
  path: string,
  queries: readonly QueryParams[],
  enabled = true,
): CountsResult {
  const results = useQueries({
    queries: queries.map((query) => ({
      queryKey: [...apiQueryKey(path, query), 'count'],
      queryFn: async ({ signal }: { signal: AbortSignal }) => {
        const page = await apiRequest(path, {
          schema: countSchema,
          query: { ...query, page: 1, pageSize: 1 },
          signal,
        });
        return page.meta.totalItems;
      },
      enabled,
      staleTime: 60_000,
    })),
  });
  const failed = results.find((result) => result.isError);
  return {
    counts: results.map((result) => result.data),
    isPending: results.some((result) => result.isPending),
    error: (failed?.error as ApiError | undefined) ?? null,
    refetch: () => {
      for (const result of results) {
        if (result.isError) void result.refetch();
      }
    },
  };
}
