import { z } from 'zod';

export const apiErrorDetailSchema = z.object({
  path: z.string(),
  message: z.string(),
});

export const apiErrorBodySchema = z.object({
  code: z.string().min(1),
  message: z.string().min(1),
  details: z.array(apiErrorDetailSchema).optional(),
});

/** Consistent error envelope returned by every service. */
export const apiErrorResponseSchema = z.object({
  error: apiErrorBodySchema,
  correlationId: z.string().optional(),
  timestamp: z.iso.datetime(),
});

export type ApiErrorDetail = z.infer<typeof apiErrorDetailSchema>;
export type ApiErrorBody = z.infer<typeof apiErrorBodySchema>;
export type ApiErrorResponse = z.infer<typeof apiErrorResponseSchema>;

export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 100;

export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE),
});

export const paginationMetaSchema = z.object({
  page: z.number().int().min(1),
  pageSize: z.number().int().min(1).max(MAX_PAGE_SIZE),
  totalItems: z.number().int().min(0),
  totalPages: z.number().int().min(0),
});

export type PaginationQuery = z.infer<typeof paginationQuerySchema>;
export type PaginationMeta = z.infer<typeof paginationMetaSchema>;

/** Builds the success envelope schema `{ data }` for a single resource. */
export function apiDataResponseSchema<T extends z.ZodType>(data: T) {
  return z.object({ data });
}

/** Builds the paginated envelope schema `{ data: T[], meta }`. */
export function apiPaginatedResponseSchema<T extends z.ZodType>(item: T) {
  return z.object({ data: z.array(item), meta: paginationMetaSchema });
}

export function buildPaginationMeta(query: PaginationQuery, totalItems: number): PaginationMeta {
  return {
    page: query.page,
    pageSize: query.pageSize,
    totalItems,
    totalPages: totalItems === 0 ? 0 : Math.ceil(totalItems / query.pageSize),
  };
}
