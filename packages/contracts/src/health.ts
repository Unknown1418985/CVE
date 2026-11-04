import { z } from 'zod';

import { SERVICE_NAMES } from './services.js';

export const healthStatusSchema = z.enum(['ok', 'degraded', 'down']);
export type HealthStatus = z.infer<typeof healthStatusSchema>;

export const dependencyCheckSchema = z.object({
  name: z.string().min(1),
  status: healthStatusSchema,
  latencyMs: z.number().min(0).optional(),
  message: z.string().optional(),
});
export type DependencyCheck = z.infer<typeof dependencyCheckSchema>;

/** Response body of `GET /api/v1/health/*` on every service. */
export const healthReportSchema = z.object({
  service: z.string().min(1),
  version: z.string().min(1),
  status: healthStatusSchema,
  uptimeSeconds: z.number().min(0),
  timestamp: z.iso.datetime(),
  checks: z.array(dependencyCheckSchema),
});
export type HealthReport = z.infer<typeof healthReportSchema>;

export const serviceHealthSummarySchema = z.object({
  service: z.enum(SERVICE_NAMES),
  status: healthStatusSchema,
  latencyMs: z.number().min(0).optional(),
  report: healthReportSchema.optional(),
  message: z.string().optional(),
});
export type ServiceHealthSummary = z.infer<typeof serviceHealthSummarySchema>;

/** Response body of `GET /api/v1/health/services` on the API Gateway. */
export const platformHealthSchema = z.object({
  status: healthStatusSchema,
  timestamp: z.iso.datetime(),
  services: z.array(serviceHealthSummarySchema),
});
export type PlatformHealth = z.infer<typeof platformHealthSchema>;

/** Aggregates individual statuses: any `down` → `down`, any `degraded` → `degraded`. */
export function aggregateHealthStatus(statuses: readonly HealthStatus[]): HealthStatus {
  if (statuses.includes('down')) return 'down';
  if (statuses.includes('degraded')) return 'degraded';
  return 'ok';
}
