import type { HealthIndicator } from './health-indicator.js';

export interface HealthModuleOptions {
  readonly service: string;
  readonly version: string;
  readonly indicators: readonly HealthIndicator[];
  readonly timeoutMs: number;
}
