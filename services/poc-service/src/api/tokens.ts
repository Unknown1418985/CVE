import type { PocConnector } from '@cve/contracts';

export const DISCOVERY_JOBS = Symbol('DISCOVERY_JOBS');
export const CONNECTOR_INFO = Symbol('CONNECTOR_INFO');
export const SCORING_SETTINGS = Symbol('SCORING_SETTINGS');

/** Static description of a connector on this deployment. */
export interface ConnectorInfo {
  readonly connector: PocConnector;
  readonly enabled: boolean;
  readonly allowedOrigins: readonly string[];
  readonly authentication: { readonly mode: 'none' | 'optional'; readonly configured: boolean };
  readonly schedule: string | null;
}
