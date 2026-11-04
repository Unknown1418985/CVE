/**
 * Canonical registry of deployable backend services.
 * Names are stable identifiers used in logs, events, health reports and configuration.
 */
export const SERVICE_NAMES = [
  'api-gateway',
  'identity-service',
  'cve-service',
  'intelligence-service',
  'asset-service',
  'poc-service',
  'download-service',
  'exploit-service',
  'reporting-service',
  'notification-service',
] as const;

export type ServiceName = (typeof SERVICE_NAMES)[number];

/** Downstream services that sit behind the API Gateway. */
export type BackendServiceName = Exclude<ServiceName, 'api-gateway'>;

export const BACKEND_SERVICE_NAMES = SERVICE_NAMES.filter(
  (name): name is BackendServiceName => name !== 'api-gateway',
);

/** Default local development ports. Deployments may override them through `PORT`. */
export const SERVICE_DEFAULT_PORTS: Readonly<Record<ServiceName, number>> = {
  'api-gateway': 4000,
  'identity-service': 4001,
  'cve-service': 4002,
  'intelligence-service': 4003,
  'asset-service': 4004,
  'poc-service': 4005,
  'download-service': 4006,
  'exploit-service': 4007,
  'reporting-service': 4008,
  'notification-service': 4009,
};

export function isServiceName(value: string): value is ServiceName {
  return (SERVICE_NAMES as readonly string[]).includes(value);
}
