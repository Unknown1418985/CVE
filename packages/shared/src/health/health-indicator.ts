import { connect } from 'node:net';

import type { DependencyCheck } from '@cve/contracts';

export interface HealthIndicator {
  /** Name shown in the health report, e.g. `postgres`. */
  readonly name: string;
  /**
   * Critical dependencies make the service `down` when unavailable; non-critical ones
   * make it `degraded`.
   */
  readonly critical: boolean;
  check(timeoutMs: number): Promise<DependencyCheck>;
}

const DEFAULT_PORTS: Readonly<Record<string, number>> = {
  'postgres:': 5432,
  'postgresql:': 5432,
  'redis:': 6379,
  'rediss:': 6380,
  'amqp:': 5672,
  'amqps:': 5671,
  'http:': 80,
  'https:': 443,
};

export function resolveHostPort(url: string): { host: string; port: number } {
  const parsed = new URL(url);
  const port = parsed.port === '' ? DEFAULT_PORTS[parsed.protocol] : Number(parsed.port);
  if (port === undefined || !Number.isInteger(port)) {
    throw new Error(`Cannot determine port for protocol ${parsed.protocol}`);
  }
  // URL keeps IPv6 hosts in brackets; net.connect expects them without.
  return { host: parsed.hostname.replace(/^\[(.*)\]$/, '$1'), port };
}

/**
 * Checks that a TCP connection to the dependency can be established.
 * This verifies network reachability only; protocol-level checks are added by the
 * services once they own real clients for the dependency.
 */
export function createTcpHealthIndicator(
  name: string,
  url: string,
  options: { critical?: boolean } = {},
): HealthIndicator {
  const { host, port } = resolveHostPort(url);
  return {
    name,
    critical: options.critical ?? true,
    check: (timeoutMs) =>
      new Promise<DependencyCheck>((resolve) => {
        const started = performance.now();
        const socket = connect({ host, port });
        const finish = (check: Omit<DependencyCheck, 'name' | 'latencyMs'>) => {
          socket.destroy();
          resolve({ name, latencyMs: Math.round(performance.now() - started), ...check });
        };
        socket.setTimeout(timeoutMs);
        socket.once('connect', () => {
          finish({ status: 'ok', message: 'tcp reachable' });
        });
        socket.once('timeout', () => {
          finish({ status: 'down', message: `tcp connect timed out after ${timeoutMs}ms` });
        });
        socket.once('error', (error: NodeJS.ErrnoException) => {
          finish({ status: 'down', message: `tcp connect failed: ${error.code ?? error.message}` });
        });
      }),
  };
}
