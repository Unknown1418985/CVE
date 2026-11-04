import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Helpers for integration tests that run against the Docker Compose stack started with
 * `docker compose -f compose.yaml -f compose.dev.yaml up -d` (ports published on 127.0.0.1).
 * Credentials are read from the repository root `.env` created by `pnpm env:generate`.
 */
export function loadRootEnvFile(fromDirectory: string): void {
  let directory = resolve(fromDirectory);
  for (let depth = 0; depth < 6; depth += 1) {
    const candidate = resolve(directory, '.env');
    if (existsSync(resolve(directory, 'pnpm-workspace.yaml'))) {
      if (existsSync(candidate)) process.loadEnvFile(candidate);
      return;
    }
    directory = resolve(directory, '..');
  }
}

export function integrationHost(): string {
  return process.env['INTEGRATION_HOST'] ?? '127.0.0.1';
}

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(
      `${name} is not set. Run \`pnpm env:generate\` and start the stack with compose.dev.yaml before integration tests.`,
    );
  }
  return value;
}

function variablePrefix(service: string): string {
  return service.toUpperCase().replaceAll('-', '_');
}

/** AMQP URL for a service user on the `cve` vhost. */
export function serviceRabbitMqUrl(service: string): string {
  const password = encodeURIComponent(requireEnv(`${variablePrefix(service)}_RABBITMQ_PASSWORD`));
  return `amqp://${service}:${password}@${integrationHost()}:5672/cve`;
}

/** Redis URL for a service ACL user. */
export function serviceRedisUrl(service: string): string {
  const password = encodeURIComponent(requireEnv(`${variablePrefix(service)}_REDIS_PASSWORD`));
  return `redis://${service}:${password}@${integrationHost()}:6379`;
}
