import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { BACKEND_SERVICE_NAMES } from '@cve/contracts';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

/**
 * Enforces the infrastructure security policy on compose.yaml so that a later change cannot
 * silently publish a database, drop resource limits or give a data store internet access.
 */
interface ComposeService {
  image?: string;
  build?: unknown;
  profiles?: string[];
  ports?: string[];
  networks?: string[] | Record<string, unknown>;
  network_mode?: string;
  cap_drop?: string[];
  cap_add?: string[];
  security_opt?: string[];
  read_only?: boolean;
  healthcheck?: { test: unknown };
  restart?: string;
  environment?: Record<string, string | number>;
  deploy?: { resources?: { limits?: { cpus?: string; memory?: string; pids?: number } } };
}

interface ComposeFile {
  services: Record<string, ComposeService>;
  networks: Record<string, { internal?: boolean } | null>;
  volumes: Record<string, unknown>;
}

const root = resolve(import.meta.dirname, '../../../..');
const load = (file: string) =>
  parse(readFileSync(resolve(root, file), 'utf8'), {
    merge: true,
    maxAliasCount: -1,
  }) as ComposeFile;
const compose = load('compose.yaml');
const services = Object.entries(compose.services);

const networksOf = (service: ComposeService): string[] =>
  Array.isArray(service.networks) ? service.networks : Object.keys(service.networks ?? {});

/** One-shot jobs that exit after provisioning. */
const JOBS = new Set(['opensearch-init', 'minio-init', 'infra-provisioner']);
const DATA_STORES = ['postgres', 'redis', 'rabbitmq', 'opensearch', 'minio'];
const EGRESS_ALLOWED = new Set([
  'intelligence-service',
  'poc-service',
  'download-service',
  'exploit-service',
  'notification-service',
]);

describe('compose.yaml security policy', () => {
  it('publishes only Nginx and Grafana, and only on 127.0.0.1', () => {
    const publishing = services
      .filter(([, service]) => (service.ports ?? []).length > 0)
      .map(([name]) => name);
    expect(publishing.sort()).toEqual(['grafana', 'nginx']);
    for (const [, service] of services) {
      for (const port of service.ports ?? []) expect(port).toMatch(/^127\.0\.0\.1:/);
    }
  });

  it('keeps data, backend, frontend and observability networks internal', () => {
    for (const name of ['data', 'backend', 'frontend', 'observability']) {
      expect(compose.networks[name]?.internal, name).toBe(true);
    }
  });

  it('never attaches data stores to a network with internet access', () => {
    const internetNetworks = Object.entries(compose.networks)
      .filter(([, network]) => network?.internal !== true)
      .map(([name]) => name);
    for (const store of DATA_STORES) {
      const service = compose.services[store];
      expect(service, store).toBeDefined();
      for (const network of networksOf(service ?? {})) {
        expect(internetNetworks, `${store} on ${network}`).not.toContain(network);
      }
    }
  });

  it('grants internet egress only to services that synchronise external sources', () => {
    for (const [name, service] of services) {
      if (networksOf(service).includes('egress')) expect(EGRESS_ALLOWED.has(name), name).toBe(true);
    }
  });

  it('drops all capabilities and forbids privilege escalation everywhere', () => {
    for (const [name, service] of services) {
      expect(service.cap_drop, name).toEqual(['ALL']);
      expect(service.security_opt, name).toContain('no-new-privileges:true');
    }
  });

  it('sets CPU, memory and PID limits on every long-running container', () => {
    for (const [name, service] of services) {
      if (JOBS.has(name) && name !== 'infra-provisioner') continue;
      const limits = service.deploy?.resources?.limits;
      expect(limits?.cpus, name).toBeDefined();
      expect(limits?.memory, name).toBeDefined();
      expect(limits?.pids, name).toBeGreaterThan(0);
    }
  });

  it('health-checks every data store and the services that others wait on', () => {
    for (const name of [
      ...DATA_STORES,
      'keycloak',
      'nginx',
      'web',
      'api-gateway',
      ...BACKEND_SERVICE_NAMES,
      'prometheus',
      'grafana',
    ]) {
      expect(compose.services[name]?.healthcheck, name).toBeDefined();
    }
  });

  it('uses persistent named volumes for every stateful component', () => {
    for (const volume of [
      'postgres-data',
      'redis-data',
      'rabbitmq-data',
      'opensearch-data',
      'minio-data',
      'prometheus-data',
      'grafana-data',
    ]) {
      expect(Object.keys(compose.volumes)).toContain(volume);
    }
  });

  it('gives every backend service its own credentials for each store', () => {
    for (const service of BACKEND_SERVICE_NAMES) {
      const env = compose.services[service]?.environment ?? {};
      const snake = service.toUpperCase().replaceAll('-', '_');
      const database = service.replaceAll('-', '_');
      expect(String(env['DATABASE_URL']), service).toBe(
        `postgresql://${database}:\${${snake}_DB_PASSWORD}@postgres:5432/${database}`,
      );
      expect(String(env['REDIS_URL']), service).toBe(
        `redis://${service}:\${${snake}_REDIS_PASSWORD}@redis:6379`,
      );
      expect(String(env['RABBITMQ_URL']), service).toBe(
        `amqp://${service}:\${${snake}_RABBITMQ_PASSWORD}@rabbitmq:5672/cve`,
      );
    }
  });

  it('contains no literal secrets (everything comes from .env)', () => {
    const text = readFileSync(resolve(root, 'compose.yaml'), 'utf8');
    for (const line of text.split('\n')) {
      if (/(PASSWORD|SECRET|_PASS)[A-Z_]*:\s*\S/.test(line) && !line.trim().startsWith('#')) {
        expect(line, line).toMatch(/\$\{[A-Z0-9_]+(:\?[^}]*)?\}/);
      }
    }
  });

  it('only publishes extra ports from the development override, still on 127.0.0.1', () => {
    const dev = load('compose.dev.yaml');
    for (const [name, service] of Object.entries(dev.services)) {
      for (const port of service.ports ?? []) expect(port, name).toMatch(/^127\.0\.0\.1:/);
    }
  });
});

describe('.env.example', () => {
  const template = readFileSync(resolve(root, '.env.example'), 'utf8');

  it('holds placeholders instead of real secrets', () => {
    for (const line of template.split('\n')) {
      const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
      if (!match) continue;
      const [, key = '', value = ''] = match;
      if (/(PASSWORD|SECRET)/.test(key)) expect(value, key).toBe('change-me');
    }
  });

  it('defines every variable compose.yaml requires', () => {
    const composeText = readFileSync(resolve(root, 'compose.yaml'), 'utf8');
    const required = new Set([...composeText.matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((m) => m[1]));
    const defined = new Set([...template.matchAll(/^([A-Z0-9_]+)=/gm)].map((m) => m[1]));
    for (const variable of required) expect(defined.has(variable), variable).toBe(true);
  });
});
