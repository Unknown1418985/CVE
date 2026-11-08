import { connect } from 'node:net';

import { platformHealthSchema } from '@cve/contracts';
import { integrationHost, requireEnv } from '@cve/testing/integration';
import { describe, expect, it } from 'vitest';

import { fullStack } from './mode.js';

/**
 * Checks for the full stack (`--profile apps --profile observability`, without compose.dev.yaml).
 * Enabled with INFRA_TEST_FULL_STACK=true because they need every container running.
 */
const host = integrationHost();
const nginx = `http://${host}:8080`;
const grafana = `http://${host}:3001`;

function tcpOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host, port });
    socket.setTimeout(1_000);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      resolve(false);
    });
  });
}

describe.runIf(fullStack)('full stack through Nginx', () => {
  it('does not expose data stores, brokers or internal UIs on the host', async () => {
    for (const port of [5432, 6379, 5672, 15672, 9200, 9000, 9001, 8180, 9090]) {
      expect(await tcpOpen(port), `port ${port}`).toBe(false);
    }
  });

  it('routes the API to the gateway with correlation IDs and security headers', async () => {
    const res = await fetch(`${nginx}/api/v1/health/live`, {
      headers: { 'x-correlation-id': 'itest-correlation-1' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-correlation-id')).toBe('itest-correlation-1');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    // server_tokens off: no version disclosure.
    expect(res.headers.get('server')).toBe('nginx');
  });

  it('reports every backend service as healthy with reachable dependencies', async () => {
    const res = await fetch(`${nginx}/api/v1/health/services`);
    expect(res.status).toBe(200);
    const health = platformHealthSchema.parse(((await res.json()) as { data: unknown }).data);
    expect(health.services).toHaveLength(9);
    for (const service of health.services) expect(service.status, service.service).toBe('ok');
  });

  it('serves the web application', async () => {
    const res = await fetch(`${nginx}/signed-out`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
  });

  it('sends visitors without a session through the Keycloak sign-in of the cve-web client', async () => {
    const home = await fetch(`${nginx}/`, { redirect: 'manual' });
    expect(home.status).toBe(307);
    expect(home.headers.get('location')).toContain('/session/login?returnTo=%2F');

    const login = await fetch(`${nginx}/session/login`, { redirect: 'manual' });
    expect(login.status).toBe(303);
    const authorize = new URL(login.headers.get('location') ?? '');
    expect(authorize.pathname).toBe('/auth/realms/cve-platform/protocol/openid-connect/auth');
    expect(authorize.searchParams.get('client_id')).toBe('cve-web');
    expect(authorize.searchParams.get('code_challenge_method')).toBe('S256');
    // Keycloak answers 400 instead of its login page when the redirect URI is not registered.
    const page = await fetch(`${nginx}${authorize.pathname}${authorize.search}`, {
      redirect: 'manual',
    });
    expect(page.status).toBe(200);
  });

  it('exposes Keycloak realm endpoints under /auth but not the admin console', async () => {
    const discovery = await fetch(
      `${nginx}/auth/realms/cve-platform/.well-known/openid-configuration`,
    );
    expect(discovery.status).toBe(200);
    expect(((await discovery.json()) as { issuer: string }).issuer).toBe(
      `${process.env['PUBLIC_ORIGIN'] ?? 'http://localhost:8080'}/auth/realms/cve-platform`,
    );
    expect((await fetch(`${nginx}/auth/admin/master/console/`)).status).toBe(404);
    expect((await fetch(`${nginx}/auth/admin/realms/cve-platform/users`)).status).toBe(404);
  });

  it('keeps metrics off the public API', async () => {
    // `/metrics` reaches the web app, which sends visitors without a session to sign in.
    const metrics = await fetch(`${nginx}/metrics`, { redirect: 'manual' });
    expect(metrics.status).not.toBe(200);
    expect(await metrics.text()).not.toContain('# TYPE');
    expect((await fetch(`${nginx}/api/v1/metrics`)).status).toBe(404);
  });
});

describe.runIf(fullStack)('observability', () => {
  const auth = () =>
    `Basic ${Buffer.from(`${requireEnv('GRAFANA_ADMIN_USER')}:${requireEnv('GRAFANA_ADMIN_PASSWORD')}`).toString('base64')}`;
  const grafanaGet = async <T>(path: string): Promise<T> => {
    const res = await fetch(`${grafana}${path}`, { headers: { authorization: auth() } });
    expect(res.status, path).toBe(200);
    return (await res.json()) as T;
  };

  interface Target {
    labels: { job: string; instance: string };
    health: string;
    lastError: string;
  }
  const activeTargets = async () =>
    (
      await grafanaGet<{ data: { activeTargets: Target[] } }>(
        '/api/datasources/proxy/uid/prometheus/api/v1/targets?state=active',
      )
    ).data.activeTargets;
  const describeTargets = (targets: Target[]) =>
    targets
      .filter((target) => target.health !== 'up')
      .map(
        (target) =>
          `${target.labels.job}/${target.labels.instance}: ${target.health} ${target.lastError}`,
      );

  it('scrapes every infrastructure and service target successfully', async () => {
    const jobs = new Set((await activeTargets()).map((target) => target.labels.job));
    for (const job of [
      'prometheus',
      'rabbitmq',
      'minio',
      'keycloak',
      'postgres',
      'redis',
      'nginx',
      'services',
    ]) {
      expect(jobs.has(job), job).toBe(true);
    }
    // Right after start-up some targets have not been scraped yet (health "unknown").
    await expect
      .poll(async () => describeTargets(await activeTargets()), {
        timeout: 60_000,
        interval: 2_000,
      })
      .toEqual([]);
  });

  it('has exporters authenticated against PostgreSQL and Redis', async () => {
    for (const metric of ['pg_up', 'redis_up']) {
      const result = await grafanaGet<{ data: { result: { value: [number, string] }[] } }>(
        `/api/datasources/proxy/uid/prometheus/api/v1/query?query=${metric}`,
      );
      expect(result.data.result[0]?.value[1], metric).toBe('1');
    }
  });

  it('loads alert rules and the provisioned dashboard', async () => {
    const rules = await grafanaGet<{ data: { groups: { name: string }[] } }>(
      '/api/datasources/proxy/uid/prometheus/api/v1/rules',
    );
    expect(rules.data.groups.map((group) => group.name).sort()).toEqual([
      'availability',
      'datastores',
      'messaging',
      'services',
    ]);
    const dashboards = await grafanaGet<{ uid: string }[]>('/api/search?type=dash-db');
    expect(dashboards.map((d) => d.uid)).toContain('cve-platform-infrastructure');
  });

  it('rejects anonymous Grafana access', async () => {
    expect((await fetch(`${grafana}/api/search`)).status).toBe(401);
  });
});
