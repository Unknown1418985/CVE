import { describe, expect, it } from 'vitest';

import { fillSecrets, parseEnvFile, renderDevEnvFiles } from './env-file.js';
import { loadProvisionerEnv, rabbitPasswordFor, rabbitPasswordVariable } from './env.js';
import { buildOpenSearchPlan } from './opensearch.js';
import { buildRabbitMqPlan } from './rabbitmq.js';
import { evaluateStack, parseComposePs } from './stack-status.js';

describe('fillSecrets', () => {
  it('replaces placeholders only', () => {
    let n = 0;
    const result = fillSecrets(
      '# change-me comment\nA=change-me\nB=keep\nC=change-me-too\n',
      () => `s${++n}`,
    );
    expect(result).toBe('# change-me comment\nA=s1\nB=keep\nC=s2\n');
  });

  it('generates distinct URL-safe secrets', () => {
    const values = parseEnvFile(fillSecrets('A=change-me\nB=change-me'));
    expect(values.get('A')).toMatch(/^[0-9a-f]{48}$/);
    expect(values.get('A')).not.toBe(values.get('B'));
  });
});

describe('renderDevEnvFiles', () => {
  const template = [
    'CVE_SERVICE_DB_PASSWORD',
    'CVE_SERVICE_REDIS_PASSWORD',
    'CVE_SERVICE_RABBITMQ_PASSWORD',
    'CVE_SERVICE_OPENSEARCH_PASSWORD',
    'DOWNLOAD_SERVICE_MINIO_SECRET_KEY',
    'POC_SERVICE_MINIO_SECRET_KEY',
    'REPORTING_SERVICE_MINIO_SECRET_KEY',
    'KEYCLOAK_API_CLIENT_SECRET',
    'KEYCLOAK_IDENTITY_SERVICE_CLIENT_SECRET',
    ...[
      'IDENTITY',
      'CVE',
      'INTELLIGENCE',
      'ASSET',
      'POC',
      'DOWNLOAD',
      'EXPLOIT',
      'REPORTING',
      'NOTIFICATION',
    ].flatMap((s) => [
      `${s}_SERVICE_DB_PASSWORD`,
      `${s}_SERVICE_REDIS_PASSWORD`,
      `${s}_SERVICE_RABBITMQ_PASSWORD`,
    ]),
  ]
    .map((key) => `${key}=change-me`)
    .join('\n');

  it('gives every service only its own credentials', () => {
    const values = parseEnvFile(fillSecrets(template));
    const files = renderDevEnvFiles(values);
    const cve = files['services/cve-service/.env'] ?? '';
    expect(cve).toContain(
      `postgresql://cve_service:${values.get('CVE_SERVICE_DB_PASSWORD') ?? ''}@localhost:5432/cve_service`,
    );
    expect(cve).toContain(
      `redis://cve-service:${values.get('CVE_SERVICE_REDIS_PASSWORD') ?? ''}@localhost:6379`,
    );
    expect(cve).toContain('/cve\n');
    expect(cve).toContain('OPENSEARCH_USERNAME=cve-service');
    expect(cve).not.toContain(values.get('POC_SERVICE_DB_PASSWORD') ?? 'x');
    expect(files['services/download-service/.env']).toContain('S3_ACCESS_KEY_ID=download-service');
    expect(files['services/asset-service/.env']).not.toContain('S3_');
    expect(files['apps/api-gateway/.env']).toContain('CVE_SERVICE_URL=http://localhost:4002');
    expect(files['apps/api-gateway/.env']).toContain(
      `KEYCLOAK_INTROSPECTION_CLIENT_SECRET=${values.get('KEYCLOAK_API_CLIENT_SECRET') ?? ''}`,
    );
    const identity = files['services/identity-service/.env'] ?? '';
    expect(identity).toContain(
      `KEYCLOAK_ADMIN_CLIENT_SECRET=${values.get('KEYCLOAK_IDENTITY_SERVICE_CLIENT_SECRET') ?? ''}`,
    );
    // The CVE Service validates tokens itself, but holds no Keycloak client secret.
    expect(cve).toContain('KEYCLOAK_URL=http://localhost:8180/auth');
    expect(cve).not.toContain('CLIENT_SECRET');
  });

  it('refuses placeholders', () => {
    expect(() => renderDevEnvFiles(parseEnvFile(template))).toThrow(/placeholder/);
  });
});

describe('provisioning plans', () => {
  const secret = 'x'.repeat(16);
  const source: Record<string, string> = {
    RABBITMQ_ADMIN_USER: 'cve-admin',
    RABBITMQ_ADMIN_PASSWORD: secret,
    OPENSEARCH_ADMIN_PASSWORD: secret,
    CVE_SERVICE_OPENSEARCH_PASSWORD: secret,
  };
  for (const service of [
    'identity',
    'cve',
    'intelligence',
    'asset',
    'poc',
    'download',
    'exploit',
    'reporting',
    'notification',
  ]) {
    source[`${service.toUpperCase()}_SERVICE_RABBITMQ_PASSWORD`] = `${service}-password-0000`;
  }

  it('loads and validates the environment', () => {
    const env = loadProvisionerEnv(source);
    expect(env.PROVISION_TARGETS).toEqual(['rabbitmq', 'opensearch']);
    expect(rabbitPasswordFor(env, 'poc-service')).toBe('poc-password-0000');
    expect(rabbitPasswordVariable('download-service')).toBe('DOWNLOAD_SERVICE_RABBITMQ_PASSWORD');
    expect(() => loadProvisionerEnv({ ...source, POC_SERVICE_RABBITMQ_PASSWORD: 'short' })).toThrow(
      /16/,
    );
    expect(() => loadProvisionerEnv({ ...source, PROVISION_TARGETS: 'mysql' })).toThrow();
  });

  it('creates one scoped RabbitMQ user per backend service', () => {
    const env = loadProvisionerEnv(source);
    const plan = buildRabbitMqPlan(env.RABBITMQ_ADMIN_USER, (service) =>
      rabbitPasswordFor(env, service),
    );
    expect(plan.vhost).toBe('cve');
    expect(plan.users).toHaveLength(9);
    expect(plan.users.map((user) => user.service)).not.toContain('api-gateway');
    const poc = plan.users.find((user) => user.service === 'poc-service');
    expect(poc?.permissions.configure).toBe('^poc-service\\..*$');
    expect(poc?.password).toBe('poc-password-0000');
  });

  it('grants OpenSearch access to the CVE index pattern only', () => {
    const plan = buildOpenSearchPlan(secret);
    expect(plan.users.map((user) => user.username)).toEqual(['cve-service']);
    expect(plan.roles[0]?.index_permissions.flatMap((p) => p.index_patterns)).toEqual(['cve-*']);
  });
});

describe('stack readiness', () => {
  const container = (Service: string, State: string, Health = '', ExitCode = 0) => ({
    Service,
    State,
    Health,
    ExitCode,
  });

  it('parses both docker compose ps output formats', () => {
    const line = JSON.stringify({
      Service: 'redis',
      State: 'running',
      Health: 'healthy',
      ExitCode: 0,
    });
    expect(parseComposePs(`${line}\n${line}`)).toHaveLength(2);
    expect(parseComposePs(`[${line}]`)).toHaveLength(1);
    expect(parseComposePs('')).toEqual([]);
  });

  it('waits for health checks, accepts finished jobs and fails on errors', () => {
    expect(
      evaluateStack([container('redis', 'running', 'healthy'), container('minio-init', 'exited')]),
    ).toEqual({ kind: 'ready' });
    expect(
      evaluateStack([container('keycloak', 'running', 'starting'), container('x', 'created')]),
    ).toEqual({
      kind: 'waiting',
      pending: ['keycloak (starting)', 'x (created)'],
    });
    expect(evaluateStack([container('infra-provisioner', 'exited', '', 1)])).toMatchObject({
      kind: 'failed',
    });
    expect(evaluateStack([])).toMatchObject({ kind: 'failed' });
  });
});
