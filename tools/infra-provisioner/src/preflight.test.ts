import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  checkCertificate,
  checkDeploymentSettings,
  checkHost,
  checkPublicUrls,
  checkSecrets,
  runPreflight,
  type Finding,
} from './preflight.js';

const pem = readFileSync(new URL('./__fixtures__/cve.example.test.pem', import.meta.url), 'utf8');
// The fixture is valid from 2026-11-08 for ten years.
const now = new Date('2027-06-01T00:00:00Z');

const goodEnv = new Map([
  ['POSTGRES_SUPERUSER_PASSWORD', 'a'.repeat(48)],
  ['KEYCLOAK_API_CLIENT_SECRET', 'b'.repeat(48)],
  ['PUBLIC_HOSTNAME', 'cve.example.test'],
  ['PUBLIC_ORIGIN', 'https://cve.example.test'],
  ['KEYCLOAK_PUBLIC_URL', 'https://cve.example.test/auth'],
  ['CORS_ALLOWED_ORIGINS', 'https://cve.example.test'],
  ['IMAGE_REGISTRY', 'registry.example.test/cve'],
  ['IMAGE_TAG', '1.4.0'],
  ['MINIO_IMAGE', 'registry.example.test/minio:RELEASE.2026-08-04T00-00-00Z'],
  ['ALERTMANAGER_WEBHOOK_URL', 'https://hooks.example.test/alerts'],
  ['BACKUP_AGE_RECIPIENTS', 'age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq'],
  ['LOG_LEVEL', 'info'],
]);
const goodHost = { maxMapCount: 262_144, composeVersion: '2.39.1' };
const messages = (findings: Finding[]) => findings.map((f) => `${f.level}: ${f.message}`);

describe('production preflight', () => {
  it('passes a complete production configuration', () => {
    expect(
      runPreflight({
        env: goodEnv,
        certificate: { certificatePem: pem, privateKeyMode: 0o640 },
        host: goodHost,
        now,
      }),
    ).toEqual([]);
  });

  it('rejects placeholder and short secrets', () => {
    const env = new Map([
      ['GRAFANA_ADMIN_PASSWORD', 'change-me'],
      ['WEB_SESSION_SECRET', 'short'],
    ]);
    expect(messages(checkSecrets(env))).toEqual([
      'error: GRAFANA_ADMIN_PASSWORD still holds the placeholder',
      'error: WEB_SESSION_SECRET is shorter than 24 characters',
    ]);
  });

  it('requires HTTPS public URLs that agree with each other', () => {
    const env = new Map(goodEnv);
    env.set('PUBLIC_ORIGIN', 'http://localhost:8080');
    env.set('KEYCLOAK_PUBLIC_URL', 'http://localhost:8080/auth');
    env.set('CORS_ALLOWED_ORIGINS', 'https://cve.example.test,http://localhost:3000');
    const found = messages(checkPublicUrls(env));
    expect(found).toContain('error: PUBLIC_ORIGIN must use https');
    expect(found).toContain(
      'error: PUBLIC_ORIGIN (localhost:8080) must use PUBLIC_HOSTNAME (cve.example.test) on port 443',
    );
    expect(found).toContain(
      'error: CORS_ALLOWED_ORIGINS entry http://localhost:3000 must be an explicit https origin',
    );
    env.set('PUBLIC_ORIGIN', 'https://cve.example.test');
    env.set('KEYCLOAK_PUBLIC_URL', 'https://keycloak.example.test/auth');
    expect(messages(checkPublicUrls(env))).toContain(
      'error: KEYCLOAK_PUBLIC_URL must be PUBLIC_ORIGIN followed by /auth',
    );
  });

  it('requires immutable images, alert delivery and encrypted backups', () => {
    const env = new Map(goodEnv);
    env.set('IMAGE_TAG', 'latest');
    env.delete('ALERTMANAGER_WEBHOOK_URL');
    env.set('BACKUP_AGE_RECIPIENTS', '');
    env.set('BACKUP_ALLOW_UNENCRYPTED', 'true');
    env.delete('MINIO_IMAGE');
    env.set('DOWNLOAD_SOURCES_ENABLED', 'github-archive,exploit-db');
    const found = messages(checkDeploymentSettings(env));
    expect(found).toEqual([
      'error: IMAGE_TAG "latest" is mutable; use a release version or commit SHA',
      'warning: MINIO_IMAGE is not set: the default is a community rebuild of MinIO; pin an image your organisation approved',
      'error: ALERTMANAGER_WEBHOOK_URL is required (alerts would not be delivered)',
      'error: BACKUP_AGE_RECIPIENTS is required (backups are encrypted)',
      'error: BACKUP_ALLOW_UNENCRYPTED must not be true in production',
      'warning: Exploit-DB downloads are enabled: confirm its terms of use permit this',
    ]);
  });

  it('checks the certificate host, validity window and key permissions', () => {
    expect(messages(checkCertificate(null, 'cve.example.test', now))).toEqual([
      'error: TLS_CERT_DIR must contain fullchain.pem and privkey.pem',
    ]);
    expect(
      messages(checkCertificate({ certificatePem: pem, privateKeyMode: 0o644 }, 'other.test', now)),
    ).toEqual([
      'error: the certificate does not cover other.test',
      'warning: privkey.pem is readable by other users; restrict it (it must stay readable by uid 101)',
    ]);
    const nearExpiry = new Date('2036-11-01T00:00:00Z');
    expect(
      messages(
        checkCertificate(
          { certificatePem: pem, privateKeyMode: 0o600 },
          'cve.example.test',
          nearExpiry,
        ),
      )[0],
    ).toMatch(/^error: the certificate expires in [0-9.]+ days/);
    expect(
      messages(checkCertificate({ certificatePem: 'nope', privateKeyMode: 0o600 }, 'x', now)),
    ).toEqual(['error: fullchain.pem is not a PEM certificate']);
  });

  it('checks the Docker Compose version and OpenSearch kernel settings', () => {
    expect(messages(checkHost({ maxMapCount: 65_530, composeVersion: 'v2.20.3' }))).toEqual([
      'warning: vm.max_map_count is 65530; OpenSearch needs at least 262144',
      'error: Docker Compose v2.20.3 is too old; compose.prod.yaml needs 2.24 or later',
    ]);
    expect(checkHost({ maxMapCount: null, composeVersion: '5.6.1' })).toEqual([]);
  });
});
