import { X509Certificate } from 'node:crypto';

import { SECRET_PLACEHOLDER } from './env-file.js';

/**
 * Production preflight checks (`pnpm deploy:preflight`). Pure functions over the deployment's
 * configuration so they can be unit tested; the CLI (`preflight-cli.ts`) supplies the file
 * system and host facts.
 */
export type FindingLevel = 'error' | 'warning';

export interface Finding {
  readonly level: FindingLevel;
  readonly check: string;
  readonly message: string;
}

export interface CertificateFacts {
  readonly certificatePem: string;
  /** File mode of privkey.pem (e.g. 0o600), or null when it does not exist. */
  readonly privateKeyMode: number | null;
}

export interface HostFacts {
  /** /proc/sys/vm/max_map_count, or null when unknown. */
  readonly maxMapCount: number | null;
  /** `docker compose version --short`, or null when unknown. */
  readonly composeVersion: string | null;
}

export interface PreflightInput {
  readonly env: ReadonlyMap<string, string>;
  readonly certificate: CertificateFacts | null;
  readonly host: HostFacts;
  readonly now: Date;
}

const SECRET_KEY = /(PASSWORD|SECRET)$/;
const MIN_SECRET_LENGTH = 24;
const CERT_ERROR_DAYS = 7;
const CERT_WARNING_DAYS = 21;
const DAY_MS = 86_400_000;

function isPrivateOrLocalHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
    hostname.includes(':')
  );
}

function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((part) => Number.parseInt(part, 10) || 0);
  const pb = b.split('.').map((part) => Number.parseInt(part, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

export function checkSecrets(env: ReadonlyMap<string, string>): Finding[] {
  const findings: Finding[] = [];
  for (const [key, value] of env) {
    if (value.startsWith(SECRET_PLACEHOLDER)) {
      findings.push({
        level: 'error',
        check: 'secrets',
        message: `${key} still holds the placeholder`,
      });
      continue;
    }
    if (SECRET_KEY.test(key) && value.length < MIN_SECRET_LENGTH) {
      findings.push({
        level: 'error',
        check: 'secrets',
        message: `${key} is shorter than ${String(MIN_SECRET_LENGTH)} characters`,
      });
    }
  }
  return findings;
}

export function checkPublicUrls(env: ReadonlyMap<string, string>): Finding[] {
  const findings: Finding[] = [];
  const error = (message: string) =>
    findings.push({ level: 'error', check: 'public-urls', message });
  const hostname = env.get('PUBLIC_HOSTNAME') ?? '';
  const origin = env.get('PUBLIC_ORIGIN') ?? '';
  const keycloak = env.get('KEYCLOAK_PUBLIC_URL') ?? '';
  if (hostname === '') error('PUBLIC_HOSTNAME is required');
  else if (isPrivateOrLocalHost(hostname)) {
    findings.push({
      level: 'warning',
      check: 'public-urls',
      message: `PUBLIC_HOSTNAME ${hostname} is not a public DNS name; browsers and ACME need one`,
    });
  }
  if (!URL.canParse(origin)) {
    error('PUBLIC_ORIGIN must be an absolute URL');
  } else {
    const url = new URL(origin);
    if (url.protocol !== 'https:') error('PUBLIC_ORIGIN must use https');
    if (url.pathname !== '/' || url.search !== '' || origin.endsWith('/')) {
      error('PUBLIC_ORIGIN must be an origin without a path or trailing slash');
    }
    if (hostname !== '' && url.host !== hostname) {
      error(`PUBLIC_ORIGIN (${url.host}) must use PUBLIC_HOSTNAME (${hostname}) on port 443`);
    }
  }
  if (keycloak !== `${origin}/auth`) {
    error('KEYCLOAK_PUBLIC_URL must be PUBLIC_ORIGIN followed by /auth');
  }
  for (const entry of (env.get('CORS_ALLOWED_ORIGINS') ?? '').split(',')) {
    const value = entry.trim();
    if (value === '') continue;
    if (value.includes('*') || !value.startsWith('https://')) {
      error(`CORS_ALLOWED_ORIGINS entry ${value} must be an explicit https origin`);
    }
  }
  return findings;
}

export function checkDeploymentSettings(env: ReadonlyMap<string, string>): Finding[] {
  const findings: Finding[] = [];
  const add = (level: FindingLevel, check: string, message: string) =>
    findings.push({ level, check, message });
  if ((env.get('IMAGE_REGISTRY') ?? '') === '')
    add('error', 'images', 'IMAGE_REGISTRY is required');
  const tag = env.get('IMAGE_TAG') ?? '';
  if (tag === '') add('error', 'images', 'IMAGE_TAG is required');
  else if (['latest', 'local', 'dev'].includes(tag)) {
    add('error', 'images', `IMAGE_TAG "${tag}" is mutable; use a release version or commit SHA`);
  }
  if ((env.get('MINIO_IMAGE') ?? '') === '') {
    add(
      'warning',
      'images',
      'MINIO_IMAGE is not set: the default is a community rebuild of MinIO; pin an image your organisation approved',
    );
  }
  const webhook = env.get('ALERTMANAGER_WEBHOOK_URL') ?? '';
  if (webhook === '')
    add(
      'error',
      'alerting',
      'ALERTMANAGER_WEBHOOK_URL is required (alerts would not be delivered)',
    );
  else if (!webhook.startsWith('https://'))
    add('warning', 'alerting', 'ALERTMANAGER_WEBHOOK_URL should use https');
  const recipients = (env.get('BACKUP_AGE_RECIPIENTS') ?? '')
    .split(',')
    .filter((r) => r.trim() !== '');
  if (recipients.length === 0)
    add('error', 'backups', 'BACKUP_AGE_RECIPIENTS is required (backups are encrypted)');
  else if (recipients.some((r) => !r.trim().startsWith('age1'))) {
    add('error', 'backups', 'BACKUP_AGE_RECIPIENTS must contain age public keys (age1...)');
  }
  if (env.get('BACKUP_ALLOW_UNENCRYPTED') === 'true') {
    add('error', 'backups', 'BACKUP_ALLOW_UNENCRYPTED must not be true in production');
  }
  if (env.get('SWAGGER_ENABLED') === 'true') {
    add('warning', 'api', 'SWAGGER_ENABLED=true is ignored by compose.prod.yaml; remove it');
  }
  if (['debug', 'trace'].includes(env.get('LOG_LEVEL') ?? '')) {
    add('warning', 'logging', 'LOG_LEVEL debug/trace is verbose and may log request details');
  }
  if ((env.get('DOWNLOAD_SOURCES_ENABLED') ?? '').includes('exploit-db')) {
    add(
      'warning',
      'sources',
      'Exploit-DB downloads are enabled: confirm its terms of use permit this',
    );
  }
  return findings;
}

export function checkCertificate(
  certificate: CertificateFacts | null,
  hostname: string,
  now: Date,
): Finding[] {
  const error = (message: string): Finding[] => [{ level: 'error', check: 'tls', message }];
  if (certificate === null) return error('TLS_CERT_DIR must contain fullchain.pem and privkey.pem');
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(certificate.certificatePem);
  } catch {
    return error('fullchain.pem is not a PEM certificate');
  }
  const findings: Finding[] = [];
  const validTo = new Date(cert.validTo);
  const daysLeft = (validTo.getTime() - now.getTime()) / DAY_MS;
  if (new Date(cert.validFrom).getTime() > now.getTime()) {
    findings.push({ level: 'error', check: 'tls', message: 'the certificate is not valid yet' });
  }
  if (daysLeft < CERT_ERROR_DAYS) {
    findings.push({
      level: 'error',
      check: 'tls',
      message: `the certificate expires in ${daysLeft.toFixed(1)} days (${validTo.toISOString()})`,
    });
  } else if (daysLeft < CERT_WARNING_DAYS) {
    findings.push({
      level: 'warning',
      check: 'tls',
      message: `the certificate expires in ${daysLeft.toFixed(0)} days; renew it`,
    });
  }
  if (hostname !== '' && cert.checkHost(hostname) === undefined) {
    findings.push({
      level: 'error',
      check: 'tls',
      message: `the certificate does not cover ${hostname}`,
    });
  }
  if (certificate.privateKeyMode === null) {
    findings.push({ level: 'error', check: 'tls', message: 'privkey.pem is missing' });
  } else if ((certificate.privateKeyMode & 0o007) !== 0) {
    findings.push({
      level: 'warning',
      check: 'tls',
      message:
        'privkey.pem is readable by other users; restrict it (it must stay readable by uid 101)',
    });
  }
  return findings;
}

export function checkHost(host: HostFacts): Finding[] {
  const findings: Finding[] = [];
  if (host.maxMapCount !== null && host.maxMapCount < 262_144) {
    findings.push({
      level: 'warning',
      check: 'host',
      message: `vm.max_map_count is ${String(host.maxMapCount)}; OpenSearch needs at least 262144`,
    });
  }
  if (host.composeVersion === null) {
    findings.push({
      level: 'warning',
      check: 'host',
      message: 'could not determine the Docker Compose version',
    });
  } else if (compareVersions(host.composeVersion.replace(/^v/, ''), '2.24.0') < 0) {
    findings.push({
      level: 'error',
      check: 'host',
      message: `Docker Compose ${host.composeVersion} is too old; compose.prod.yaml needs 2.24 or later`,
    });
  }
  return findings;
}

export function runPreflight(input: PreflightInput): Finding[] {
  return [
    ...checkSecrets(input.env),
    ...checkPublicUrls(input.env),
    ...checkDeploymentSettings(input.env),
    ...checkCertificate(input.certificate, input.env.get('PUBLIC_HOSTNAME') ?? '', input.now),
    ...checkHost(input.host),
  ];
}
