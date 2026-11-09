import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

import { createLogger } from '@cve/logger';

import { parseEnvFile } from './env-file.js';
import { runPreflight, type CertificateFacts, type HostFacts } from './preflight.js';

/**
 * `pnpm deploy:preflight` — validates a production deployment before `docker compose up`:
 * configuration in `.env` (or ENV_FILE), the TLS certificate in TLS_CERT_DIR and host settings.
 * Variables exported in the shell override `.env`, exactly as Docker Compose resolves them.
 * Exits 1 when any error is found; warnings are reported but do not fail.
 */
const logger = createLogger({ service: 'deploy-preflight' });

function loadEnv(): Map<string, string> {
  const file = resolve(process.cwd(), process.env['ENV_FILE'] ?? '.env');
  if (!existsSync(file)) throw new Error(`${file} not found; run from the repository root`);
  const values = parseEnvFile(readFileSync(file, 'utf8'));
  for (const key of [
    ...values.keys(),
    'IMAGE_REGISTRY',
    'IMAGE_TAG',
    'PUBLIC_HOSTNAME',
    'TLS_CERT_DIR',
  ]) {
    const override = process.env[key];
    if (override !== undefined) values.set(key, override);
  }
  return values;
}

function loadCertificate(dir: string | undefined): CertificateFacts | null {
  if (dir === undefined || dir === '') return null;
  const certPath = resolve(dir, 'fullchain.pem');
  if (!existsSync(certPath)) return null;
  const keyPath = resolve(dir, 'privkey.pem');
  return {
    certificatePem: readFileSync(certPath, 'utf8'),
    privateKeyMode: existsSync(keyPath) ? statSync(keyPath).mode & 0o777 : null,
  };
}

function hostFacts(): HostFacts {
  const attempt = <T>(read: () => T): T | null => {
    try {
      return read();
    } catch {
      return null;
    }
  };
  return {
    maxMapCount: attempt(() =>
      Number.parseInt(readFileSync('/proc/sys/vm/max_map_count', 'utf8').trim(), 10),
    ),
    composeVersion: attempt(() =>
      execFileSync('docker', ['compose', 'version', '--short'], {
        encoding: 'utf8',
        timeout: 10_000,
      }).trim(),
    ),
  };
}

try {
  const env = loadEnv();
  const findings = runPreflight({
    env,
    certificate: loadCertificate(env.get('TLS_CERT_DIR')),
    host: hostFacts(),
    now: new Date(),
  });
  for (const finding of findings) {
    logger[finding.level === 'error' ? 'error' : 'warn']({ check: finding.check }, finding.message);
  }
  const errors = findings.filter((finding) => finding.level === 'error').length;
  const warnings = findings.length - errors;
  if (errors > 0) {
    logger.error({ errors, warnings }, 'preflight failed: fix the errors before deploying');
    process.exit(1);
  }
  logger.info({ warnings }, 'preflight passed');
} catch (error) {
  logger.fatal({ err: error }, 'preflight could not run');
  process.exit(1);
}
