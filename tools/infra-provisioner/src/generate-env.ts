import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { createLogger } from '@cve/logger';

import { fillSecrets, parseEnvFile, renderDevEnvFiles } from './env-file.js';

/**
 * `pnpm env:generate [--force]` — creates `.env` from `.env.example` with random secrets and
 * writes per-application `.env` files for `pnpm dev`. Existing files are kept unless --force.
 */
const logger = createLogger({ service: 'env-generator' });
const root = process.cwd();
const force = process.argv.includes('--force');

function write(relativePath: string, content: string): void {
  const target = resolve(root, relativePath);
  if (existsSync(target) && !force) {
    logger.info({ file: relativePath }, 'file exists, keeping it (use --force to overwrite)');
    return;
  }
  writeFileSync(target, content, { mode: 0o600 });
  logger.info({ file: relativePath }, 'file written');
}

try {
  const examplePath = resolve(root, '.env.example');
  if (!existsSync(examplePath))
    throw new Error('Run this from the repository root (.env.example not found)');
  write('.env', fillSecrets(readFileSync(examplePath, 'utf8')));
  const values = parseEnvFile(readFileSync(resolve(root, '.env'), 'utf8'));
  for (const [path, content] of Object.entries(renderDevEnvFiles(values))) {
    write(path, content);
  }
} catch (error) {
  logger.fatal({ err: error }, 'failed to generate environment files');
  process.exit(1);
}
