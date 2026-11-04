import { execFileSync } from 'node:child_process';

import { createLogger } from '@cve/logger';

import { evaluateStack, parseComposePs } from './stack-status.js';

/**
 * `pnpm infra:wait` — blocks until the Compose stack is ready (see evaluateStack). Honours the
 * usual COMPOSE_FILE / COMPOSE_PROFILES variables, e.g.
 *   COMPOSE_FILE=compose.yaml:compose.dev.yaml pnpm infra:wait
 * `docker compose up --wait` cannot be used because it treats finished provisioning jobs as
 * failures.
 */
const logger = createLogger({ service: 'stack-wait' });
const timeoutMs = Number(process.env['STACK_WAIT_TIMEOUT_MS'] ?? 600_000);
const deadline = Date.now() + timeoutMs;

function poll(): void {
  const output = execFileSync('docker', ['compose', 'ps', '--all', '--format', 'json'], {
    encoding: 'utf8',
  });
  const verdict = evaluateStack(parseComposePs(output));
  if (verdict.kind === 'ready') {
    logger.info('stack is ready');
    return;
  }
  if (verdict.kind === 'failed') {
    logger.fatal({ reason: verdict.reason }, 'stack failed to start');
    process.exit(1);
  }
  if (Date.now() > deadline) {
    logger.fatal({ pending: verdict.pending, timeoutMs }, 'timed out waiting for the stack');
    process.exit(1);
  }
  logger.info({ pending: verdict.pending }, 'waiting for containers');
  setTimeout(poll, 3_000);
}

try {
  poll();
} catch (error) {
  logger.fatal({ err: error }, 'failed to inspect the stack');
  process.exit(1);
}
