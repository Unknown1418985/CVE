import { readFileSync } from 'node:fs';

import { createLogger } from '@cve/logger';

import { loadProvisionerEnv, rabbitPasswordFor } from './env.js';
import { HttpClient, waitUntil } from './http-client.js';
import { applyOpenSearchPlan, buildOpenSearchPlan } from './opensearch.js';
import { applyRabbitMqPlan, buildRabbitMqPlan } from './rabbitmq.js';

const logger = createLogger({ service: 'infra-provisioner' });

async function main(): Promise<void> {
  const env = loadProvisionerEnv();
  logger.level = env.LOG_LEVEL;
  const onRetry = (target: string) => (error: unknown, delayMs: number) => {
    logger.info(
      { target, delayMs, reason: error instanceof Error ? error.message : String(error) },
      'waiting for dependency',
    );
  };

  if (env.PROVISION_TARGETS.includes('rabbitmq')) {
    const client = new HttpClient({
      baseUrl: env.RABBITMQ_MANAGEMENT_URL,
      username: env.RABBITMQ_ADMIN_USER,
      password: env.RABBITMQ_ADMIN_PASSWORD,
      timeoutMs: env.HTTP_TIMEOUT_MS,
    });
    await waitUntil(
      'RabbitMQ management API',
      async () => {
        await client.expect('GET', '/api/overview');
      },
      { timeoutMs: env.PROVISION_WAIT_TIMEOUT_MS, onRetry: onRetry('rabbitmq') },
    );
    await applyRabbitMqPlan(
      client,
      buildRabbitMqPlan(env.RABBITMQ_ADMIN_USER, (service) => rabbitPasswordFor(env, service)),
      logger,
    );
  }

  if (env.PROVISION_TARGETS.includes('opensearch')) {
    const client = new HttpClient({
      baseUrl: env.OPENSEARCH_URL,
      username: env.OPENSEARCH_ADMIN_USER,
      password: env.OPENSEARCH_ADMIN_PASSWORD,
      timeoutMs: env.HTTP_TIMEOUT_MS,
      ...(env.OPENSEARCH_URL.startsWith('https:')
        ? { ca: readFileSync(env.OPENSEARCH_CA_FILE, 'utf8') }
        : {}),
    });
    await waitUntil(
      'OpenSearch security API',
      async () => {
        await client.expect('GET', '/_cluster/health?wait_for_status=yellow&timeout=5s');
        await client.expect('GET', '/_plugins/_security/api/account');
      },
      { timeoutMs: env.PROVISION_WAIT_TIMEOUT_MS, onRetry: onRetry('opensearch') },
    );
    await applyOpenSearchPlan(
      client,
      buildOpenSearchPlan(env.CVE_SERVICE_OPENSEARCH_PASSWORD),
      logger,
    );
  }

  logger.info({ targets: env.PROVISION_TARGETS }, 'provisioning complete');
}

main().catch((error: unknown) => {
  logger.fatal({ err: error }, 'provisioning failed');
  process.exit(1);
});
