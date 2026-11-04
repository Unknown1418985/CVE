/** Environment values for a backend service under test; no real infrastructure is contacted. */
export function buildServiceTestEnv(
  serviceName: string,
  overrides: Readonly<Record<string, string>> = {},
): Record<string, string> {
  const database = serviceName.replaceAll('-', '_');
  return {
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    // Port 9 (discard) on loopback is closed in test environments, so TCP checks fail fast.
    DATABASE_URL: `postgresql://${database}:test-password@127.0.0.1:9/${database}`,
    REDIS_URL: 'redis://127.0.0.1:9',
    RABBITMQ_URL: 'amqp://test:test@127.0.0.1:9',
    HEALTH_CHECK_TIMEOUT_MS: '500',
    // Object storage and search settings are only read by the services that use them.
    S3_ENDPOINT: 'http://127.0.0.1:9',
    S3_ACCESS_KEY_ID: serviceName,
    S3_SECRET_ACCESS_KEY: 'test-secret-key-0000',
    OPENSEARCH_URL: 'https://127.0.0.1:9',
    OPENSEARCH_USERNAME: serviceName,
    OPENSEARCH_PASSWORD: 'test-password-0000',
    ...overrides,
  };
}
