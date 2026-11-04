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
    ...overrides,
  };
}
