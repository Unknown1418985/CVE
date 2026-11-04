import { createNodeVitestConfig } from '@cve/testing/vitest';
import { defineConfig } from 'vitest/config';

// Integration suites (test/integration) need PostgreSQL and Redis; they run with
// `pnpm test:integration`.
export default defineConfig(
  createNodeVitestConfig({
    decorators: true,
    include: ['test/*.test.ts', 'test/adapters/*.test.ts'],
  }),
);
