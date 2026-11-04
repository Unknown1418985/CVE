import { loadRootEnvFile } from '@cve/testing/integration';
import { defineConfig } from 'vitest/config';

loadRootEnvFile(import.meta.dirname);

/** Live checks against the stack started with compose.dev.yaml (see docs/infrastructure.md). */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/live/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false,
  },
});
