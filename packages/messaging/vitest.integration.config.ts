import { loadRootEnvFile } from '@cve/testing/integration';
import { defineConfig } from 'vitest/config';

loadRootEnvFile(import.meta.dirname);

/** Runs against the live Compose stack; see docs/infrastructure.md ("Integration tests"). */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/integration/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false,
  },
});
