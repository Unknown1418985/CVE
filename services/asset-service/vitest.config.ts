import { createNodeVitestConfig } from '@cve/testing/vitest';
import { defineConfig } from 'vitest/config';

export default defineConfig(
  createNodeVitestConfig({ decorators: true, include: ['src/**/*.test.ts', 'test/*.test.ts'] }),
);
