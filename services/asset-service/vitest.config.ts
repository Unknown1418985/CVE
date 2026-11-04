import { createNodeVitestConfig } from '@cve/testing/vitest';
import { defineConfig } from 'vitest/config';

export default defineConfig(createNodeVitestConfig({ decorators: true }));
