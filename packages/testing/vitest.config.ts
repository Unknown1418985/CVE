import { defineConfig } from 'vitest/config';

import { createNodeVitestConfig } from './src/vitest.js';

export default defineConfig(createNodeVitestConfig());
