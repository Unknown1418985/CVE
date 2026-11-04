import { defineConfig } from 'vitest/config';

/** Static checks of the Compose definition; no containers are started. */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/static/**/*.test.ts'],
  },
});
