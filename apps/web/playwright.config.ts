import { defineConfig, devices } from '@playwright/test';

const WEB_PORT = 3100;
const MOCK_PORT = 4100;
const reuse = process.env['CI'] === undefined;

/**
 * End-to-end tests run the real web server (production build) against a mock Keycloak and
 * API Gateway (`e2e/mock/server.ts`), so the BFF session, proxy and UI are exercised together
 * without the backend services.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !reuse,
  retries: reuse ? 0 : 1,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  reporter: reuse ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://localhost:${String(WEB_PORT)}`,
    trace: 'off',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: `node e2e/mock/server.ts`,
      url: `http://localhost:${String(MOCK_PORT)}/health`,
      reuseExistingServer: reuse,
      env: { MOCK_PORT: String(MOCK_PORT) },
    },
    {
      // The standalone server is what the container image runs; static assets are copied as in the image.
      command:
        'next build && cp -R .next/static .next/standalone/apps/web/.next/ && node .next/standalone/apps/web/server.js',
      url: `http://localhost:${String(WEB_PORT)}/api/health`,
      reuseExistingServer: reuse,
      timeout: 300_000,
      env: {
        PUBLIC_ORIGIN: `http://localhost:${String(WEB_PORT)}`,
        API_GATEWAY_INTERNAL_URL: `http://localhost:${String(MOCK_PORT)}`,
        KEYCLOAK_PUBLIC_URL: `http://localhost:${String(MOCK_PORT)}/auth`,
        WEB_SESSION_SECRET: 'e2e-only-session-secret-0123456789abcdef',
        LOG_LEVEL: 'warn',
        PORT: String(WEB_PORT),
        HOSTNAME: 'localhost',
      },
    },
  ],
});
