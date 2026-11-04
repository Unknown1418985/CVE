import { BACKEND_SERVICE_NAMES } from '@cve/contracts';

import { serviceUrlVariable } from '../src/config/env.js';

export function gatewayTestEnv(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    HEALTH_CHECK_TIMEOUT_MS: '500',
    ...Object.fromEntries(
      BACKEND_SERVICE_NAMES.map((service) => [
        serviceUrlVariable(service),
        `http://${service}.internal:4000/`,
      ]),
    ),
    ...overrides,
  };
}
