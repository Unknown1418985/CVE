import { createRequire } from 'node:module';

import type { ServiceName } from '@cve/contracts';

// Resolves to the package root from both src/ (tests) and dist/ (runtime).
const packageJson = createRequire(import.meta.url)('../package.json') as { version: string };

export const SERVICE_NAME = 'api-gateway' satisfies ServiceName;
export const SERVICE_VERSION = packageJson.version;
