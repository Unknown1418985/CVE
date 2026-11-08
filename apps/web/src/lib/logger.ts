import 'server-only';

import { createLogger, type Logger } from '@cve/logger';

/** Structured JSON logger of the web server (Pino, with the platform's redaction rules). */
export const logger: Logger = createLogger({
  service: 'web',
  level: process.env['LOG_LEVEL'] ?? (process.env.NODE_ENV === 'test' ? 'silent' : 'info'),
});
