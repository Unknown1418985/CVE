import { pino, type DestinationStream, type Logger, type LoggerOptions } from 'pino';

/** Paths that must never reach log sinks. Matching is case-sensitive, so common variants are listed. */
export const DEFAULT_REDACT_PATHS: readonly string[] = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["set-cookie"]',
  'req.headers["x-api-key"]',
  'res.headers["set-cookie"]',
  '*.password',
  '*.passwd',
  '*.secret',
  '*.token',
  '*.accessToken',
  '*.refreshToken',
  '*.apiKey',
  '*.authorization',
  '*.databaseUrl',
  'password',
  'secret',
  'token',
  'apiKey',
];

export const REDACTED_VALUE = '[REDACTED]';

export interface CreateLoggerOptions {
  /** Stable service name added to every record. */
  readonly service: string;
  readonly level?: LoggerOptions['level'];
  /** Human-readable output for local development. Never enable in production. */
  readonly pretty?: boolean;
  /** Additional redaction paths. */
  readonly redact?: readonly string[];
  /** Custom destination (used by tests). */
  readonly destination?: DestinationStream;
}

export type { Logger } from 'pino';

export function createLogger(options: CreateLoggerOptions): Logger {
  const loggerOptions: LoggerOptions = {
    level: options.level ?? 'info',
    base: { service: options.service },
    messageKey: 'message',
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level: (label) => ({ level: label }),
    },
    redact: {
      paths: [...DEFAULT_REDACT_PATHS, ...(options.redact ?? [])],
      censor: REDACTED_VALUE,
    },
  };

  if (options.destination) {
    return pino(loggerOptions, options.destination);
  }

  if (options.pretty) {
    return pino({
      ...loggerOptions,
      transport: { target: 'pino-pretty', options: { messageKey: 'message', colorize: true } },
    });
  }

  return pino(loggerOptions);
}
