import type { LoggerService, LogLevel } from '@nestjs/common';
import type { Logger } from 'pino';

type PinoMethod = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace';

const NEST_TO_PINO: Readonly<Record<LogLevel, PinoMethod>> = {
  fatal: 'fatal',
  error: 'error',
  warn: 'warn',
  log: 'info',
  debug: 'debug',
  verbose: 'trace',
};

/**
 * Adapts a Pino logger to NestJS's `LoggerService` so framework logs are structured JSON.
 * Nest passes the logging context (usually a class name) as the last string argument.
 */
export class PinoNestLogger implements LoggerService {
  constructor(private readonly logger: Logger) {}

  log(message: unknown, ...optionalParams: unknown[]): void {
    this.write('log', message, optionalParams);
  }

  error(message: unknown, ...optionalParams: unknown[]): void {
    this.write('error', message, optionalParams);
  }

  warn(message: unknown, ...optionalParams: unknown[]): void {
    this.write('warn', message, optionalParams);
  }

  debug(message: unknown, ...optionalParams: unknown[]): void {
    this.write('debug', message, optionalParams);
  }

  verbose(message: unknown, ...optionalParams: unknown[]): void {
    this.write('verbose', message, optionalParams);
  }

  fatal(message: unknown, ...optionalParams: unknown[]): void {
    this.write('fatal', message, optionalParams);
  }

  private write(level: LogLevel, message: unknown, params: unknown[]): void {
    const method = NEST_TO_PINO[level];
    const rest = [...params];
    const last = rest.at(-1);
    const context = typeof last === 'string' ? (rest.pop() as string) : undefined;

    // Nest passes an error stack as the first optional param for `error`.
    const stack = level === 'error' && typeof rest[0] === 'string' ? rest.shift() : undefined;

    const bindings: Record<string, unknown> = {};
    if (context !== undefined) bindings['context'] = context;
    if (stack !== undefined) bindings['stack'] = stack;
    if (rest.length > 0) bindings['params'] = rest;

    if (message instanceof Error) {
      this.logger[method]({ ...bindings, err: message }, message.message);
    } else if (typeof message === 'string') {
      this.logger[method](bindings, message);
    } else {
      this.logger[method]({ ...bindings, data: message }, 'log');
    }
  }
}
