import type { NextFunction, Request, Response } from 'express';

import { CORRELATION_ID_HEADER } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { resolveCorrelationId } from '@cve/security';

const correlationIds = new WeakMap<Request, string>();

export function getCorrelationId(req: Request): string | undefined {
  return correlationIds.get(req);
}

export interface RequestContextMiddlewareOptions {
  readonly logger: Logger;
  /** Paths logged at debug level (e.g. health probes) to keep logs readable. */
  readonly quietPathPrefixes?: readonly string[];
}

/**
 * Assigns a correlation ID to every request (reusing a valid incoming one), echoes it in the
 * response, and writes one structured log line per completed request.
 */
export function createRequestContextMiddleware(options: RequestContextMiddlewareOptions) {
  const quiet = options.quietPathPrefixes ?? [];
  return (req: Request, res: Response, next: NextFunction): void => {
    const correlationId = resolveCorrelationId(req.headers[CORRELATION_ID_HEADER]);
    correlationIds.set(req, correlationId);
    res.setHeader(CORRELATION_ID_HEADER, correlationId);

    const started = performance.now();
    res.once('finish', () => {
      const entry = {
        correlationId,
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        durationMs: Math.round(performance.now() - started),
      };
      if (quiet.some((prefix) => req.path.startsWith(prefix))) {
        options.logger.debug(entry, 'request completed');
      } else if (res.statusCode >= 500) {
        options.logger.error(entry, 'request completed');
      } else {
        options.logger.info(entry, 'request completed');
      }
    });
    next();
  };
}
