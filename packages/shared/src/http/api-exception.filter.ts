import {
  Catch,
  HttpException,
  HttpStatus,
  type ArgumentsHost,
  type ExceptionFilter,
} from '@nestjs/common';
import type { Request, Response } from 'express';

import type { ApiErrorDetail, ApiErrorResponse } from '@cve/contracts';
import type { Logger } from '@cve/logger';

import { getCorrelationId } from './correlation-id.js';

/** Converts an HTTP status into a stable machine-readable code, e.g. 404 → NOT_FOUND. */
export function errorCodeForStatus(status: number): string {
  const name = (HttpStatus as unknown as Record<number, string | undefined>)[status];
  return name ?? (status >= 500 ? 'INTERNAL_SERVER_ERROR' : 'HTTP_ERROR');
}

function extractMessage(exception: HttpException): {
  message: string;
  details?: ApiErrorDetail[];
} {
  const response = exception.getResponse();
  if (typeof response === 'string') return { message: response };
  if (typeof response === 'object') {
    const body = response as { message?: unknown; details?: unknown };
    if (Array.isArray(body.message)) {
      const messages = body.message.filter((m): m is string => typeof m === 'string');
      return {
        message: 'Request validation failed',
        details: messages.map((message) => ({ path: '', message })),
      };
    }
    if (typeof body.message === 'string') return { message: body.message };
  }
  return { message: exception.message };
}

/** Produces the consistent error envelope for every unhandled exception. */
@Catch()
export class ApiExceptionFilter implements ExceptionFilter {
  constructor(private readonly logger: Logger) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();
    const correlationId = getCorrelationId(req);

    let status: number = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'An unexpected error occurred';
    let details: ApiErrorDetail[] | undefined;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      ({ message, details } = extractMessage(exception));
    }

    if (status >= 500) {
      this.logger.error(
        { err: exception, correlationId, path: req.path, method: req.method },
        'unhandled exception',
      );
    }

    const body: ApiErrorResponse = {
      error: {
        code: errorCodeForStatus(status),
        message,
        ...(details ? { details } : {}),
      },
      ...(correlationId ? { correlationId } : {}),
      timestamp: new Date().toISOString(),
    };
    res.status(status).json(body);
  }
}
