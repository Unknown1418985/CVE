import { BadRequestException } from '@nestjs/common';
import type { z } from 'zod';

import type { ApiErrorDetail } from '@cve/contracts';

/** Raised for invalid input; rendered by `ApiExceptionFilter` with per-field details. */
export class RequestValidationException extends BadRequestException {
  constructor(readonly details: readonly ApiErrorDetail[]) {
    super({ message: 'Request validation failed', details });
  }
}

/** Validates `value` against `schema` and throws a 400 with field-level details on failure. */
export function parseRequest<TSchema extends z.ZodType>(
  schema: TSchema,
  value: unknown,
): z.infer<TSchema> {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new RequestValidationException(
      result.error.issues.map((issue) => ({
        path: issue.path.map(String).join('.'),
        message: issue.message,
      })),
    );
  }
  return result.data;
}
