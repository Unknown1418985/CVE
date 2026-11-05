import {
  BadRequestException,
  ConflictException,
  NotFoundException,
  PreconditionFailedException,
} from '@nestjs/common';
import type { Response } from 'express';
import { z } from 'zod';

import { RequestValidationException } from '@cve/shared';

/** `If-Match` precondition: a resource version, `*` (must exist) or none. */
export type Precondition = number | '*' | undefined;

/** Parses `If-Match`: `*` or a strong ETag produced by this service (`"<version>"`). */
export function parsePrecondition(header: string | undefined): Precondition {
  if (header === undefined) return undefined;
  const value = header.trim();
  if (value === '*') return '*';
  const match = /^"([1-9]\d{0,9})"$/.exec(value);
  if (!match) {
    throw new BadRequestException({
      message: 'Invalid If-Match header',
      details: [{ path: 'If-Match', message: 'expected * or an ETag such as "3"' }],
    });
  }
  return Number(match[1]);
}

/** Throws 412 when a numeric precondition does not match the stored version. */
export function checkPrecondition(precondition: Precondition, version: number): void {
  if (typeof precondition === 'number' && precondition !== version) {
    throw new PreconditionFailedException({
      message: `The resource is at version ${String(version)}, not ${String(precondition)}`,
      details: [{ path: 'If-Match', message: 'stale ETag; fetch the resource again' }],
    });
  }
}

export const etag = (version: number) => `"${String(version)}"`;

/** Sends a versioned resource with its ETag. */
export function versioned<T extends { version: number }>(
  res: Response,
  resource: T,
  status: number,
  location?: string,
): { data: T } {
  res.status(status);
  res.setHeader('ETag', etag(resource.version));
  res.setHeader('Cache-Control', 'no-store');
  if (location !== undefined) res.setHeader('Location', location);
  return { data: resource };
}

export function conflict(message: string, path = ''): ConflictException {
  return new ConflictException({ message, details: [{ path, message }] });
}

export function notFound(message: string): NotFoundException {
  return new NotFoundException({ message });
}

export function badField(path: string, message: string): BadRequestException {
  return new BadRequestException({
    message: 'Request validation failed',
    details: [{ path, message }],
  });
}

const uuidParam = z.uuid({ message: 'must be a UUID' });

/** Validates a UUID path parameter; the error names the parameter. */
export function parseUuid(value: string, name: string): string {
  const result = uuidParam.safeParse(value);
  if (!result.success)
    throw new RequestValidationException([{ path: name, message: 'must be a UUID' }]);
  return result.data;
}
