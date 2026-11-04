import {
  BadGatewayException,
  ConflictException,
  HttpException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';

import { IdentityProviderError } from '../keycloak/identity-provider.js';

/** Maps identity-provider failures to HTTP errors without leaking upstream details. */
export function toHttpError(error: unknown): unknown {
  if (!(error instanceof IdentityProviderError)) return error;
  switch (error.status) {
    case 404:
      return new NotFoundException('User not found');
    case 409:
      return new ConflictException('The identity provider rejected a conflicting change');
    case 503:
      return new ServiceUnavailableException('The identity provider is unavailable');
    case 400:
      return new HttpException('Invalid identifier', 400);
    default:
      return new BadGatewayException('The identity provider returned an error');
  }
}

export async function withIdpErrors<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    throw toHttpError(error);
  }
}
