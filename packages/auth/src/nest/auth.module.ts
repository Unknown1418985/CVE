import { Global, Module, type DynamicModule, type Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';

import { AUTH_OPTIONS } from './auth.constants.js';
import type { AuthModuleOptions } from './auth.options.js';
import { AuthenticationGuard } from './authentication.guard.js';
import { AuthorizationGuard } from './authorization.guard.js';

/** Provides the auth options and guards. Register the guards globally with {@link authGuards}. */
@Global()
@Module({})
export class AuthModule {
  static forRoot(options: AuthModuleOptions): DynamicModule {
    return {
      module: AuthModule,
      providers: [
        { provide: AUTH_OPTIONS, useValue: options },
        AuthenticationGuard,
        AuthorizationGuard,
      ],
      exports: [AUTH_OPTIONS, AuthenticationGuard, AuthorizationGuard],
    };
  }
}

/**
 * Global guard providers in execution order. Pass `between` to run guards (e.g. a per-user
 * rate limiter) after authentication and before authorization.
 */
export function authGuards(between: readonly Provider[] = []): Provider[] {
  return [
    { provide: APP_GUARD, useExisting: AuthenticationGuard },
    ...between,
    { provide: APP_GUARD, useExisting: AuthorizationGuard },
  ];
}
