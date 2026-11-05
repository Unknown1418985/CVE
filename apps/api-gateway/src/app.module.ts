import { Module, type DynamicModule } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';

import { authGuards, AuthModule, type SessionChecker, type TokenVerifier } from '@cve/auth';
import { createLogger, type Logger } from '@cve/logger';
import { HealthModule } from '@cve/shared';

import { createGatewayAuth } from './auth/gateway-auth.js';
import { UserThrottlerGuard } from './auth/user-throttler.guard.js';
import { serviceRegistryFromEnv, type Env } from './config/env.js';
import { AssetProxyController } from './proxy/asset-proxy.controller.js';
import { CveProxyController } from './proxy/cve-proxy.controller.js';
import { IdentityProxyController } from './proxy/identity-proxy.controller.js';
import { IntelligenceProxyController } from './proxy/intelligence-proxy.controller.js';
import { PocProxyController } from './proxy/poc-proxy.controller.js';
import { PROXY_OPTIONS } from './proxy/proxy.constants.js';
import { ProxyService, type ProxyOptions } from './proxy/proxy.service.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';
import type { HttpFetch } from './services-health/services-health.constants.js';
import { ServicesHealthModule } from './services-health/services-health.module.js';

export interface AppModuleOverrides {
  /** Used for backend calls and health checks (tests). */
  readonly fetch?: HttpFetch;
  readonly verifier?: TokenVerifier;
  /** `null` disables the session check (tests); omitted builds it from the environment. */
  readonly sessionChecker?: (SessionChecker & { invalidate?(sessionId: string): void }) | null;
  readonly logger?: Logger;
}

/**
 * Root module of the API Gateway. Guard order: authentication → per-user rate limiting →
 * authorization. Every route is private unless marked `@Public()`.
 */
@Module({})
export class AppModule {
  static register(env: Env, overrides: AppModuleOverrides = {}): DynamicModule {
    const logger =
      overrides.logger ?? createLogger({ service: SERVICE_NAME, level: env.LOG_LEVEL });
    const auth = createGatewayAuth(env);
    const verifier = overrides.verifier ?? auth.verifier;
    const sessionChecker =
      overrides.sessionChecker === null
        ? undefined
        : (overrides.sessionChecker ?? auth.sessionChecker);
    const registry = serviceRegistryFromEnv(env);
    const fetchFn = overrides.fetch ?? globalThis.fetch.bind(globalThis);

    const proxyOptions: ProxyOptions = {
      registry,
      fetch: fetchFn,
      timeoutMs: env.PROXY_TIMEOUT_MS,
      logger,
      ...(sessionChecker?.invalidate
        ? { onSessionEnded: (sessionId: string) => sessionChecker.invalidate?.(sessionId) }
        : {}),
    };

    return {
      module: AppModule,
      imports: [
        AuthModule.forRoot({
          verifier,
          logger,
          ...(sessionChecker ? { sessionChecker } : {}),
        }),
        ThrottlerModule.forRoot({
          throttlers: [{ ttl: env.RATE_LIMIT_TTL_MS, limit: env.RATE_LIMIT_MAX }],
        }),
        HealthModule.forRoot({
          service: SERVICE_NAME,
          version: SERVICE_VERSION,
          timeoutMs: env.HEALTH_CHECK_TIMEOUT_MS,
          indicators: [],
        }),
        ServicesHealthModule.register({
          registry,
          timeoutMs: env.HEALTH_CHECK_TIMEOUT_MS,
          fetch: fetchFn,
        }),
      ],
      controllers: [
        IdentityProxyController,
        CveProxyController,
        IntelligenceProxyController,
        AssetProxyController,
        PocProxyController,
      ],
      providers: [
        { provide: PROXY_OPTIONS, useValue: proxyOptions },
        ProxyService,
        ...authGuards([{ provide: APP_GUARD, useClass: UserThrottlerGuard }]),
      ],
    };
  }
}
