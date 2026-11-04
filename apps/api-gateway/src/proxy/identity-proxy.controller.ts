import { All, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';

import { RequirePermissions } from '@cve/auth';
import { DEFAULT_RATE_LIMIT } from '@cve/security';

import { ProxyService } from './proxy.service.js';

const SERVICE = 'identity-service';

/**
 * Public routes of the Identity Service. The gateway enforces authentication and coarse
 * permissions here; the Identity Service re-validates the token and applies fine-grained rules.
 */
@ApiExcludeController()
@ApiBearerAuth()
@Controller()
export class IdentityProxyController {
  constructor(private readonly proxy: ProxyService) {}

  @All(['me', 'me/*path'])
  me(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Post('auth/logout')
  @Throttle({ default: { limit: DEFAULT_RATE_LIMIT.authLimit, ttl: DEFAULT_RATE_LIMIT.ttlMs } })
  logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Get(['roles', 'permissions'])
  catalog(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @All(['users', 'users/*path'])
  @RequirePermissions('user:read')
  users(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Get(['audit-logs', 'audit-logs/*path'])
  @RequirePermissions('audit:read')
  audit(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }
}
