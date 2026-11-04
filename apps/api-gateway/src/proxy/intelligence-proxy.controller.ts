import { Controller, Get, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiExcludeController } from '@nestjs/swagger';
import type { Request, Response } from 'express';

import { RequirePermissions } from '@cve/auth';

import { ProxyService } from './proxy.service.js';

const SERVICE = 'intelligence-service';
const ROUTES = ['sources', 'sources/*path', 'sync-runs', 'sync-runs/*path'];

/**
 * Public routes of the Intelligence Service (data sources and synchronisation history). Reads
 * need `data-source:read`; queuing runs and retries needs `data-source:manage`. The service
 * validates the token again and applies the same permissions per route.
 */
@ApiExcludeController()
@ApiBearerAuth()
@Controller()
export class IntelligenceProxyController {
  constructor(private readonly proxy: ProxyService) {}

  @Get(ROUTES)
  @RequirePermissions('data-source:read')
  read(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Post(ROUTES)
  @RequirePermissions('data-source:manage')
  trigger(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }
}
