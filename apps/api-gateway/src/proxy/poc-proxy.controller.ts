import { Controller, Delete, Get, Patch, Post, Put, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiExcludeController } from '@nestjs/swagger';
import type { Request, Response } from 'express';

import { RequirePermissions } from '@cve/auth';

import { ProxyService } from './proxy.service.js';

const SERVICE = 'poc-service';
const ROUTES = [
  'poc-repositories',
  'poc-repositories/*path',
  'poc-owners',
  'poc-owners/*path',
  'poc-associations',
  'poc-associations/*path',
  'poc-artifacts',
  'poc-artifacts/*path',
  'poc-references',
  'poc-references/*path',
  'poc-connectors',
  'poc-connectors/*path',
  'poc-discovery-runs',
  'poc-discovery-runs/*path',
];

/**
 * Public routes of the PoC Service (repository metadata, CVE associations, artifacts, discovery
 * runs). Reads need `poc:read`, writes `poc:manage`; the PoC Service validates the token again and
 * applies finer rules per route (malicious artifacts need `quarantine:read`).
 */
@ApiExcludeController()
@ApiBearerAuth()
@Controller()
export class PocProxyController {
  constructor(private readonly proxy: ProxyService) {}

  @Get(ROUTES)
  @RequirePermissions('poc:read')
  read(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Post(ROUTES)
  @RequirePermissions('poc:manage')
  create(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Put(ROUTES)
  @RequirePermissions('poc:manage')
  replace(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Patch(ROUTES)
  @RequirePermissions('poc:manage')
  update(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Delete(ROUTES)
  @RequirePermissions('poc:manage')
  remove(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }
}
