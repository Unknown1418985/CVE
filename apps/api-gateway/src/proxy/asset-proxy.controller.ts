import { Controller, Delete, Get, Patch, Post, Put, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiExcludeController } from '@nestjs/swagger';
import type { Request, Response } from 'express';

import { RequirePermissions } from '@cve/auth';

import { ProxyService } from './proxy.service.js';

const SERVICE = 'asset-service';
const ROUTES = [
  'vendors',
  'vendors/*path',
  'products',
  'products/*path',
  'cve-associations',
  'cve-associations/*path',
];

/**
 * Public routes of the Asset Service (vendors, products, CVE associations). Reads need
 * `asset:read`, writes `asset:manage`; the Asset Service validates the token again and applies
 * the same permissions per route.
 */
@ApiExcludeController()
@ApiBearerAuth()
@Controller()
export class AssetProxyController {
  constructor(private readonly proxy: ProxyService) {}

  @Get(ROUTES)
  @RequirePermissions('asset:read')
  read(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Post(ROUTES)
  @RequirePermissions('asset:manage')
  create(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Put(ROUTES)
  @RequirePermissions('asset:manage')
  replace(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Patch(ROUTES)
  @RequirePermissions('asset:manage')
  update(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Delete(ROUTES)
  @RequirePermissions('asset:manage')
  remove(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }
}
