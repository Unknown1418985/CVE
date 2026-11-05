import { Controller, Get, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiExcludeController } from '@nestjs/swagger';
import type { Request, Response } from 'express';

import { RequirePermissions } from '@cve/auth';

import { ProxyService } from './proxy.service.js';

const SERVICE = 'download-service';
const READ_ROUTES = [
  'download-sources',
  'download-requests',
  'download-requests/*path',
  'download-artifacts',
  'download-artifacts/*path',
];
const SCHEDULE_ROUTES = [
  'download-requests',
  'download-requests/:requestId/retry',
  'download-requests/:requestId/cancel',
];
const QUARANTINE_ROUTES = [
  'download-artifacts/:artifactId/rescan',
  'download-artifacts/:artifactId/lifecycle',
];

/**
 * Public routes of the Download Service. Reads need `download:read`, scheduling
 * `download:schedule`, release decisions and rescans `quarantine:manage`, and artifact content
 * `artifact:download`. The Download Service validates the token again and hides quarantined
 * artifacts from users without `quarantine:read`. Content is streamed, never buffered.
 */
@ApiExcludeController()
@ApiBearerAuth()
@Controller()
export class DownloadProxyController {
  constructor(private readonly proxy: ProxyService) {}

  // Declared before the generic read route so that it matches first.
  @Get('download-artifacts/:artifactId/content')
  @RequirePermissions('artifact:download')
  content(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.stream(SERVICE, req, res);
  }

  @Get(READ_ROUTES)
  @RequirePermissions('download:read')
  read(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Post(SCHEDULE_ROUTES)
  @RequirePermissions('download:schedule')
  schedule(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }

  @Post(QUARANTINE_ROUTES)
  @RequirePermissions('quarantine:manage')
  manage(@Req() req: Request, @Res() res: Response): Promise<void> {
    return this.proxy.forward(SERVICE, req, res);
  }
}
