import { Controller, Get, HttpStatus, Res } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';

import type { HealthReport } from '@cve/contracts';

import { HealthService } from './health.service.js';

export interface HealthResponse {
  data: HealthReport;
}

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(private readonly health: HealthService) {}

  @Get('live')
  @ApiOperation({ summary: 'Liveness probe' })
  live(): HealthResponse {
    return { data: this.health.liveness() };
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe (checks dependencies); 503 when down' })
  async ready(@Res({ passthrough: true }) res: Response): Promise<HealthResponse> {
    return this.readinessResponse(res);
  }

  @Get()
  @ApiOperation({ summary: 'Health report (same as readiness)' })
  async report(@Res({ passthrough: true }) res: Response): Promise<HealthResponse> {
    return this.readinessResponse(res);
  }

  private async readinessResponse(res: Response): Promise<HealthResponse> {
    const report = await this.health.readiness();
    res.status(report.status === 'down' ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.OK);
    return { data: report };
  }
}
