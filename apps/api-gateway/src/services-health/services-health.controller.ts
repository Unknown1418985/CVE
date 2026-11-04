import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

import type { PlatformHealth } from '@cve/contracts';

import { ServicesHealthService } from './services-health.service.js';

@ApiTags('health')
@Controller('health/services')
export class ServicesHealthController {
  constructor(private readonly servicesHealth: ServicesHealthService) {}

  @Get()
  @ApiOperation({
    summary: 'Readiness of every backend service',
    description:
      'Always answers 200 while the gateway is running; inspect `data.status` for the platform status.',
  })
  async check(): Promise<{ data: PlatformHealth }> {
    return { data: await this.servicesHealth.check() };
  }
}
