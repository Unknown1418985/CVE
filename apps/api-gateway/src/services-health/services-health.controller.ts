import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

import { OptionalPrincipal, type AuthenticatedPrincipal } from '@cve/auth';
import type { PlatformHealth } from '@cve/contracts';
import { Public } from '@cve/shared';

import { ServicesHealthService } from './services-health.service.js';

@ApiTags('health')
@Public()
@Controller('health/services')
export class ServicesHealthController {
  constructor(private readonly servicesHealth: ServicesHealthService) {}

  @Get()
  @ApiOperation({
    summary: 'Readiness of every backend service',
    description:
      'Always answers 200 while the gateway is running; inspect `data.status` for the platform status. Anonymous callers receive only per-service status; dependency reports, versions and error messages require the `platform-health:read` permission.',
  })
  async check(
    @OptionalPrincipal() principal: AuthenticatedPrincipal | undefined,
  ): Promise<{ data: PlatformHealth }> {
    const health = await this.servicesHealth.check();
    if (principal?.permissions.includes('platform-health:read') === true) return { data: health };
    return {
      data: {
        ...health,
        services: health.services.map(({ service, status }) => ({ service, status })),
      },
    };
  }
}
