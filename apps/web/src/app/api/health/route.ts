import { NextResponse } from 'next/server';

import type { HealthReport } from '@cve/contracts';

import packageJson from '../../../../package.json' with { type: 'json' };

export const dynamic = 'force-dynamic';

/** Liveness of the web frontend itself (does not depend on the API Gateway). */
export function GET(): NextResponse<{ data: HealthReport }> {
  return NextResponse.json({
    data: {
      service: 'web',
      version: packageJson.version,
      status: 'ok',
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
      checks: [],
    },
  });
}
