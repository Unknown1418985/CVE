import type { ReactElement } from 'react';

import { HealthStatusBadge } from '@/components/health-status-badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { getServerEnv } from '@/lib/env';
import { fetchPlatformHealth } from '@/lib/platform-health';

// Health must be live on every request; never serve a cached status.
export const dynamic = 'force-dynamic';

export default async function OverviewPage(): Promise<ReactElement> {
  const result = await fetchPlatformHealth(getServerEnv().API_GATEWAY_INTERNAL_URL);

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Vulnerability intelligence dashboards become available as data sources are connected. This
          page currently shows the live status of platform services.
        </p>
      </header>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <CardTitle>Platform services</CardTitle>
            {result.ok ? <HealthStatusBadge status={result.health.status} /> : null}
          </div>
          <CardDescription>
            Readiness reported by each service through the API Gateway.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {result.ok ? (
            <ul className="divide-y divide-border">
              {result.health.services.map((service) => (
                <li
                  key={service.service}
                  className="flex flex-wrap items-center justify-between gap-2 py-3"
                >
                  <div>
                    <p className="text-sm font-medium">{service.service}</p>
                    {service.message ? (
                      <p className="text-xs text-muted-foreground">{service.message}</p>
                    ) : null}
                  </div>
                  <HealthStatusBadge status={service.status} />
                </li>
              ))}
            </ul>
          ) : (
            <div
              role="alert"
              className="rounded-md border border-status-down/40 bg-status-down/10 p-4 text-sm"
            >
              <p className="font-medium text-status-down">Service status unavailable</p>
              <p className="mt-1 text-muted-foreground">{result.error}.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
