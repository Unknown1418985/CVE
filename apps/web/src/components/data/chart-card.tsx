'use client';

import type { ReactElement, ReactNode } from 'react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export function ChartCard({
  title,
  description,
  children,
  footer,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}): ReactElement {
  return (
    <Card className="flex flex-col">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description === undefined ? null : <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="flex-1">{children}</CardContent>
      {footer === undefined ? null : (
        <div className="border-t border-border px-5 py-3 text-xs text-muted-foreground">
          {footer}
        </div>
      )}
    </Card>
  );
}

export const chartTooltipStyle = {
  contentStyle: {
    background: 'var(--card)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    color: 'var(--card-foreground)',
    fontSize: 12,
  },
  itemStyle: { color: 'var(--card-foreground)' },
  labelStyle: { color: 'var(--muted-foreground)' },
  cursor: { fill: 'var(--muted)', opacity: 0.4 },
} as const;

export const axisProps = {
  stroke: 'var(--chart-axis)',
  tick: { fill: 'var(--chart-axis)', fontSize: 11 },
  tickLine: false,
  axisLine: false,
} as const;
