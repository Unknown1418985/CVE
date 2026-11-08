'use client';

import { BarChart3, Table2 } from 'lucide-react';
import { useState, type ReactElement } from 'react';
import { Bar, BarChart, CartesianGrid, Rectangle, ResponsiveContainer, Tooltip, XAxis, YAxis, type BarShapeProps } from 'recharts';

import { Button } from '@/components/ui/button';
import { formatNumber } from '@/lib/format';

import { axisProps, chartTooltipStyle } from './chart-card';

export interface BarDatum {
  readonly key: string;
  readonly label: string;
  readonly value: number;
  readonly color?: string;
}

/**
 * Single-measure bar chart with a table view (identity is never color-only: every bar has a
 * category label on its axis). Renders nothing it was not given.
 */
export function BarChartView({
  data,
  valueLabel,
  height = 240,
  horizontal = false,
  color = 'var(--chart-1)',
  onSelect,
}: {
  data: readonly BarDatum[];
  valueLabel: string;
  height?: number;
  horizontal?: boolean;
  color?: string;
  onSelect?: (datum: BarDatum) => void;
}): ReactElement {
  const [showTable, setShowTable] = useState(false);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex justify-end">
        <Button
          variant="ghost"
          size="sm"
          aria-pressed={showTable}
          onClick={() => {
            setShowTable((value) => !value);
          }}
        >
          {showTable ? <BarChart3 aria-hidden="true" /> : <Table2 aria-hidden="true" />}
          {showTable ? 'Show chart' : 'Show table'}
        </Button>
      </div>
      {showTable ? (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="py-1.5 font-medium">Category</th>
              <th className="py-1.5 text-right font-medium">{valueLabel}</th>
            </tr>
          </thead>
          <tbody>
            {data.map((datum) => (
              <tr key={datum.key} className="border-b border-border last:border-0">
                <td className="py-1.5">{datum.label}</td>
                <td className="py-1.5 text-right tabular-nums">{formatNumber(datum.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={{ height }} role="img" aria-label={`${valueLabel} by category`}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={[...data]}
              layout={horizontal ? 'vertical' : 'horizontal'}
              margin={{ top: 4, right: 12, bottom: 4, left: horizontal ? 8 : -8 }}
              barCategoryGap={2}
            >
              <CartesianGrid stroke="var(--chart-grid)" vertical={horizontal} horizontal={!horizontal} />
              {horizontal ? (
                <>
                  <XAxis type="number" allowDecimals={false} {...axisProps} />
                  <YAxis type="category" dataKey="label" width={130} {...axisProps} />
                </>
              ) : (
                <>
                  <XAxis dataKey="label" {...axisProps} interval={0} />
                  <YAxis allowDecimals={false} {...axisProps} />
                </>
              )}
              <Tooltip
                {...chartTooltipStyle}
                formatter={(value) => [formatNumber(Number(value)), valueLabel]}
              />
              <Bar
                dataKey="value"
                name={valueLabel}
                radius={horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]}
                maxBarSize={48}
                cursor={onSelect === undefined ? undefined : 'pointer'}
                onClick={(entry: unknown) => {
                  const payload = (entry as { payload?: BarDatum }).payload;
                  if (payload !== undefined) onSelect?.(payload);
                }}
                shape={(props: BarShapeProps) => (
                  <Rectangle {...props} fill={(props.payload as BarDatum | undefined)?.color ?? color} />
                )}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
