import type {
  ArtifactLifecycleStatus,
  ArtifactScanStatus,
  ArtifactVerificationStatus,
  CveExploitMaturity,
  DownloadRequestStatus,
  ExploitMaturity,
  RecordSeverity,
} from '@cve/contracts';
import {
  Ban,
  CheckCircle2,
  CircleDashed,
  CircleHelp,
  Clock,
  Loader2,
  Lock,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  TriangleAlert,
  Unlock,
  type LucideIcon,
} from 'lucide-react';
import type { ReactElement } from 'react';

import { Badge, type BadgeProps } from '@/components/ui/badge';
import { formatScore, humanize } from '@/lib/format';
import { cn } from '@/lib/utils';

type Variant = NonNullable<BadgeProps['variant']>;

interface StatusStyle {
  readonly variant: Variant;
  readonly icon?: LucideIcon;
  readonly label?: string;
}

function StatusBadge({
  value,
  styles,
  prefix,
  className,
  testId,
}: {
  value: string;
  styles: Readonly<Record<string, StatusStyle>>;
  prefix?: string;
  className?: string | undefined;
  testId?: string;
}): ReactElement {
  const style = styles[value] ?? { variant: 'outline' as const };
  const Icon = style.icon;
  const label = style.label ?? humanize(value);
  return (
    <Badge variant={style.variant} className={cn('gap-1', className)} data-testid={testId} data-status={value}>
      {Icon === undefined ? null : <Icon className="size-3" aria-hidden="true" />}
      {prefix === undefined ? label : `${prefix}: ${label}`}
    </Badge>
  );
}

const SEVERITY_CLASS: Readonly<Record<RecordSeverity, string>> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  none: 'bg-severity-none',
  unknown: 'bg-severity-unknown',
};

/** Severity with a colored marker and the text label (color is never the only cue). */
export function SeverityBadge({
  severity,
  score,
}: {
  severity: RecordSeverity;
  score?: number | null;
}): ReactElement {
  return (
    <span
      data-testid="severity-badge"
      data-severity={severity}
      className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-0.5 text-xs font-medium whitespace-nowrap"
    >
      <span className={cn('size-2 rounded-full', SEVERITY_CLASS[severity])} aria-hidden="true" />
      {humanize(severity)}
      {score === undefined || score === null ? null : (
        <span className="text-muted-foreground tabular-nums">{formatScore(score)}</span>
      )}
    </span>
  );
}

export const SEVERITY_COLORS: Readonly<Record<RecordSeverity, string>> = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  medium: 'var(--severity-medium)',
  low: 'var(--severity-low)',
  none: 'var(--severity-none)',
  unknown: 'var(--severity-unknown)',
};

const SCAN: Readonly<Record<ArtifactScanStatus, StatusStyle>> = {
  pending: { variant: 'muted', icon: Clock, label: 'Scan pending' },
  scanning: { variant: 'info', icon: Loader2, label: 'Scanning' },
  clean: { variant: 'success', icon: ShieldCheck, label: 'Clean' },
  suspicious: { variant: 'warning', icon: ShieldAlert, label: 'Suspicious' },
  malicious: { variant: 'destructive', icon: ShieldX, label: 'Malicious' },
  incomplete: { variant: 'warning', icon: CircleDashed, label: 'Scan incomplete' },
  'integrity-failure': { variant: 'destructive', icon: TriangleAlert, label: 'Integrity failure' },
};

export function ScanStatusBadge({ status }: { status: ArtifactScanStatus }): ReactElement {
  return <StatusBadge value={status} styles={SCAN} testId="scan-status" />;
}

const LIFECYCLE: Readonly<Record<ArtifactLifecycleStatus, StatusStyle>> = {
  quarantined: { variant: 'warning', icon: Lock, label: 'Quarantined' },
  released: { variant: 'success', icon: Unlock, label: 'Released' },
  rejected: { variant: 'destructive', icon: Ban, label: 'Rejected' },
};

export function LifecycleBadge({ status }: { status: ArtifactLifecycleStatus }): ReactElement {
  return <StatusBadge value={status} styles={LIFECYCLE} testId="lifecycle-status" />;
}

const VERIFICATION: Readonly<Record<ArtifactVerificationStatus, StatusStyle>> = {
  unverified: { variant: 'muted', icon: CircleHelp, label: 'Unverified' },
  'in-review': { variant: 'info', icon: Clock, label: 'In review' },
  verified: { variant: 'success', icon: CheckCircle2, label: 'Verified' },
  rejected: { variant: 'outline', icon: Ban, label: 'Rejected' },
  malicious: { variant: 'destructive', icon: ShieldX, label: 'Malicious' },
};

export function VerificationBadge({ status }: { status: ArtifactVerificationStatus }): ReactElement {
  return <StatusBadge value={status} styles={VERIFICATION} testId="verification-status" />;
}

/**
 * The three independent security facts of a stored artifact. Release is not verification and a
 * clean scan is not a verdict, so they are always shown side by side.
 */
export function ArtifactSecurityStatus({
  lifecycle,
  scan,
  verification,
}: {
  lifecycle: ArtifactLifecycleStatus;
  scan: ArtifactScanStatus;
  verification: ArtifactVerificationStatus;
}): ReactElement {
  return (
    <div className="flex flex-wrap items-center gap-1" data-testid="artifact-security-status">
      <LifecycleBadge status={lifecycle} />
      <ScanStatusBadge status={scan} />
      <VerificationBadge status={verification} />
    </div>
  );
}

const DOWNLOAD: Readonly<Record<DownloadRequestStatus, StatusStyle>> = {
  pending: { variant: 'muted', icon: Clock },
  downloading: { variant: 'info', icon: Loader2 },
  stored: { variant: 'success', icon: CheckCircle2, label: 'Stored (quarantine)' },
  duplicate: { variant: 'info', icon: CheckCircle2 },
  failed: { variant: 'destructive', icon: TriangleAlert },
  rejected: { variant: 'destructive', icon: Ban, label: 'Rejected by policy' },
  cancelled: { variant: 'muted', icon: Ban },
};

export function DownloadStatusBadge({ status }: { status: DownloadRequestStatus }): ReactElement {
  return <StatusBadge value={status} styles={DOWNLOAD} testId="download-status" />;
}

const RUN: Readonly<Record<string, StatusStyle>> = {
  running: { variant: 'info', icon: Loader2 },
  succeeded: { variant: 'success', icon: CheckCircle2 },
  failed: { variant: 'destructive', icon: TriangleAlert },
  abandoned: { variant: 'warning', icon: CircleDashed },
};

export function RunStatusBadge({ status }: { status: string | null }): ReactElement {
  if (status === null) return <Badge variant="outline">Never run</Badge>;
  return <StatusBadge value={status} styles={RUN} testId="run-status" />;
}

const MATURITY: Readonly<Record<CveExploitMaturity, StatusStyle>> = {
  none: { variant: 'muted', label: 'No known exploit' },
  unproven: { variant: 'outline', icon: CircleHelp },
  'proof-of-concept': { variant: 'info', label: 'Proof of concept' },
  functional: { variant: 'warning', icon: TriangleAlert },
  weaponized: { variant: 'destructive', icon: ShieldAlert },
  'exploited-in-the-wild': { variant: 'destructive', icon: ShieldX, label: 'Exploited in the wild' },
};

export function MaturityBadge({ maturity }: { maturity: CveExploitMaturity | ExploitMaturity }): ReactElement {
  return <StatusBadge value={maturity} styles={MATURITY} testId="maturity" />;
}

const REVIEW: Readonly<Record<string, StatusStyle>> = {
  candidate: { variant: 'info', icon: CircleHelp },
  confirmed: { variant: 'success', icon: CheckCircle2 },
  rejected: { variant: 'outline', icon: Ban },
};

export function ReviewStatusBadge({ status }: { status: string }): ReactElement {
  return <StatusBadge value={status} styles={REVIEW} testId="review-status" />;
}

const CONFIDENCE: Readonly<Record<string, StatusStyle>> = {
  high: { variant: 'success' },
  medium: { variant: 'warning' },
  low: { variant: 'muted' },
};

export function ConfidenceBadge({
  level,
  value,
}: {
  level: string | null;
  value?: number | null;
}): ReactElement {
  if (level === null) return <Badge variant="outline">—</Badge>;
  const percent = value === undefined || value === null ? '' : ` ${Math.round(value * 100)}%`;
  return (
    <Badge variant={CONFIDENCE[level]?.variant ?? 'outline'} data-testid="confidence">
      {humanize(level)}
      {percent}
    </Badge>
  );
}

export function KevBadge({ inKev }: { inKev: boolean }): ReactElement | null {
  if (!inKev) return null;
  return (
    <Badge variant="destructive" className="gap-1" data-testid="kev-badge">
      <ShieldAlert className="size-3" aria-hidden="true" />
      KEV
    </Badge>
  );
}

export function EnabledBadge({ enabled, onLabel = 'Enabled', offLabel = 'Disabled' }: { enabled: boolean; onLabel?: string; offLabel?: string }): ReactElement {
  return <Badge variant={enabled ? 'success' : 'muted'}>{enabled ? onLabel : offLabel}</Badge>;
}
