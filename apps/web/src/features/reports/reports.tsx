'use client';

import {
  auditEventSchema,
  cveExploitAssessmentSchema,
  cveSummarySchema,
  downloadArtifactSchema,
  type AuditEvent,
  type CveExploitAssessment,
  type CveSummary,
  type DownloadArtifact,
  type Permission,
} from '@cve/contracts';
import { FileJson, FileSpreadsheet, Info, Loader2 } from 'lucide-react';
import { useState, type ReactElement } from 'react';
import type { z } from 'zod';

import { PageHeader } from '@/components/data/page-header';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { usePermissions } from '@/features/auth/use-me';
import { apiRequest, describeError, pageSchema, type QueryParams } from '@/lib/api/client';
import { formatNumber } from '@/lib/format';

import { exportFileName, toCsv, toJson, type ExportColumn } from './export';

/** Upper bound for one browser export (the API serves at most 100 rows per page). */
export const MAX_EXPORT_ROWS = 5_000;
const PAGE_SIZE = 100;

interface ReportDefinition<T> {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly permission: Permission;
  readonly path: string;
  readonly rowSchema: z.ZodType<T>;
  readonly query: (since: string | undefined) => QueryParams;
  /** Label of the optional "since" date filter; omitted when the report has none. */
  readonly sinceLabel?: string;
  readonly columns: readonly ExportColumn<T>[];
}

function defineReport<T>(definition: ReportDefinition<T>): ReportDefinition<T> {
  return definition;
}

function sinceTimestamp(value: string): string | undefined {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : undefined;
}

const CVE_COLUMNS: readonly ExportColumn<CveSummary>[] = [
  { header: 'CVE ID', value: (row) => row.cveId },
  { header: 'State', value: (row) => row.state },
  { header: 'Severity', value: (row) => row.severity },
  { header: 'CVSS score', value: (row) => row.cvssScore },
  { header: 'CVSS version', value: (row) => row.cvssVersion },
  { header: 'In CISA KEV', value: (row) => row.inKev },
  { header: 'EPSS score', value: (row) => row.epssScore },
  { header: 'EPSS percentile', value: (row) => row.epssPercentile },
  { header: 'CWE IDs', value: (row) => row.cweIds },
  { header: 'Published', value: (row) => row.publishedAt },
  { header: 'Last modified', value: (row) => row.lastModifiedAt },
  { header: 'Title', value: (row) => row.title },
  { header: 'Description', value: (row) => row.description },
];

export const REPORTS = [
  defineReport<CveSummary>({
    id: 'critical-high-cves',
    title: 'Critical and high severity CVEs',
    description: 'Every CVE rated critical or high, with CVSS, EPSS, KEV status and CWE classification.',
    permission: 'cve:read',
    path: 'cves',
    rowSchema: cveSummarySchema,
    sinceLabel: 'Published since',
    query: (since) => ({ severity: ['critical', 'high'], publishedFrom: since, sort: 'cvssScore', order: 'desc' }),
    columns: CVE_COLUMNS,
  }),
  defineReport<CveSummary>({
    id: 'known-exploited-cves',
    title: 'Known exploited vulnerabilities',
    description: 'CVEs listed in the CISA Known Exploited Vulnerabilities catalog, ordered by EPSS score.',
    permission: 'cve:read',
    path: 'cves',
    rowSchema: cveSummarySchema,
    sinceLabel: 'Published since',
    query: (since) => ({ kev: true, publishedFrom: since, sort: 'epssScore', order: 'desc' }),
    columns: CVE_COLUMNS,
  }),
  defineReport<CveExploitAssessment>({
    id: 'exploitation-status',
    title: 'Exploitation status',
    description: 'CVEs with a functional exploit, weaponized exploit or exploitation in the wild, with the evidence behind each classification.',
    permission: 'exploit:read',
    path: 'exploit-assessments',
    rowSchema: cveExploitAssessmentSchema,
    query: () => ({ maturity: ['functional', 'weaponized', 'exploited-in-the-wild'], sort: 'confidence', order: 'desc' }),
    columns: [
      { header: 'CVE ID', value: (row) => row.cveId },
      { header: 'Maturity', value: (row) => row.maturity },
      { header: 'Confidence', value: (row) => row.confidence },
      { header: 'Public PoC', value: (row) => row.indicators.publicPoc.present },
      { header: 'Functional exploit', value: (row) => row.indicators.functionalExploit.present },
      { header: 'Exploited in the wild', value: (row) => row.indicators.exploitedInTheWild.present },
      { header: 'In CISA KEV', value: (row) => row.inKev },
      { header: 'Known ransomware use', value: (row) => row.knownRansomwareCampaignUse },
      { header: 'Exploits', value: (row) => row.availability.exploitCount },
      { header: 'Metasploit modules', value: (row) => row.availability.metasploitModuleCount },
      { header: 'PoC repositories', value: (row) => row.availability.pocRepositoryCount },
      { header: 'Sources', value: (row) => row.availability.sources },
      { header: 'First exploit published', value: (row) => row.firstExploitPublishedAt },
      { header: 'CVSS v4 E', value: (row) => row.cvssV4ExploitMaturity },
      { header: 'Evaluated', value: (row) => row.evaluatedAt },
    ],
  }),
  defineReport<DownloadArtifact>({
    id: 'artifact-security-status',
    title: 'Stored artifact security status',
    description: 'Downloaded PoC artifacts with lifecycle, scan and verification status, hashes and provenance. Quarantined artifacts are included only for roles that may inspect them.',
    permission: 'download:read',
    path: 'download-artifacts',
    rowSchema: downloadArtifactSchema,
    query: () => ({ sort: 'downloadedAt', order: 'desc' }),
    columns: [
      { header: 'Artifact ID', value: (row) => row.id },
      { header: 'SHA-256', value: (row) => row.sha256 },
      { header: 'Lifecycle', value: (row) => row.lifecycleStatus },
      { header: 'Scan', value: (row) => row.scanStatus },
      { header: 'Verification', value: (row) => row.verificationStatus },
      { header: 'Detected type', value: (row) => row.detectedType },
      { header: 'Risk indicators', value: (row) => row.riskIndicators },
      { header: 'Size (bytes)', value: (row) => row.sizeBytes },
      { header: 'Source', value: (row) => row.source },
      { header: 'Source URL', value: (row) => row.sourceUrl },
      { header: 'Source repository', value: (row) => row.sourceRepository },
      { header: 'CVE IDs', value: (row) => row.cveIds },
      { header: 'Downloaded', value: (row) => row.downloadedAt },
      { header: 'Last scanned', value: (row) => row.lastScannedAt },
      { header: 'Released', value: (row) => row.releasedAt },
    ],
  }),
  defineReport<AuditEvent>({
    id: 'audit-log',
    title: 'Audit log',
    description: 'Audit entries, newest first, for compliance reviews.',
    permission: 'audit:read',
    path: 'audit-logs',
    rowSchema: auditEventSchema,
    sinceLabel: 'Occurred since',
    query: (since) => ({ from: since }),
    columns: [
      { header: 'Occurred', value: (row) => row.occurredAt },
      { header: 'Action', value: (row) => row.action },
      { header: 'Outcome', value: (row) => row.outcome },
      { header: 'Actor type', value: (row) => row.actorType },
      { header: 'Actor', value: (row) => row.actorUsername ?? row.actorId },
      { header: 'Resource type', value: (row) => row.resourceType },
      { header: 'Resource ID', value: (row) => row.resourceId },
      { header: 'Service', value: (row) => row.source },
      { header: 'IP address', value: (row) => row.ipAddress },
      { header: 'Correlation ID', value: (row) => row.correlationId },
    ],
  }),
] as const;

/** Fetches every page of a report (up to MAX_EXPORT_ROWS) and validates each against the contract. */
export async function collectRows<T>(
  report: ReportDefinition<T>,
  since: string | undefined,
  onProgress: (loaded: number, total: number) => void,
  signal?: AbortSignal,
): Promise<{ rows: T[]; total: number }> {
  const schema = pageSchema(report.rowSchema);
  const rows: T[] = [];
  let total = 0;
  for (let page = 1; rows.length < MAX_EXPORT_ROWS; page += 1) {
    const result = await apiRequest(report.path, { schema, query: { ...report.query(since), page, pageSize: PAGE_SIZE }, signal });
    total = result.meta.totalItems;
    rows.push(...result.data);
    onProgress(rows.length, total);
    if (page >= result.meta.totalPages || result.data.length === 0) break;
  }
  return { rows: rows.slice(0, MAX_EXPORT_ROWS), total };
}

function saveFile(content: string, fileName: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => { URL.revokeObjectURL(url); }, 1_000);
}

type Status =
  | { kind: 'idle' }
  | { kind: 'running'; loaded: number; total: number }
  | { kind: 'done'; rows: number; total: number }
  | { kind: 'error'; message: string };

function ReportCard<T>({ report }: { report: ReportDefinition<T> }): ReactElement {
  const [since, setSince] = useState('');
  const [status, setStatus] = useState<Status>({ kind: 'idle' });
  const run = async (format: 'csv' | 'json'): Promise<void> => {
    setStatus({ kind: 'running', loaded: 0, total: 0 });
    try {
      const sinceValue = sinceTimestamp(since);
      const { rows, total } = await collectRows(report, sinceValue, (loaded, all) => { setStatus({ kind: 'running', loaded, total: all }); });
      const fileName = exportFileName(report.title, format);
      if (format === 'csv') saveFile(toCsv(rows, report.columns), fileName, 'text/csv;charset=utf-8');
      else {
        saveFile(
          toJson(rows, report.columns, { report: report.title, generatedAt: new Date().toISOString(), filters: report.query(sinceValue), totalAvailable: total }),
          fileName,
          'application/json',
        );
      }
      setStatus({ kind: 'done', rows: rows.length, total });
    } catch (caught) {
      setStatus({ kind: 'error', message: describeError(caught) });
    }
  };
  const running = status.kind === 'running';
  return (
    <li className="flex flex-col gap-3 rounded-xl border border-border bg-card p-5" data-testid={`report-${report.id}`}>
      <div>
        <h2 className="font-semibold">{report.title}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{report.description}</p>
      </div>
      <div className="flex flex-wrap items-end gap-3">
        {report.sinceLabel === undefined ? null : (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor={`${report.id}-since`}>{report.sinceLabel} (optional)</Label>
            <Input id={`${report.id}-since`} type="date" className="w-44" value={since} onChange={(event) => { setSince(event.target.value); }} />
          </div>
        )}
        <Button variant="outline" disabled={running} onClick={() => { void run('csv'); }}>
          <FileSpreadsheet aria-hidden="true" /> Export CSV
        </Button>
        <Button variant="outline" disabled={running} onClick={() => { void run('json'); }}>
          <FileJson aria-hidden="true" /> Export JSON
        </Button>
      </div>
      <div aria-live="polite" className="text-xs">
        {status.kind === 'running' ? (
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <Loader2 className="size-3 animate-spin" aria-hidden="true" /> Loading {formatNumber(status.loaded)}
            {status.total > 0 ? ` of ${formatNumber(Math.min(status.total, MAX_EXPORT_ROWS))}` : ''} rows…
          </span>
        ) : status.kind === 'done' ? (
          <span className="text-muted-foreground">
            Exported {formatNumber(status.rows)} rows.
            {status.total > status.rows ? ` ${formatNumber(status.total)} match; browser exports are limited to ${formatNumber(MAX_EXPORT_ROWS)} rows, narrow the date filter for the rest.` : ''}
          </span>
        ) : status.kind === 'error' ? (
          <span role="alert" className="text-status-down">{status.message}</span>
        ) : null}
      </div>
    </li>
  );
}

export function ReportsView(): ReactElement {
  const permissions = usePermissions();
  const available = permissions === undefined ? [] : REPORTS.filter((report) => permissions.has(report.permission));
  return (
    <>
      <PageHeader title="Reports" description="Export live platform data for briefings, compliance reviews and offline analysis." />
      <div className="flex gap-3 rounded-xl border border-border bg-card p-4 text-sm" role="note">
        <Info className="mt-0.5 size-4 shrink-0 text-status-info" aria-hidden="true" />
        <p className="text-muted-foreground">
          These exports are generated in your browser from the same APIs the rest of the interface uses, so they reflect exactly what
          your role can see right now. Stored, scheduled and shared reports come with the Reporting Service, which does not expose an
          API yet; nothing is listed here until it does.
        </p>
      </div>
      {permissions === undefined ? null : available.length === 0 ? (
        <p className="text-sm text-muted-foreground">Your role has no access to data that can be exported.</p>
      ) : (
        <ul className="grid gap-4 lg:grid-cols-2">
          {available.map((report) => <ReportCard key={report.id} report={report as ReportDefinition<unknown>} />)}
        </ul>
      )}
    </>
  );
}
