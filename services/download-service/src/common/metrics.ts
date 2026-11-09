import { boundedLabel, counter } from '@cve/metrics';

/**
 * Download pipeline instruments. Label values come from closed sets (source names, outcome and
 * error codes, scanner names, verdicts); `boundedLabel` collapses anything unexpected.
 */
const downloadAttempts = () =>
  counter({
    name: 'download_attempts_total',
    help: 'Download attempts by source, outcome and error code (SSRF and policy blocks included)',
    labelNames: ['source', 'outcome', 'code'] as const,
  });

const downloadBytes = () =>
  counter({
    name: 'download_bytes_total',
    help: 'Bytes received from external sources by successful downloads',
    labelNames: ['source'] as const,
  });

const artifactScans = () =>
  counter({
    name: 'artifact_scans_total',
    help: 'Completed artifact scans by aggregated scan status',
    labelNames: ['status'] as const,
  });

const scannerVerdicts = () =>
  counter({
    name: 'artifact_scanner_verdicts_total',
    help: 'Individual scanner verdicts (ClamAV, YARA)',
    labelNames: ['scanner', 'verdict'] as const,
  });

export function recordDownloadAttempt(source: string, outcome: string, code?: string): void {
  downloadAttempts().inc({
    source: boundedLabel(source),
    outcome: boundedLabel(outcome),
    code: code === undefined ? 'none' : boundedLabel(code),
  });
}

export function recordDownloadedBytes(source: string, bytes: number): void {
  if (bytes > 0) downloadBytes().inc({ source: boundedLabel(source) }, bytes);
}

export function recordScan(
  status: string,
  runs: readonly { readonly scanner: string; readonly verdict: string }[],
): void {
  artifactScans().inc({ status: boundedLabel(status) });
  for (const run of runs) {
    scannerVerdicts().inc({
      scanner: boundedLabel(run.scanner),
      verdict: boundedLabel(run.verdict),
    });
  }
}
