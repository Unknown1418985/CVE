import { platformRegistry } from '@cve/metrics';
import { describe, expect, it } from 'vitest';

import { recordDownloadAttempt, recordDownloadedBytes, recordScan } from './metrics.js';

describe('download metrics', () => {
  it('counts attempts with their error code so SSRF and policy blocks are visible', async () => {
    recordDownloadAttempt('github-archive', 'stored');
    recordDownloadAttempt('github-archive', 'rejected', 'url-not-allowed');
    recordDownloadedBytes('github-archive', 2048);
    const attempts = await platformRegistry.getSingleMetricAsString('download_attempts_total');
    expect(attempts).toContain(
      'download_attempts_total{source="github-archive",outcome="stored",code="none"} 1',
    );
    expect(attempts).toContain('outcome="rejected",code="url-not-allowed"} 1');
    expect(await platformRegistry.getSingleMetricAsString('download_bytes_total')).toContain(
      'download_bytes_total{source="github-archive"} 2048',
    );
  });

  it('counts scan results and individual scanner verdicts', async () => {
    recordScan('malicious', [
      { scanner: 'clamav', verdict: 'malicious' },
      { scanner: 'yara', verdict: 'clean' },
    ]);
    expect(await platformRegistry.getSingleMetricAsString('artifact_scans_total')).toContain(
      'artifact_scans_total{status="malicious"} 1',
    );
    expect(
      await platformRegistry.getSingleMetricAsString('artifact_scanner_verdicts_total'),
    ).toContain('artifact_scanner_verdicts_total{scanner="clamav",verdict="malicious"} 1');
  });
});
