import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import type { ScanFinding } from '@cve/contracts';

import type { FileScanner, ScannerResult } from './clamav.js';

export interface YaraOptions {
  /** The `yara` command-line scanner (YARA 4.x). */
  readonly binary: string;
  /** Rules file (it may `include` others). */
  readonly rulesPath: string;
  readonly timeoutMs: number;
}

const MAX_OUTPUT_BYTES = 1024 * 1024;

function run(
  binary: string,
  args: readonly string[],
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      [...args],
      {
        timeout: timeoutMs,
        maxBuffer: MAX_OUTPUT_BYTES,
        // No shell, no inherited environment: only the arguments above reach the scanner.
        shell: false,
        env: {},
        windowsHide: true,
        ...(signal === undefined ? {} : { signal }),
      },
      (error, stdout, stderr) => {
        if (error !== null && typeof error.code !== 'number') {
          reject(error);
          return;
        }
        resolve({ stdout, stderr, code: error === null ? 0 : Number(error.code) });
      },
    );
  });
}

/**
 * Parses `yara -g -e` output: `namespace:Rule [tag1,tag2] <path>`, one line per matching rule.
 */
export function parseYaraOutput(stdout: string, path: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trimEnd();
    if (!trimmed.endsWith(` ${path}`)) continue;
    const head = trimmed.slice(0, trimmed.length - path.length - 1);
    const match = /^(\S+?)(?:\s+\[([^\]]*)\])?$/.exec(head);
    if (match?.[1] === undefined) continue;
    const tags = match[2] === undefined || match[2] === '' ? null : match[2];
    findings.push({ name: match[1].slice(0, 255), detail: tags === null ? null : `tags: ${tags}` });
  }
  return findings;
}

/**
 * YARA through its command-line scanner. YARA only reads the file as bytes. Any rule match makes
 * the artifact `suspicious` (rules are heuristics, not proof of malware).
 */
export class YaraCliScanner implements FileScanner {
  readonly name = 'yara' as const;

  constructor(private readonly options: YaraOptions) {}

  private async versions(): Promise<{ engine: string | null; rules: string | null }> {
    const [engine, rules] = await Promise.all([
      run(this.options.binary, ['--version'], 5_000).then(
        (result) => (result.code === 0 ? `YARA ${result.stdout.trim()}` : null),
        () => null,
      ),
      readFile(this.options.rulesPath).then(
        (content) => `rules sha256:${createHash('sha256').update(content).digest('hex').slice(0, 16)}`,
        () => null,
      ),
    ]);
    return { engine, rules };
  }

  async ping(): Promise<void> {
    const result = await run(this.options.binary, ['--version'], 5_000);
    if (result.code !== 0) throw new Error(`yara --version exited with ${String(result.code)}`);
    await readFile(this.options.rulesPath);
  }

  async scan(path: string, signal: AbortSignal): Promise<ScannerResult> {
    const versions = await this.versions();
    const base = { engineVersion: versions.engine, signatureVersion: versions.rules };
    try {
      const seconds = Math.max(1, Math.floor(this.options.timeoutMs / 1000));
      const result = await run(
        this.options.binary,
        // -w no warnings, -N no symlinks, -g tags, -e namespace, -a scan timeout, -p one thread.
        ['-w', '-N', '-g', '-e', '-a', String(seconds), '-p', '1', this.options.rulesPath, path],
        this.options.timeoutMs + 5_000,
        signal,
      );
      if (result.code !== 0) {
        return {
          ...base,
          verdict: 'error',
          findings: [],
          error: `yara exited with ${String(result.code)}: ${result.stderr.trim().slice(0, 500)}`,
        };
      }
      const findings = parseYaraOutput(result.stdout, path);
      return { ...base, verdict: findings.length > 0 ? 'suspicious' : 'clean', findings, error: null };
    } catch (error) {
      return {
        ...base,
        verdict: 'error',
        findings: [],
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}
