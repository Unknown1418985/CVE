import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

/**
 * Policy checks for the production deployment configuration, the monitoring configuration and the
 * backup tooling. No containers are started.
 */
const root = resolve(import.meta.dirname, '../../../..');
const read = (file: string) => readFileSync(resolve(root, file), 'utf8');

interface ComposeService {
  image?: string;
  ports?: string[];
  volumes?: string[];
  environment?: Record<string, string>;
  restart?: string;
}

// `!override` is a Docker Compose tag; for these checks its value is the plain sequence.
const prod = parse(read('compose.prod.yaml'), {
  merge: true,
  customTags: [{ tag: '!override', collection: 'seq', resolve: (value: unknown) => value }],
}) as { services: Record<string, ComposeService> };
const base = parse(read('compose.yaml'), { merge: true, maxAliasCount: -1 }) as {
  services: Record<string, ComposeService & { build?: unknown; profiles?: string[] }>;
};

const BUILT_SERVICES = Object.entries(base.services)
  .filter(([, service]) => service.build !== undefined)
  .map(([name]) => name);

describe('compose.prod.yaml', () => {
  it('publishes only Nginx on 80/443 (Grafana stays on 127.0.0.1)', () => {
    const publishing = Object.entries(prod.services).filter(([, s]) => (s.ports ?? []).length > 0);
    expect(publishing.map(([name]) => name)).toEqual(['nginx']);
    expect(prod.services['nginx']?.ports).toEqual([
      '${PUBLIC_BIND_ADDRESS:-0.0.0.0}:80:8080',
      '${PUBLIC_BIND_ADDRESS:-0.0.0.0}:443:8443',
    ]);
    expect(read('compose.prod.yaml')).toContain('ports: !override');
  });

  it('terminates TLS with certificates mounted read-only', () => {
    const volumes = prod.services['nginx']?.volumes ?? [];
    expect(volumes).toContain('./infra/nginx/nginx.tls.conf:/etc/nginx/nginx.conf:ro');
    expect(
      volumes.some((v) => v.endsWith(':/etc/nginx/tls:ro') && v.includes('TLS_CERT_DIR:?')),
    ).toBe(true);
  });

  it('runs every locally built image from the registry with an explicit tag', () => {
    expect(BUILT_SERVICES.length).toBeGreaterThan(10);
    for (const name of BUILT_SERVICES) {
      expect(prod.services[name]?.image, name).toMatch(
        /^\$\{IMAGE_REGISTRY:\?[^}]+\}\/cve-platform-[a-z-]+:\$\{IMAGE_TAG:\?[^}]+\}$/,
      );
    }
  });

  it('requires HTTPS public URLs instead of localhost defaults', () => {
    const text = read('compose.prod.yaml');
    expect(text).not.toMatch(/localhost/);
    for (const [name, service] of Object.entries(base.services)) {
      if (service.environment?.['KEYCLOAK_PUBLIC_URL'] === undefined) continue;
      expect(prod.services[name]?.environment?.['KEYCLOAK_PUBLIC_URL'], name).toMatch(
        /^\$\{KEYCLOAK_PUBLIC_URL:\?/,
      );
    }
    expect(prod.services['keycloak']?.environment?.['KC_HOSTNAME']).toMatch(
      /^\$\{KEYCLOAK_PUBLIC_URL:\?/,
    );
    expect(prod.services['alertmanager']?.environment?.['ALERTMANAGER_WEBHOOK_URL']).toMatch(/:\?/);
  });

  it('disables OpenAPI documentation on every API', () => {
    for (const [name, service] of Object.entries(prod.services)) {
      if (!name.endsWith('-service') && name !== 'api-gateway') continue;
      if (name.endsWith('-migrate')) continue;
      expect(service.environment?.['SWAGGER_ENABLED'], name).toBe('false');
    }
  });
});

describe('Nginx', () => {
  const tls = read('infra/nginx/nginx.tls.conf');
  const shared = read('infra/nginx/snippets/platform.conf');

  it('offers only TLS 1.2+ and sends HSTS', () => {
    expect(tls).toMatch(/ssl_protocols TLSv1\.2 TLSv1\.3;/);
    expect(tls).toMatch(
      /add_header Strict-Transport-Security "max-age=\d{8,}; includeSubDomains" always;/,
    );
    expect(tls).toMatch(/ssl_session_tickets off;/);
    expect(tls).not.toMatch(/TLSv1(\.1)?[ ;]/);
  });

  it('redirects HTTP and rejects unknown host names', () => {
    expect(tls).toContain('return 301 https://$server_name$request_uri;');
    expect(tls).toContain('ssl_reject_handshake on;');
    expect(tls).toContain('return 444;');
  });

  it('shares one set of routes and keeps the Keycloak admin console unreachable', () => {
    for (const config of [tls, read('infra/nginx/nginx.conf')]) {
      expect(config).toContain('include /etc/nginx/platform/snippets/platform.conf;');
    }
    expect(shared).toMatch(/location \/auth\/ \{\s+return 404;/);
    expect(shared).not.toContain('/metrics');
  });
});

/** Platform metric names defined in source (packages and services). */
function definedPlatformMetrics(): Set<string> {
  const names = new Set<string>();
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      if (['node_modules', 'dist', 'generated', '.next', '.turbo'].includes(entry)) continue;
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) walk(path);
      else if (path.endsWith('.ts') && !path.endsWith('.test.ts')) {
        for (const match of readFileSync(path, 'utf8').matchAll(/name: '([a-z_]+)'/g)) {
          if (match[1] !== undefined) names.add(match[1]);
        }
      }
    }
  };
  for (const dir of ['packages', 'services', 'apps/api-gateway/src']) walk(resolve(root, dir));
  return names;
}

const PLATFORM_PREFIXES = [
  'messaging_',
  'outbox_',
  'jobs_',
  'job_',
  'auth_',
  'download_',
  'artifact_',
  'source_sync_',
  'service_',
  'http_server_',
];

function referencedPlatformMetrics(expr: string): string[] {
  return [...expr.matchAll(/\b([a-z][a-z0-9_]*)\b/g)]
    .map((m) => m[1] ?? '')
    .filter((token) => PLATFORM_PREFIXES.some((prefix) => token.startsWith(prefix)))
    .map((token) => token.replace(/_(bucket|count|sum)$/, ''));
}

interface RuleFile {
  groups: {
    name: string;
    rules: { alert?: string; expr: string; labels?: { severity?: string } }[];
  }[];
}

describe('monitoring configuration', () => {
  const defined = definedPlatformMetrics();
  const ruleFiles = readdirSync(resolve(root, 'infra/prometheus/rules')).filter((f) =>
    f.endsWith('.yml'),
  );
  const rules = ruleFiles.flatMap((file) =>
    (parse(read(`infra/prometheus/rules/${file}`)) as RuleFile).groups.flatMap((g) => g.rules),
  );

  it('defines the instruments the alert rules and dashboards rely on', () => {
    for (const name of [
      'service_ready',
      'service_dependency_up',
      'outbox_pending_events',
      'messaging_events_consumed_total',
      'jobs_processed_total',
      'job_queue_jobs',
      'auth_requests_rejected_total',
      'download_attempts_total',
      'artifact_scans_total',
      'source_sync_runs_total',
      'http_server_request_duration_seconds',
    ]) {
      expect(defined.has(name), name).toBe(true);
    }
  });

  it('only alerts on metrics that exist, with a severity and a summary', () => {
    const alerts = new Set<string>();
    for (const rule of rules) {
      if (rule.alert === undefined) continue;
      expect(alerts.has(rule.alert), `duplicate alert ${rule.alert}`).toBe(false);
      alerts.add(rule.alert);
      expect(['critical', 'warning', 'info'], rule.alert).toContain(rule.labels?.severity);
      for (const metric of referencedPlatformMetrics(rule.expr)) {
        expect(defined.has(metric), `${rule.alert} uses unknown metric ${metric}`).toBe(true);
      }
    }
    expect(alerts.size).toBeGreaterThanOrEqual(25);
  });

  it('provisions dashboards with unique UIDs that only query existing metrics', () => {
    const dir = resolve(root, 'infra/grafana/dashboards');
    const uids = new Set<string>();
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
      const dashboard = JSON.parse(readFileSync(join(dir, file), 'utf8')) as {
        uid: string;
        editable: boolean;
        panels: { title: string; datasource?: { uid: string }; targets?: { expr: string }[] }[];
      };
      expect(uids.has(dashboard.uid), file).toBe(false);
      uids.add(dashboard.uid);
      expect(dashboard.editable, file).toBe(false);
      for (const panel of dashboard.panels) {
        for (const target of panel.targets ?? []) {
          expect(panel.datasource?.uid, `${file}: ${panel.title}`).toBe('prometheus');
          for (const metric of referencedPlatformMetrics(target.expr)) {
            expect(defined.has(metric), `${file}: ${panel.title} uses unknown ${metric}`).toBe(
              true,
            );
          }
        }
      }
    }
    expect([...uids].sort()).toEqual([
      'cve-platform-infrastructure',
      'cve-platform-pipeline',
      'cve-platform-security',
      'cve-platform-services',
    ]);
  });

  it('routes alerts to Alertmanager without a URL in the repository', () => {
    const prometheus = parse(read('infra/prometheus/prometheus.yml')) as {
      alerting: { alertmanagers: { static_configs: { targets: string[] }[] }[] };
    };
    expect(prometheus.alerting.alertmanagers[0]?.static_configs[0]?.targets).toEqual([
      'alertmanager:9093',
    ]);
    const alertmanager = read('infra/alertmanager/alertmanager.yml');
    expect(alertmanager).toContain('url_file: /tmp/alertmanager/webhook-url');
    expect(alertmanager).not.toMatch(/https?:\/\//);
  });
});

describe('backup tooling', () => {
  const scripts = ['backup.sh', 'verify.sh', 'restore.sh'];

  it('has valid POSIX shell syntax and fails fast', () => {
    for (const script of [...scripts, 'lib.sh']) {
      const path = resolve(root, 'infra/backup', script);
      execFileSync('sh', ['-n', path]);
      if (script !== 'lib.sh') {
        expect(read(`infra/backup/${script}`), script).toMatch(/^set -eu$/m);
        expect(statSync(path).mode & 0o111, `${script} is executable`).not.toBe(0);
      }
    }
  });

  it('refuses unencrypted backups unless explicitly allowed', () => {
    const backup = read('infra/backup/backup.sh');
    expect(backup).toMatch(/Refusing to write unencrypted backups/);
    expect(backup).toContain('umask 077');
    // .env is only ever stored encrypted.
    expect(backup).toMatch(/if \[ "\$ENCRYPT" = "true" \] && \[ -f "\$env_file" \]/);
  });

  it('requires explicit confirmation and stopped applications before restoring', () => {
    const restore = read('infra/backup/restore.sh');
    expect(restore).toContain('re-run with --yes to confirm');
    expect(restore).toMatch(/is running; stop the application services/);
    expect(restore).toContain('sha256sum --quiet --check SHA256SUMS');
  });

  it('backs up every service database and bucket', () => {
    const lib = read('infra/backup/lib.sh');
    for (const database of [
      'identity_service',
      'cve_service',
      'intelligence_service',
      'asset_service',
      'poc_service',
      'download_service',
      'exploit_service',
      'reporting_service',
      'notification_service',
      'keycloak',
    ]) {
      expect(lib, database).toContain(database);
    }
    for (const bucket of ['cve-poc-quarantine', 'cve-poc-artifacts', 'cve-reports']) {
      expect(lib, bucket).toContain(bucket);
    }
  });
});
