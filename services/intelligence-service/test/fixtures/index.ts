/**
 * Synthetic upstream responses in the formats of the real APIs. All identifiers are in the
 * `CVE-2026-9xxxx` range (and fake GHSA IDs), and every description says the data is synthetic:
 * none of this is real vulnerability data.
 */

export const V31_CRITICAL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
export const V31_MEDIUM = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
export const V40_BASE = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

export const syntheticCveId = (n: number) => `CVE-2026-${String(90_000 + n)}`;
export const syntheticGhsaId = (n: number) => {
  const alphabet = '23456789cfghjmpqrvwx';
  const digits = String(n)
    .padStart(4, '0')
    .split('')
    .map((d) => alphabet[Number(d)] ?? '2')
    .join('');
  return `GHSA-${digits}-2222-3333`;
};

export function nvdCve(n: number, overrides: Record<string, unknown> = {}) {
  const id = syntheticCveId(n);
  return {
    id,
    sourceIdentifier: 'cna@example.test',
    published: '2026-03-01T10:00:00.000',
    lastModified: '2026-03-02T11:00:00.000',
    vulnStatus: 'Analyzed',
    cveTags: [],
    descriptions: [
      { lang: 'en', value: `Synthetic NVD record ${n}. Not a real vulnerability.` },
      { lang: 'es', value: `Registro sintético ${n}.` },
    ],
    metrics: {
      cvssMetricV40: [
        {
          source: 'cna@example.test',
          type: 'Secondary',
          cvssData: {
            version: '4.0',
            vectorString: V40_BASE,
            baseScore: 9.3,
            baseSeverity: 'CRITICAL',
          },
        },
      ],
      cvssMetricV31: [
        {
          source: 'nvd@nist.gov',
          type: 'Primary',
          cvssData: {
            version: '3.1',
            vectorString: V31_CRITICAL,
            baseScore: 9.8,
            baseSeverity: 'CRITICAL',
          },
          exploitabilityScore: 3.9,
          impactScore: 5.9,
        },
      ],
      cvssMetricV2: [
        {
          source: 'nvd@nist.gov',
          type: 'Primary',
          cvssData: { version: '2.0', vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P', baseScore: 7.5 },
        },
      ],
    },
    weaknesses: [
      { source: 'nvd@nist.gov', type: 'Primary', description: [{ lang: 'en', value: 'CWE-79' }] },
      {
        source: 'cna@example.test',
        type: 'Secondary',
        description: [{ lang: 'en', value: 'NVD-CWE-noinfo' }],
      },
    ],
    configurations: [
      {
        nodes: [
          {
            operator: 'OR',
            negate: false,
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:example_vendor:example_product:*:*:*:*:*:*:*:*',
                versionStartIncluding: '1.0.0',
                versionEndExcluding: '1.4.2',
                matchCriteriaId: '00000000-0000-0000-0000-000000000001',
              },
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:example_vendor:example_product:2.0.0:*:*:*:*:*:*:*',
                matchCriteriaId: '00000000-0000-0000-0000-000000000002',
              },
              {
                vulnerable: false,
                criteria: 'cpe:2.3:o:example_os:example_os:-:*:*:*:*:*:*:*',
                matchCriteriaId: '00000000-0000-0000-0000-000000000003',
              },
            ],
          },
        ],
      },
    ],
    references: [
      {
        url: `https://example.test/advisories/${n}`,
        source: 'cna@example.test',
        tags: ['Vendor Advisory'],
      },
      {
        url: `https://example.test/patches/${n}`,
        source: 'cna@example.test',
        tags: ['Patch', 'Patch'],
      },
    ],
    ...overrides,
  };
}

export function nvdPage(cves: unknown[], startIndex: number, totalResults: number) {
  return {
    resultsPerPage: cves.length,
    startIndex,
    totalResults,
    format: 'NVD_CVE',
    version: '2.0',
    timestamp: '2026-11-04T12:00:00.000',
    vulnerabilities: cves.map((cve) => ({ cve })),
  };
}

export function cveRecordV5(
  n: number,
  overrides: {
    state?: string;
    cna?: Record<string, unknown>;
    adp?: unknown[];
    dateUpdated?: string;
  } = {},
) {
  const id = syntheticCveId(n);
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.2',
    cveMetadata: {
      cveId: id,
      assignerOrgId: '00000000-0000-4000-8000-000000000001',
      state: overrides.state ?? 'PUBLISHED',
      assignerShortName: 'ExampleCNA',
      dateReserved: '2026-02-01T00:00:00.000Z',
      datePublished: '2026-03-01T10:00:00.000Z',
      dateUpdated: overrides.dateUpdated ?? '2026-03-05T10:00:00.000Z',
    },
    containers: {
      cna: {
        providerMetadata: {
          orgId: '00000000-0000-4000-8000-000000000001',
          shortName: 'ExampleCNA',
        },
        title: `Synthetic CVE List record ${n}`,
        descriptions: [
          { lang: 'en', value: `Synthetic CVE List record ${n}. Not a real vulnerability.` },
        ],
        affected: [
          {
            vendor: 'Example Vendor',
            product: 'Example Product',
            defaultStatus: 'unaffected',
            versions: [
              { version: '1.0.0', lessThan: '1.4.2', status: 'affected', versionType: 'semver' },
              { version: '2.0.0', status: 'affected' },
              { version: 'before 3 (free text)', status: 'affected' },
            ],
          },
          {
            packageName: 'example-lib',
            collectionURL: 'https://registry.example.test',
            defaultStatus: 'affected',
          },
        ],
        problemTypes: [
          {
            descriptions: [
              { cweId: 'CWE-89', lang: 'en', description: 'SQL Injection', type: 'CWE' },
            ],
          },
        ],
        metrics: [
          {
            format: 'CVSS',
            cvssV3_1: {
              version: '3.1',
              vectorString: V31_MEDIUM,
              baseScore: 6.1,
              baseSeverity: 'MEDIUM',
            },
          },
          { other: { type: 'vendor severity', content: { value: 'High' } } },
        ],
        references: [
          {
            url: `https://example.test/advisories/${n}`,
            tags: ['vendor-advisory', 'x_refsource_EXAMPLE'],
          },
        ],
        ...overrides.cna,
      },
      adp: overrides.adp ?? [
        {
          providerMetadata: {
            orgId: '00000000-0000-4000-8000-000000000002',
            shortName: 'CISA-ADP',
          },
          title: 'CISA ADP Vulnrichment',
          metrics: [{ cvssV3_1: { version: '3.1', vectorString: V31_CRITICAL, baseScore: 9.8 } }],
          problemTypes: [
            {
              descriptions: [
                { type: 'CWE', lang: 'en', description: 'CWE-79 Improper Neutralization' },
              ],
            },
          ],
          references: [{ url: `https://example.test/advisories/${n}`, tags: ['exploit'] }],
        },
      ],
    },
  };
}

export function deltaLogEntry(fetchTime: string, changed: { new?: number[]; updated?: number[] }) {
  const change = (n: number) => ({
    cveId: syntheticCveId(n),
    cveOrgLink: `https://www.cve.org/CVERecord?id=${syntheticCveId(n)}`,
    githubLink: `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/90xxx/${syntheticCveId(n)}.json`,
    dateUpdated: fetchTime,
  });
  return {
    fetchTime,
    numberOfChanges: (changed.new?.length ?? 0) + (changed.updated?.length ?? 0),
    new: (changed.new ?? []).map(change),
    updated: (changed.updated ?? []).map(change),
    error: [],
  };
}

export function kevEntry(n: number, overrides: Record<string, unknown> = {}) {
  return {
    cveID: syntheticCveId(n),
    vendorProject: 'Example Vendor',
    product: 'Example Product',
    vulnerabilityName: `Example Product synthetic vulnerability ${n}`,
    dateAdded: '2026-04-01',
    shortDescription: `Synthetic KEV entry ${n}. Not a real vulnerability.`,
    requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product.',
    dueDate: '2026-04-22',
    knownRansomwareCampaignUse: 'Unknown',
    notes: `https://example.test/kev/${n}`,
    cwes: ['CWE-79'],
    ...overrides,
  };
}

export function kevCatalog(catalogVersion: string, entries: unknown[]) {
  return {
    title: 'CISA Catalog of Known Exploited Vulnerabilities (synthetic)',
    catalogVersion,
    dateReleased: '2026-11-04T12:00:00.0000Z',
    count: entries.length,
    vulnerabilities: entries,
  };
}

export function epssPage(
  date: string,
  rows: { n: number; epss: string; percentile: string }[],
  offset: number,
  total: number,
) {
  return {
    status: 'OK',
    'status-code': 200,
    version: '1.0',
    access: 'public',
    total,
    offset,
    limit: rows.length,
    data: rows.map((row) => ({
      cve: syntheticCveId(row.n),
      epss: row.epss,
      percentile: row.percentile,
      date,
    })),
  };
}

export function advisory(n: number, overrides: Record<string, unknown> = {}) {
  const ghsa = syntheticGhsaId(n);
  return {
    ghsa_id: ghsa,
    cve_id: syntheticCveId(n),
    url: `https://api.github.com/advisories/${ghsa}`,
    html_url: `https://github.com/advisories/${ghsa}`,
    summary: `Synthetic advisory ${n}`,
    description: `Synthetic GitHub advisory ${n}. Not a real vulnerability.`,
    type: 'reviewed',
    severity: 'high',
    identifiers: [
      { value: ghsa, type: 'GHSA' },
      { value: syntheticCveId(n), type: 'CVE' },
    ],
    references: [`https://example.test/advisories/${n}`],
    published_at: '2026-03-01T10:00:00Z',
    updated_at: '2026-03-03T10:00:00Z',
    withdrawn_at: null,
    vulnerabilities: [
      {
        package: { ecosystem: 'npm', name: 'example-package' },
        vulnerable_version_range: '>= 1.0.0, < 1.4.2',
        first_patched_version: '1.4.2',
        vulnerable_functions: [],
      },
      { package: { ecosystem: 'pip', name: 'example-py' }, vulnerable_version_range: '<= 0.9' },
    ],
    cvss_severities: {
      cvss_v3: { vector_string: V31_CRITICAL, score: 9.8 },
      cvss_v4: { vector_string: V40_BASE, score: 9.3 },
    },
    cwes: [{ cwe_id: 'CWE-79', name: 'Cross-site Scripting' }],
    ...overrides,
  };
}
