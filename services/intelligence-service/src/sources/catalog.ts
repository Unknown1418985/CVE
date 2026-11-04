import type { IntelligenceSource } from '@cve/contracts';

export interface SourceTerms {
  readonly name: string;
  readonly description: string;
  readonly license: string;
  readonly termsUrl: string;
  /** Attribution carried by every event derived from the source. */
  readonly attribution: string;
  /** Whether the terms permit keeping the original payloads. */
  readonly rawRetentionPermitted: boolean;
}

/**
 * Terms of use of every source, reviewed when the adapters were written (2026-11). Each adapter
 * also follows the source's documented quotas (see docs/intelligence-service.md).
 */
export const SOURCE_TERMS: Readonly<Record<IntelligenceSource, SourceTerms>> = {
  nvd: {
    name: 'NVD CVE API 2.0',
    description: 'NIST National Vulnerability Database: CVE records with NVD analysis.',
    license: 'NVD data is not subject to copyright in the United States (NIST terms of use)',
    termsUrl: 'https://nvd.nist.gov/developers/terms-of-use',
    attribution:
      'This product uses data from the NVD API but is not endorsed or certified by the NVD.',
    rawRetentionPermitted: true,
  },
  'mitre-cve': {
    name: 'MITRE CVE List (CVE JSON 5)',
    description: 'Official CVE Program records published by CNAs, with ADP enrichment.',
    license: 'CVE Program terms of use (free to use, copy and distribute with attribution)',
    termsUrl: 'https://www.cve.org/Legal/TermsOfUse',
    attribution: 'CVE® records © The MITRE Corporation, provided by the CVE Program.',
    rawRetentionPermitted: true,
  },
  'cisa-kev': {
    name: 'CISA Known Exploited Vulnerabilities',
    description: 'CISA catalog of vulnerabilities known to be exploited in the wild.',
    license: 'CC0 1.0 Universal',
    termsUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    attribution: 'Source: CISA Known Exploited Vulnerabilities Catalog.',
    rawRetentionPermitted: true,
  },
  'first-epss': {
    name: 'FIRST EPSS',
    description: 'Exploit Prediction Scoring System: daily probability of exploitation.',
    license: 'EPSS is free to use with attribution (FIRST EPSS usage guidelines)',
    termsUrl: 'https://www.first.org/epss/user-guide',
    attribution:
      'EPSS scores from FIRST.org (Jacobs, Romanosky, et al., Exploit Prediction Scoring System).',
    rawRetentionPermitted: true,
  },
  'github-advisory': {
    name: 'GitHub Advisory Database',
    description: 'Reviewed security advisories for open source packages (GitHub REST API).',
    license: 'CC BY 4.0',
    termsUrl: 'https://github.com/github/advisory-database/blob/main/LICENSE.md',
    attribution: 'Contains data from the GitHub Advisory Database, licensed under CC BY 4.0.',
    rawRetentionPermitted: true,
  },
};
