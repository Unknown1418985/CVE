import type { PocConnector } from '@cve/contracts';

export interface ConnectorTerms {
  readonly name: string;
  readonly description: string;
  readonly termsUrl: string | null;
}

/**
 * Approved connectors, reviewed 2026-11. Adding a connector means adding it here, to
 * `POC_CONNECTORS` and to the configuration allowlist; nothing else can be enabled.
 */
export const CONNECTOR_TERMS: Readonly<Record<PocConnector, ConnectorTerms>> = {
  github: {
    name: 'GitHub repository search',
    description:
      'Searches public GitHub repositories for CVE IDs and reads repository metadata, head commits and file listings through the REST API. No repository content is downloaded or executed.',
    termsUrl:
      'https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#h-api-terms',
  },
  'cve-references': {
    name: 'CVE record references',
    description:
      'Public PoC references (GitHub repositories, Exploit-DB, Packet Storm, references tagged as exploits) listed by CVE records that the Intelligence Service observes.',
    termsUrl: null,
  },
};
