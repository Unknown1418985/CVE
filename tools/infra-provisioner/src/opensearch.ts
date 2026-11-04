import type { Logger } from '@cve/logger';

import type { HttpClient } from './http-client.js';

export interface OpenSearchRole {
  readonly name: string;
  readonly cluster_permissions: readonly string[];
  readonly index_permissions: readonly {
    readonly index_patterns: readonly string[];
    readonly allowed_actions: readonly string[];
  }[];
}

export interface OpenSearchUser {
  readonly username: string;
  readonly password: string;
  readonly description: string;
  readonly roles: readonly string[];
}

export interface OpenSearchPlan {
  readonly roles: readonly OpenSearchRole[];
  readonly users: readonly OpenSearchUser[];
}

/** Index prefix owned by the CVE Service; no other service is granted access to it. */
export const CVE_INDEX_PATTERN = 'cve-*';

export function buildOpenSearchPlan(cveServicePassword: string): OpenSearchPlan {
  return {
    roles: [
      {
        name: 'cve_service_search',
        cluster_permissions: [
          'cluster_monitor',
          'cluster_composite_ops',
          'indices:admin/template/get',
        ],
        index_permissions: [
          {
            index_patterns: [CVE_INDEX_PATTERN],
            allowed_actions: ['crud', 'create_index', 'manage', 'indices_monitor'],
          },
        ],
      },
    ],
    users: [
      {
        username: 'cve-service',
        password: cveServicePassword,
        description: 'CVE Service search indexer and query user',
        roles: ['cve_service_search'],
      },
    ],
  };
}

const SECURITY_API = '/_plugins/_security/api';
const enc = encodeURIComponent;

export async function applyOpenSearchPlan(
  client: HttpClient,
  plan: OpenSearchPlan,
  logger: Logger,
): Promise<void> {
  for (const role of plan.roles) {
    await client.expect('PUT', `${SECURITY_API}/roles/${enc(role.name)}`, {
      cluster_permissions: role.cluster_permissions,
      index_permissions: role.index_permissions,
    });
  }
  for (const user of plan.users) {
    await client.expect('PUT', `${SECURITY_API}/internalusers/${enc(user.username)}`, {
      password: user.password,
      backend_roles: [],
      description: user.description,
    });
  }
  for (const role of plan.roles) {
    const users = plan.users
      .filter((user) => user.roles.includes(role.name))
      .map((user) => user.username);
    await client.expect('PUT', `${SECURITY_API}/rolesmapping/${enc(role.name)}`, { users });
    logger.info({ role: role.name, users }, 'opensearch role provisioned');
  }
}
