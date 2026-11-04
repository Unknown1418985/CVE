import { describe, expect, it } from 'vitest';

import {
  EVENTS_EXCHANGE,
  assertBindingKey,
  consumerTopology,
  serviceInternalExchange,
  servicePermissions,
} from './topology.js';

describe('consumerTopology', () => {
  it('derives queue names from service and consumer', () => {
    expect(consumerTopology('cve-service', 'kev-updater', 2)).toEqual({
      internalExchange: 'cve-service.internal',
      queue: 'cve-service.kev-updater',
      deadLetterQueue: 'cve-service.kev-updater.dlq',
      retryQueues: ['cve-service.kev-updater.retry.1', 'cve-service.kev-updater.retry.2'],
    });
  });

  it('rejects unsafe names', () => {
    expect(() => consumerTopology('cve-service', 'Bad Name', 1)).toThrow(/consumer name/);
    expect(() => consumerTopology('cve-service', 'a.b', 1)).toThrow(/consumer name/);
    expect(() => consumerTopology('nope' as 'cve-service', 'ok', 1)).toThrow(/Unknown service/);
    expect(() => consumerTopology('cve-service', 'ok', 11)).toThrow(/retryCount/);
  });
});

describe('assertBindingKey', () => {
  it('accepts event types and wildcards', () => {
    for (const key of [
      'cve.record.created',
      'cve.record.*',
      'poc.#',
      'poc-artifact.file.released',
    ]) {
      expect(() => {
        assertBindingKey(key);
      }).not.toThrow();
    }
  });

  it('rejects malformed keys', () => {
    for (const key of ['', 'CVE.record', 'cve..record', 'cve.record.', 'cve record']) {
      expect(() => {
        assertBindingKey(key);
      }).toThrow();
    }
  });
});

describe('servicePermissions', () => {
  const permissions = servicePermissions('poc-service');
  const matches = (pattern: string, resource: string) => new RegExp(pattern).test(resource);

  it('allows the service to configure only its own resources', () => {
    expect(matches(permissions.configure, 'poc-service.discovery')).toBe(true);
    expect(matches(permissions.configure, serviceInternalExchange('poc-service'))).toBe(true);
    expect(matches(permissions.configure, EVENTS_EXCHANGE)).toBe(false);
    expect(matches(permissions.configure, 'cve-service.discovery')).toBe(false);
    expect(matches(permissions.configure, 'poc-servicex.discovery')).toBe(false);
  });

  it('allows publishing to the events exchange but not to other services', () => {
    expect(matches(permissions.write, EVENTS_EXCHANGE)).toBe(true);
    expect(matches(permissions.write, 'poc-service.internal')).toBe(true);
    expect(matches(permissions.write, 'cve-service.internal')).toBe(false);
    expect(matches(permissions.write, 'amq.default')).toBe(false);
    expect(matches(permissions.write, 'cveXevents')).toBe(false);
  });

  it('allows reading only from the events exchange and its own queues', () => {
    expect(matches(permissions.read, 'poc-service.discovery.dlq')).toBe(true);
    expect(matches(permissions.read, 'download-service.fetch')).toBe(false);
  });
});
