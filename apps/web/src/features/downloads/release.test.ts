import { describe, expect, it } from 'vitest';

import { releaseBlocker } from './release';

const base = {
  lifecycleStatus: 'quarantined',
  scanStatus: 'clean',
  verificationStatus: 'unverified',
  releasable: true,
} as const;

describe('releaseBlocker', () => {
  it('allows release of a clean, releasable quarantined artifact', () => {
    expect(releaseBlocker(base)).toBeNull();
  });

  it('blocks release until the scan is clean', () => {
    for (const scanStatus of [
      'pending',
      'scanning',
      'suspicious',
      'malicious',
      'incomplete',
      'integrity-failure',
    ] as const) {
      expect(releaseBlocker({ ...base, scanStatus })).toMatch(/clean scan/);
    }
  });

  it('blocks release when a linked PoC artifact is malicious or rejected', () => {
    expect(releaseBlocker({ ...base, verificationStatus: 'malicious' })).toMatch(/malicious/);
    expect(releaseBlocker({ ...base, verificationStatus: 'rejected' })).toMatch(/rejected/);
  });

  it('honours the service verdict and ignores states where release is not a transition', () => {
    expect(releaseBlocker({ ...base, releasable: false })).toMatch(/not releasable/);
    expect(releaseBlocker({ ...base, lifecycleStatus: 'released' })).toBeNull();
  });
});
