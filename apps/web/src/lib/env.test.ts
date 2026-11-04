import { describe, expect, it } from 'vitest';

import { parseServerEnv } from './env';

describe('parseServerEnv', () => {
  it('applies defaults', () => {
    expect(parseServerEnv({}).API_GATEWAY_INTERNAL_URL).toBe('http://localhost:4000');
  });

  it('strips trailing slashes', () => {
    expect(
      parseServerEnv({ API_GATEWAY_INTERNAL_URL: 'http://api-gateway:4000/' })
        .API_GATEWAY_INTERNAL_URL,
    ).toBe('http://api-gateway:4000');
  });

  it('rejects non-http URLs', () => {
    expect(() => parseServerEnv({ API_GATEWAY_INTERNAL_URL: 'file:///etc/passwd' })).toThrow(
      /API_GATEWAY_INTERNAL_URL/,
    );
  });
});
