import 'server-only';

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Derives a purpose-bound 256-bit key from the configured secret (HKDF-SHA-256). */
export function deriveKey(secret: string, purpose: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, 'cve-web', purpose, 32));
}

/**
 * Encrypts and authenticates a JSON value (AES-256-GCM). The purpose is bound as additional
 * authenticated data, so a sealed value cannot be replayed as another cookie.
 */
export function seal(value: unknown, key: Buffer, purpose: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(purpose));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString('base64url');
}

/** Returns the decrypted JSON value, or `null` when the input was tampered with or is invalid. */
export function unseal(token: string, key: Buffer, purpose: string): unknown {
  try {
    const raw = Buffer.from(token, 'base64url');
    if (raw.length <= IV_BYTES + TAG_BYTES) return null;
    const iv = raw.subarray(0, IV_BYTES);
    const tag = raw.subarray(raw.length - TAG_BYTES);
    const ciphertext = raw.subarray(IV_BYTES, raw.length - TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from(purpose));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
      'utf8',
    );
    return JSON.parse(plaintext) as unknown;
  } catch {
    return null;
  }
}
