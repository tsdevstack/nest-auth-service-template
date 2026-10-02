import { hashApiKey } from '@tsdevstack/nest-common';
import { generateApiKey } from './generate-api-key';

describe('generateApiKey', () => {
  it('should be tsk_ plus 43 base64url characters (32 bytes)', () => {
    const { key } = generateApiKey();
    expect(key).toMatch(/^tsk_[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(key.slice(4), 'base64url')).toHaveLength(32);
  });

  it('should return the 12-character display prefix and the sha256 hash', () => {
    const generated = generateApiKey();
    expect(generated.prefix).toBe(generated.key.slice(0, 12));
    expect(generated.keyHash).toBe(hashApiKey(generated.key));
  });

  it('should never repeat', () => {
    const keys = new Set(
      Array.from({ length: 200 }, () => generateApiKey().key),
    );
    expect(keys.size).toBe(200);
  });
});
