import { createHash } from 'node:crypto';
import type Redis from 'ioredis';
import { runRedisScript } from './run-redis-script';

describe('runRedisScript', () => {
  const script = 'return 1';
  const sha = createHash('sha1').update(script).digest('hex');

  it('should run the cached script by its SHA1', async () => {
    const client = { evalsha: jest.fn().mockResolvedValue(1), eval: jest.fn() };
    await expect(
      runRedisScript(client as unknown as Redis, script, ['k'], ['a']),
    ).resolves.toBe(1);
    expect(client.evalsha).toHaveBeenCalledWith(sha, 1, 'k', 'a');
    expect(client.eval).not.toHaveBeenCalled();
  });

  it('should fall back to EVAL once on NOSCRIPT', async () => {
    const client = {
      evalsha: jest
        .fn()
        .mockRejectedValue(
          new Error('NOSCRIPT No matching script. Please use EVAL.'),
        ),
      eval: jest.fn().mockResolvedValue(2),
    };
    await expect(
      runRedisScript(client as unknown as Redis, script, ['k1', 'k2'], []),
    ).resolves.toBe(2);
    expect(client.eval).toHaveBeenCalledWith(script, 2, 'k1', 'k2');
  });

  it('should rethrow other errors', async () => {
    const client = {
      evalsha: jest.fn().mockRejectedValue(new Error('CROSSSLOT Keys')),
      eval: jest.fn(),
    };
    await expect(
      runRedisScript(client as unknown as Redis, script, ['k'], []),
    ).rejects.toThrow('CROSSSLOT');
    expect(client.eval).not.toHaveBeenCalled();
  });
});
