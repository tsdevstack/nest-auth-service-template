import { createHash } from 'node:crypto';
import type Redis from 'ioredis';

/**
 * Runs a Lua script by its SHA1 (`EVALSHA`) and falls back to `EVAL` once
 * when Redis does not have it cached (`NOSCRIPT`, for example after a
 * restart).
 */
export async function runRedisScript(
  client: Redis,
  script: string,
  keys: string[],
  args: string[],
): Promise<unknown> {
  const sha = createHash('sha1').update(script).digest('hex');
  try {
    return await client.evalsha(sha, keys.length, ...keys, ...args);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('NOSCRIPT')) {
      return await client.eval(script, keys.length, ...keys, ...args);
    }
    throw error;
  }
}
