import { buildApiKeyCounterKey } from '@tsdevstack/nest-common';
import { API_KEY_SEED_FLAG_SEGMENT } from '../api-keys.constants';

/**
 * Name of the flag that marks a week or month counter as already holding
 * the saved total: `apikey:{<h>}:seeded:week:<start>` or
 * `apikey:{<h>}:seeded:month:<YYYY-MM>`. Same hash tag as the counter.
 */
export function buildApiKeySeedFlagKey(
  keyHash: string,
  window: 'week' | 'month',
  nowSeconds: number,
): string {
  const counterKey = buildApiKeyCounterKey(keyHash, window, nowSeconds);
  const tagEnd = counterKey.indexOf('}:') + 2;
  return `${counterKey.slice(0, tagEnd)}${API_KEY_SEED_FLAG_SEGMENT}:${counterKey.slice(tagEnd)}`;
}
