import { randomBytes } from 'node:crypto';
import { hashApiKey } from '@tsdevstack/nest-common';
import {
  API_KEY_DISPLAY_PREFIX_LENGTH,
  API_KEY_PREFIX,
  API_KEY_RANDOM_BYTES,
} from '../api-keys.constants';
import type { GeneratedApiKey } from '../api-keys.types';

/**
 * Generates a new key: `tsk_` plus base64url of 32 random bytes (47
 * characters), its display prefix and its sha256 hex hash.
 */
export function generateApiKey(): GeneratedApiKey {
  const key = `${API_KEY_PREFIX}${randomBytes(API_KEY_RANDOM_BYTES).toString('base64url')}`;
  return {
    key,
    prefix: key.slice(0, API_KEY_DISPLAY_PREFIX_LENGTH),
    keyHash: hashApiKey(key),
  };
}
