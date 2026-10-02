import {
  CONSUMER_NAME_MAX_LENGTH,
  CONSUMER_NAME_PATTERN,
  RESERVED_CONSUMER_NAMES,
  SERVICE_NAME_SUFFIX,
} from '../api-keys.constants';

/**
 * Checks a consumer name: kebab-case starting with a letter, at most 64
 * characters, not `internal` or `partner`, and not a service name (ending
 * in `-service`).
 *
 * @param name - Proposed consumer name
 * @returns Why the name is rejected, or null when it is valid
 */
export function getConsumerNameError(name: unknown): string | null {
  if (typeof name !== 'string' || name.length === 0) {
    return 'consumer is required';
  }

  if (name.length > CONSUMER_NAME_MAX_LENGTH) {
    return `consumer must be at most ${CONSUMER_NAME_MAX_LENGTH} characters`;
  }

  if (!CONSUMER_NAME_PATTERN.test(name)) {
    return 'consumer must be kebab-case: lowercase letters, digits and single hyphens, starting with a letter (for example acme-corp)';
  }

  if (RESERVED_CONSUMER_NAMES.includes(name)) {
    return `consumer must not be ${RESERVED_CONSUMER_NAMES.join(' or ')}`;
  }

  if (name.endsWith(SERVICE_NAME_SUFFIX)) {
    return `consumer must not be a service name (ending in ${SERVICE_NAME_SUFFIX})`;
  }

  return null;
}
