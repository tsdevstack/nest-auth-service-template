import { BadRequestException } from '@nestjs/common';
import {
  API_KEY_EXPIRY_MAX_MS,
  API_KEY_EXPIRY_MIN_MS,
} from '../api-keys.constants';

/**
 * Turns a validated ISO 8601 expiry into a Date (null stays null, meaning
 * no expiry). Rejects values the DTO check cannot catch, such as dates
 * before 1970 or after 9999, with 400 instead of a database error.
 *
 * @throws BadRequestException for an unparsable or out-of-range date
 */
export function parseApiKeyExpiry(
  value: string | null | undefined,
): Date | null {
  if (value === null || value === undefined) {
    return null;
  }

  const date = new Date(value);
  const time = date.getTime();
  if (
    Number.isNaN(time) ||
    time < API_KEY_EXPIRY_MIN_MS ||
    time > API_KEY_EXPIRY_MAX_MS
  ) {
    throw new BadRequestException(
      'expiresAt must be a valid date between 1970 and 9999',
    );
  }
  return date;
}
