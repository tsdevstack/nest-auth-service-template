import {
  getApiKeyWindowId,
  getApiKeyWindowStart,
} from '@tsdevstack/nest-common';

const DAY_SECONDS = 86_400;

/**
 * Label of the usage period that contains `nowSeconds`, as stored in
 * `ApiKeyUsage.period`: ISO week `2026-W40` (week-numbering year) or month
 * `2026-09`. UTC.
 */
export function formatApiKeyUsagePeriod(
  window: 'week' | 'month',
  nowSeconds: number,
): string {
  if (window === 'month') {
    return getApiKeyWindowId('month', nowSeconds);
  }

  // The ISO week belongs to the year of its Thursday
  const thursday = new Date(
    (getApiKeyWindowStart('week', nowSeconds) + 3 * DAY_SECONDS) * 1000,
  );
  const year = thursday.getUTCFullYear();
  const dayOfYear =
    (thursday.getTime() - Date.UTC(year, 0, 1)) / (DAY_SECONDS * 1000);
  const week = Math.floor(dayOfYear / 7) + 1;

  return `${year}-W${String(week).padStart(2, '0')}`;
}
