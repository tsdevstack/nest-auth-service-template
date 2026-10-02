import { ApiProperty } from '@nestjs/swagger';

/** Saved request total of one period, copied from the gateway by the usage sync job */
export class ApiKeyUsageDto {
  @ApiProperty({
    description: 'ISO week (2026-W40) or calendar month (2026-09), UTC',
    example: '2026-09',
    type: String,
  })
  period: string;

  @ApiProperty({
    description:
      'Requests admitted in the period, as of the last sync. Stored as a 64-bit integer: a JSON number while exact (up to 2^53 - 1), a decimal string above that.',
    example: 1234,
    oneOf: [{ type: 'integer' }, { type: 'string', pattern: '^[0-9]+$' }],
  })
  count: number | string;
}
