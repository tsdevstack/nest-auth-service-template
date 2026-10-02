import {
  IsInt,
  IsISO8601,
  Matches,
  IsOptional,
  IsString,
  Length,
  Max,
  Min,
  ValidateIf,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import {
  API_KEY_EXPIRY_TIMEZONE_PATTERN,
  API_KEY_LIMIT_MAX,
  API_KEY_NAME_MAX_LENGTH,
} from '../api-keys.constants';

const LIMIT_DESCRIPTION =
  "Omit to keep the current value; null to remove the key's own limit (the gateway's global default applies).";

/**
 * Changes to a key. Absent fields stay as they are; `null` clears a limit or
 * the expiry. Takes effect at Kong on the next request.
 */
export class UpdateApiKeyDto {
  @ApiProperty({
    description: 'New label',
    example: 'Production integration',
    maxLength: API_KEY_NAME_MAX_LENGTH,
    required: false,
    type: String,
  })
  @ValidateIf((_, value) => value !== undefined)
  @IsString()
  @Length(1, API_KEY_NAME_MAX_LENGTH)
  name?: string;

  @ApiProperty({
    description: `Requests per minute. ${LIMIT_DESCRIPTION}`,
    example: 120,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    nullable: true,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerMinute?: number | null;

  @ApiProperty({
    description: `Requests per hour. ${LIMIT_DESCRIPTION}`,
    example: 2000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    nullable: true,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerHour?: number | null;

  @ApiProperty({
    description: `Requests per day. ${LIMIT_DESCRIPTION}`,
    example: 20000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    nullable: true,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerDay?: number | null;

  @ApiProperty({
    description: `Requests per ISO week. ${LIMIT_DESCRIPTION}`,
    example: 100000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    nullable: true,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerWeek?: number | null;

  @ApiProperty({
    description: `Requests per calendar month. ${LIMIT_DESCRIPTION}`,
    example: 400000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    nullable: true,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerMonth?: number | null;

  @ApiProperty({
    description:
      'New expiry: ISO 8601 with Z or an offset, 1970 to 9999 (a past time expires the key now). Omit to keep it; null for no expiry.',
    example: '2027-06-30T23:59:59Z',
    format: 'date-time',
    nullable: true,
    required: false,
    type: String,
  })
  @IsOptional()
  @IsISO8601({ strict: true })
  @Matches(API_KEY_EXPIRY_TIMEZONE_PATTERN, {
    message: 'expiresAt must end with Z or an explicit offset such as +02:00',
  })
  expiresAt?: string | null;
}
