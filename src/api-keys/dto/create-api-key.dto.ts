import {
  IsInt,
  IsISO8601,
  Matches,
  IsOptional,
  IsString,
  Length,
  Max,
  Min,
  Validate,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import {
  API_KEY_EXPIRY_TIMEZONE_PATTERN,
  API_KEY_LIMIT_MAX,
  API_KEY_NAME_MAX_LENGTH,
  CONSUMER_NAME_MAX_LENGTH,
} from '../api-keys.constants';
import { ConsumerNameConstraint } from './consumer-name.constraint';

export class CreateApiKeyDto {
  @ApiProperty({
    description: 'Label for admins, for example "Production integration"',
    example: 'Production integration',
    maxLength: API_KEY_NAME_MAX_LENGTH,
    type: String,
  })
  @IsString()
  @Length(1, API_KEY_NAME_MAX_LENGTH)
  name: string;

  @ApiProperty({
    description:
      'Who the key is for (not a user). Kebab-case, starting with a letter; not "internal", "partner" or a service name (ending in -service). Backends read it with @Partner().',
    example: 'acme-corp',
    maxLength: CONSUMER_NAME_MAX_LENGTH,
    type: String,
  })
  @Validate(ConsumerNameConstraint)
  consumer: string;

  @ApiProperty({
    description:
      "Requests per minute (UTC). Omit to use the gateway's global default.",
    example: 60,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerMinute?: number;

  @ApiProperty({
    description:
      "Requests per hour (UTC). Omit to use the gateway's global default.",
    example: 1000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerHour?: number;

  @ApiProperty({
    description:
      "Requests per day (UTC). Omit to use the gateway's global default.",
    example: 10000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerDay?: number;

  @ApiProperty({
    description:
      "Requests per ISO week (Monday 00:00 UTC). Omit to use the gateway's global default.",
    example: 50000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerWeek?: number;

  @ApiProperty({
    description:
      "Requests per calendar month (UTC). Omit to use the gateway's global default.",
    example: 100000,
    minimum: 1,
    maximum: API_KEY_LIMIT_MAX,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(API_KEY_LIMIT_MAX)
  limitPerMonth?: number;

  @ApiProperty({
    description:
      'When the key stops working: ISO 8601 with Z or an offset, in the future, before year 10000. Omit for a key without expiry.',
    example: '2026-12-31T23:59:59Z',
    format: 'date-time',
    required: false,
    type: String,
  })
  @IsOptional()
  @IsISO8601({ strict: true })
  @Matches(API_KEY_EXPIRY_TIMEZONE_PATTERN, {
    message: 'expiresAt must end with Z or an explicit offset such as +02:00',
  })
  expiresAt?: string;
}
