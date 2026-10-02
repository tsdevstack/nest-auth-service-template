import { IsInt, IsOptional, Max, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import {
  API_KEY_ROTATION_DEFAULT_GRACE_HOURS,
  API_KEY_ROTATION_MAX_GRACE_HOURS,
} from '../api-keys.constants';

export class RotateApiKeyDto {
  @ApiProperty({
    description:
      'How long the old key keeps working, in hours (0 ends it now). Its expiry becomes the earlier of its current expiry and now plus the grace.',
    example: API_KEY_ROTATION_DEFAULT_GRACE_HOURS,
    default: API_KEY_ROTATION_DEFAULT_GRACE_HOURS,
    minimum: 0,
    maximum: API_KEY_ROTATION_MAX_GRACE_HOURS,
    required: false,
    type: Number,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(API_KEY_ROTATION_MAX_GRACE_HOURS)
  graceHours?: number;
}
