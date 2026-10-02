import { IsOptional, Matches, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import {
  CONSUMER_NAME_MAX_LENGTH,
  CONSUMER_NAME_PATTERN,
} from '../api-keys.constants';

export class ListApiKeysQueryDto {
  @ApiProperty({
    description: 'Only keys of this consumer',
    example: 'acme-corp',
    required: false,
    type: String,
  })
  @IsOptional()
  @MaxLength(CONSUMER_NAME_MAX_LENGTH)
  @Matches(CONSUMER_NAME_PATTERN, { message: 'consumer must be kebab-case' })
  consumer?: string;
}
