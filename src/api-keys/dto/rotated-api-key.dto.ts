import { ApiProperty } from '@nestjs/swagger';
import { ApiKeyDto } from './api-key.dto';
import { CreatedApiKeyDto } from './created-api-key.dto';

/** Result of a rotation: the new key (shown once) and the old key's new expiry */
export class RotatedApiKeyDto {
  @ApiProperty({
    description: 'The replacement key, with the key itself (shown once)',
    type: () => CreatedApiKeyDto,
  })
  newKey: CreatedApiKeyDto;

  @ApiProperty({
    description: 'The old key; it works until its (shortened) expiresAt',
    type: () => ApiKeyDto,
  })
  previousKey: ApiKeyDto;
}
