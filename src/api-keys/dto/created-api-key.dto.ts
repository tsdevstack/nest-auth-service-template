import { ApiProperty } from '@nestjs/swagger';
import { ApiKeyDto } from './api-key.dto';

/** A new key, with the key itself. It is shown this one time only. */
export class CreatedApiKeyDto extends ApiKeyDto {
  @ApiProperty({
    description:
      'The API key. Shown once: only its hash is stored. Clients send it in the x-api-key header.',
    example: 'tsk_Qm9vZ3JhcGhpY2FsbHktcmFuZG9tLWtleS1tYXRlcmlhbA',
    type: String,
  })
  key: string;
}
