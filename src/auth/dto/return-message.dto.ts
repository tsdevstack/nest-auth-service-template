import { ApiProperty } from '@nestjs/swagger';

export class ReturnMessageDto {
  @ApiProperty({
    description: 'Response message',
    example: 'Operation completed successfully',
    type: String,
  })
  message: string;
}
