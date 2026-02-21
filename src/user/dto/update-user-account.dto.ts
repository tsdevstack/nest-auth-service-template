import { IsString, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateUserAccountDto {
  @ApiProperty({
    description: 'User first name',
    example: 'John',
    required: false,
    type: String,
  })
  @IsOptional()
  @IsString()
  firstName?: string;

  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    required: false,
    type: String,
  })
  @IsOptional()
  @IsString()
  lastName?: string;
}
