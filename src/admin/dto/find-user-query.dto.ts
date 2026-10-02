import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class FindUserQueryDto {
  @ApiProperty({
    description: 'Email address of the user to find (case-insensitive)',
    example: 'john.doe@example.com',
    format: 'email',
    type: String,
  })
  @IsEmail({}, { message: 'Enter a valid email address' })
  email: string;
}
