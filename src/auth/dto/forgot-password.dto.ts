import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'Email address to send password reset instructions to',
    example: 'john.doe@example.com',
    format: 'email',
    type: String,
  })
  @IsEmail()
  email: string;
}
