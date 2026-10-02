import { IsString, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordDto {
  @ApiProperty({
    description: 'Current password of the logged-in user',
    example: 'SecurePass123',
    type: String,
  })
  @IsString()
  @MinLength(1, { message: 'Current password is required' })
  currentPassword: string;

  @ApiProperty({
    description:
      'New password (min 8 chars, must include uppercase, lowercase, and number)',
    example: 'NewSecurePass123',
    minLength: 8,
    type: String,
  })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @Matches(/[a-z]/, {
    message: 'Password must contain at least one lowercase letter',
  })
  @Matches(/[A-Z]/, {
    message: 'Password must contain at least one uppercase letter',
  })
  @Matches(/[0-9]/, { message: 'Password must contain at least one number' })
  newPassword: string;
}
