import { ApiProperty } from '@nestjs/swagger';

export class UserDto {
  @ApiProperty({
    description: 'Unique user identifier',
    example: 'clx1234567890abcdef',
    type: String,
  })
  id: string;

  @ApiProperty({
    description: 'User first name',
    example: 'John',
    type: String,
  })
  firstName: string;

  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    type: String,
  })
  lastName: string;

  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    type: String,
  })
  email: string;

  @ApiProperty({
    description: 'Whether the user has confirmed their email',
    example: true,
    type: Boolean,
  })
  confirmed: boolean;

  @ApiProperty({
    description: 'Current user account status',
    example: 'ACTIVE',
    enum: ['ACTIVE', 'INACTIVE'],
    type: String,
  })
  status: 'ACTIVE' | 'INACTIVE';

  @ApiProperty({
    description: 'When the user account was created',
    example: '2024-01-15T10:30:00Z',
    type: Date,
  })
  createdAt: Date;

  @ApiProperty({
    description: 'User role in the system',
    example: 'USER',
    enum: ['USER', 'ADMIN'],
    type: String,
  })
  role: 'USER' | 'ADMIN';
}
