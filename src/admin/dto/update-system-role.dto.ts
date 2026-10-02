import { IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { SystemRole } from '../../generated/prisma/enums';

export class UpdateSystemRoleDto {
  @ApiProperty({
    description: 'New system role of the user',
    example: 'ADMIN',
    enum: ['USER', 'ADMIN'],
    type: String,
  })
  @IsIn(Object.values(SystemRole), {
    message: 'systemRole must be USER or ADMIN',
  })
  systemRole: SystemRole;
}
