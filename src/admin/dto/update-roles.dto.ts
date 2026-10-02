import { IsArray, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateRolesDto {
  @ApiProperty({
    description:
      'Complete list of custom roles for the user (replaces the current list). Each role must be declared in src/roles/roles.constants.ts; an empty list removes all custom roles.',
    example: [],
    type: [String],
  })
  @IsArray()
  @IsString({ each: true })
  roles: string[];
}
