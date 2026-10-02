import {
  Body,
  Controller,
  Get,
  Param,
  Put,
  Query,
  Req,
  UseGuards,
  Version,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConflictResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  RateLimitDecorator,
  RateLimitGuard,
  Roles,
} from '@tsdevstack/nest-common';
import type { AuthenticatedRequest } from '@tsdevstack/nest-common';
import { AdminUsersService } from './admin-users.service';
import { ActiveAdminGuard } from './active-admin.guard';
import { FindUserQueryDto } from './dto/find-user-query.dto';
import { UpdateSystemRoleDto } from './dto/update-system-role.dto';
import { UpdateRolesDto } from './dto/update-roles.dto';
import { UserDto } from '../user/dto/user.dto';

/**
 * Admin-only user management.
 *
 * Guards run in this order: `RolesGuard` (from `@Roles('ADMIN')`, checks the
 * role in the JWT, no I/O), `RateLimitGuard`, then `ActiveAdminGuard`
 * (re-checks the caller's current role and status in the database). Class
 * decorators apply bottom-up and each `@UseGuards()` appends, so
 * `@UseGuards()` must stay above `@Roles()` for this order. Role changes
 * apply at the target user's next token refresh.
 */
@Controller('admin/users')
@ApiTags('admin')
@ApiBearerAuth()
@UseGuards(RateLimitGuard, ActiveAdminGuard)
@Roles('ADMIN')
@RateLimitDecorator({
  keyGenerator: 'userId',
  maxRequests: 1000,
  windowMs: 60 * 60 * 1000,
})
export class AdminUsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

  @Get()
  @Version('1')
  @ApiOperation({
    operationId: 'adminFindUserByEmail',
    summary: 'Find a user by email (admin)',
    description:
      'Looks up a user by email address, case-insensitive. Requires the ADMIN system role.',
  })
  @ApiResponse({
    status: 200,
    description: 'User found',
    type: () => UserDto,
  })
  @ApiBadRequestResponse({ description: 'Invalid email address' })
  @ApiUnauthorizedResponse({
    description: 'Authentication required - invalid or missing access token',
  })
  @ApiForbiddenResponse({ description: 'Caller is not an active admin' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiConflictResponse({
    description: 'Several users have this email with different letter case',
  })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async findByEmail(@Query() query: FindUserQueryDto): Promise<UserDto> {
    return await this.adminUsersService.findByEmail(query.email);
  }

  @Put(':id/system-role')
  @Version('1')
  @ApiOperation({
    operationId: 'adminUpdateUserSystemRole',
    summary: 'Change the system role of a user (admin)',
    description:
      'Sets the system role (USER or ADMIN) of a user. Takes effect at the next token refresh of that user. Requires the ADMIN system role.',
  })
  @ApiBody({ type: UpdateSystemRoleDto, description: 'New system role' })
  @ApiResponse({
    status: 200,
    description: 'System role updated',
    type: () => UserDto,
  })
  @ApiBadRequestResponse({ description: 'Invalid system role' })
  @ApiUnauthorizedResponse({
    description: 'Authentication required - invalid or missing access token',
  })
  @ApiForbiddenResponse({ description: 'Caller is not an active admin' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async updateSystemRole(
    @Req() req: AuthenticatedRequest,
    @Param('id') id: string,
    @Body() body: UpdateSystemRoleDto,
  ): Promise<UserDto> {
    return await this.adminUsersService.updateSystemRole(
      req.user?.id ?? '',
      id,
      body.systemRole,
    );
  }

  @Put(':id/roles')
  @Version('1')
  @ApiOperation({
    operationId: 'adminUpdateUserRoles',
    summary: 'Replace the custom roles of a user (admin)',
    description:
      'Replaces the custom roles of a user. Every role must be declared in src/roles/roles.constants.ts. Takes effect at the next token refresh of that user. Requires the ADMIN system role.',
  })
  @ApiBody({ type: UpdateRolesDto, description: 'Complete list of roles' })
  @ApiResponse({
    status: 200,
    description: 'Custom roles updated',
    type: () => UserDto,
  })
  @ApiBadRequestResponse({
    description: 'Undeclared custom role, or a system role name',
  })
  @ApiUnauthorizedResponse({
    description: 'Authentication required - invalid or missing access token',
  })
  @ApiForbiddenResponse({ description: 'Caller is not an active admin' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async updateRoles(
    @Req() req: AuthenticatedRequest,
    @Param('id') id: string,
    @Body() body: UpdateRolesDto,
  ): Promise<UserDto> {
    return await this.adminUsersService.updateRoles(
      req.user?.id ?? '',
      id,
      body.roles,
    );
  }
}
