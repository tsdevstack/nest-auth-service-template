import {
  Controller,
  Get,
  UseGuards,
  Put,
  Body,
  Version,
  UnauthorizedException,
  Req,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UpdateUserAccountDto } from './dto/update-user-account.dto';
import { RateLimitGuard, RateLimitDecorator } from '@tsdevstack/nest-common';
import type { AuthenticatedRequest } from '@tsdevstack/nest-common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
} from '@nestjs/swagger';
import { UserDto } from './dto/user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AuthService } from '../auth/auth.service';
import { TokenDto } from '../auth/dto/token.dto';

@Controller('user')
@ApiTags('users')
@ApiBearerAuth() // Indicates that all endpoints require Bearer token
@UseGuards(RateLimitGuard)
@RateLimitDecorator({
  keyGenerator: 'userId',
  maxRequests: 1000,
  windowMs: 60 * 60 * 1000,
})
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly authService: AuthService,
  ) {}

  @Get('account')
  @Version('1')
  @ApiOperation({
    operationId: 'getUserAccount',
    summary: 'Get current user account',
    description:
      'Retrieves the account information for the currently authenticated user. Requires a confirmed email address.',
  })
  @ApiResponse({
    status: 200,
    description: 'User account retrieved successfully',
    type: () => UserDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Authentication required - invalid or missing access token',
  })
  @ApiForbiddenResponse({
    description:
      'Email confirmation required - user must confirm their email address first',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 429,
    description: 'Rate limit exceeded',
  })
  async getAccount(@Req() req: AuthenticatedRequest): Promise<UserDto> {
    if (!req.user?.confirmed) {
      throw new UnauthorizedException('Email not confirmed');
    }
    return await this.userService.getUserAccount(req.user.id);
  }

  @Put('account')
  @Version('1')
  @ApiOperation({
    operationId: 'updateUserAccount',
    summary: 'Update current user account',
    description:
      'Updates the account information for the currently authenticated user. Only provided fields will be updated. Requires a confirmed email address.',
  })
  @ApiBody({
    type: UpdateUserAccountDto,
    description: 'Account fields to update',
  })
  @ApiResponse({
    status: 200,
    description: 'User account updated successfully',
    type: () => UserDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Authentication required - invalid or missing access token',
  })
  @ApiForbiddenResponse({
    description:
      'Email confirmation required - user must confirm their email address first',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input data',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 429,
    description: 'Rate limit exceeded',
  })
  async updateAccount(
    @Req() req: AuthenticatedRequest,
    @Body() updateData: UpdateUserAccountDto,
  ): Promise<UserDto> {
    if (!req.user?.confirmed) {
      throw new UnauthorizedException('Email not confirmed');
    }
    return await this.userService.updateUserAccount(req.user.id, updateData);
  }

  @Put('password')
  @Version('1')
  @ApiOperation({
    operationId: 'changePassword',
    summary: 'Change the password of the current user',
    description:
      'Verifies the current password and sets a new one (same rules as signup). Requires a confirmed email address. Revokes every refresh token of the user, so other sessions end at their next refresh, and returns a new token pair for the calling session.',
  })
  @ApiBody({
    type: ChangePasswordDto,
    description: 'Current and new password',
  })
  @ApiResponse({
    status: 200,
    description: 'Password changed. Returns new access and refresh tokens.',
    type: TokenDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input data or incorrect current password',
  })
  @ApiUnauthorizedResponse({
    description: 'Authentication required - invalid or missing access token',
  })
  @ApiResponse({
    status: 429,
    description: 'Rate limit exceeded',
  })
  @RateLimitDecorator({
    maxRequests: 5,
    windowMs: 15 * 60 * 1000, // 5 attempts per user per 15 min
    message: 'Too many password change attempts',
    customKeyGenerator: (context) =>
      `change-password:${context.switchToHttp().getRequest<AuthenticatedRequest>().user?.id ?? 'anonymous'}`,
  })
  async changePassword(
    @Req() req: AuthenticatedRequest,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<TokenDto> {
    if (!req.user?.confirmed) {
      throw new UnauthorizedException('Email not confirmed');
    }
    return await this.authService.changePassword(
      req.user.id,
      changePasswordDto,
    );
  }
}
