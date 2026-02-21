import { Controller, Post, Body, UseGuards, Version } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import {
  RateLimitGuard,
  RateLimitDecorator,
  EmailRateLimitGuard,
  EmailRateLimitDecorator,
  Public,
} from '@tsdevstack/nest-common';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { ReturnMessageDto } from './dto/return-message.dto';
import { TokenDto } from './dto/token.dto';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'signup',
    summary: 'Register a new user account',
    description:
      'Creates a new user account with email verification. Requires valid email and password. Account will be inactive until email is confirmed.',
  })
  @ApiBody({
    type: SignupDto,
    description: 'User registration details',
  })
  @ApiResponse({
    status: 201,
    description: 'Account created successfully. Verification email sent.',
    type: ReturnMessageDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 409, description: 'Email already exists' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 5,
    windowMs: 60 * 60 * 1000, // 5 signups per IP per hour
    message: 'Too many signup attempts from this IP',
  })
  async signup(@Body() signupDto: SignupDto): Promise<ReturnMessageDto> {
    return await this.authService.signup(signupDto);
  }

  @Post('login')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'login',
    summary: 'Authenticate user and get access tokens',
    description:
      'Authenticates user credentials and returns access and refresh tokens. Login is allowed regardless of email confirmation status.',
  })
  @ApiBody({
    type: LoginDto,
    description: 'User login credentials',
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful. Returns access and refresh tokens.',
    type: TokenDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard, EmailRateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 20,
    windowMs: 15 * 60 * 1000, // 20 attempts per IP per 15 min
    message: 'Too many login attempts from this IP',
  })
  @EmailRateLimitDecorator({
    maxRequests: 5,
    windowMs: 15 * 60 * 1000, // 5 attempts per email per 15 min
    message: 'Too many login attempts for this email',
  })
  async login(@Body() loginDto: LoginDto): Promise<TokenDto> {
    return await this.authService.login(loginDto);
  }

  @Post('confirm-email')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'confirmEmail',
    summary: 'Confirm email address',
    description:
      'Verifies user email address using the confirmation token sent during registration. Sets user status to ACTIVE and confirmed to true.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: {
          type: 'string',
          description: 'Email confirmation token received via email',
        },
      },
      required: ['token'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Email confirmed successfully. User account is now active.',
    type: ReturnMessageDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid, expired, or already used confirmation token',
  })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    message: 'Too many confirmation attempts',
  })
  async confirmEmail(
    @Body() { token }: { token: string },
  ): Promise<ReturnMessageDto> {
    return await this.authService.confirmEmail(token);
  }

  @Post('resend-confirmation')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'resendConfirmation',
    summary: 'Resend email confirmation',
    description:
      'Sends a new email confirmation token to the specified email address. Cleans up any existing tokens before creating a new one.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          format: 'email',
          description: 'Email address to resend confirmation to',
        },
      },
      required: ['email'],
    },
  })
  @ApiResponse({
    status: 200,
    description:
      'Confirmation email sent successfully (or generic response for security)',
    type: ReturnMessageDto,
  })
  @ApiResponse({ status: 401, description: 'Email already confirmed' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard, EmailRateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    message: 'Too many resend attempts from this IP',
  })
  @EmailRateLimitDecorator({
    maxRequests: 3,
    windowMs: 60 * 60 * 1000, // 3 re-sends per email per hour
    message: 'Too many confirmation emails sent to this address',
  })
  async resendConfirmation(
    @Body() { email }: { email: string },
  ): Promise<ReturnMessageDto> {
    return await this.authService.resendConfirmation(email);
  }

  @Post('forgot-password')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'forgotPassword',
    summary: 'Request password reset',
    description:
      "Initiates password reset process by sending a reset token to the user's email address. Invalidates existing refresh tokens and reset tokens for security.",
  })
  @ApiBody({
    type: ForgotPasswordDto,
    description: 'Email address for password reset',
  })
  @ApiResponse({
    status: 200,
    description:
      'Password reset email sent successfully (or generic response for security)',
    type: ReturnMessageDto,
  })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard, EmailRateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    message: 'Too many resend attempts from this IP',
  })
  @EmailRateLimitDecorator({
    maxRequests: 3,
    windowMs: 60 * 60 * 1000, // 3 re-sends per email per hour
    message: 'Too many confirmation emails sent to this address',
  })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ): Promise<ReturnMessageDto> {
    return await this.authService.forgotPassword(forgotPasswordDto);
  }

  @Post('reset-password')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'resetPassword',
    summary: 'Reset user password',
    description:
      'Resets user password using the reset token received via email. Invalidates all existing refresh tokens for security. The reset token is single-use and expires after a set time.',
  })
  @ApiBody({
    type: ResetPasswordDto,
    description: 'Password reset token and new password',
  })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully. All refresh tokens invalidated.',
    type: ReturnMessageDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid or expired reset token' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    message: 'Too many reset attempts from this IP',
  })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<ReturnMessageDto> {
    return await this.authService.resetPassword(resetPasswordDto);
  }

  @Post('refresh-token')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'refreshToken',
    summary: 'Refresh access token',
    description:
      'Generates a new access token using a valid refresh token. Implements refresh token rotation - the old refresh token is invalidated and a new one is issued.',
  })
  @ApiBody({
    type: RefreshTokenDto,
    description: 'Valid refresh token',
  })
  @ApiResponse({
    status: 200,
    description: 'New access and refresh tokens generated successfully',
    type: TokenDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    message: 'Too many refresh attempts from this IP',
  })
  async refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<TokenDto> {
    return await this.authService.refreshToken(refreshTokenDto.refreshToken);
  }

  @Post('logout')
  @Version('1')
  @Public()
  @ApiOperation({
    operationId: 'logout',
    summary: 'Logout user',
    description:
      "Invalidates the user's refresh token, effectively logging them out. The access token will remain valid until it expires naturally.",
  })
  @ApiBody({
    type: RefreshTokenDto,
    description: 'Refresh token to invalidate',
  })
  @ApiResponse({
    status: 200,
    description: 'Logout successful. Refresh token invalidated.',
    type: ReturnMessageDto,
  })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @UseGuards(RateLimitGuard)
  @RateLimitDecorator({
    keyGenerator: 'ip',
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    message: 'Too many refresh attempts from this IP',
  })
  async logout(
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<ReturnMessageDto> {
    return await this.authService.logout(refreshTokenDto.refreshToken);
  }
}
