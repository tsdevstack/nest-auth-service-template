import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { SecretsService, LoggerService } from '@tsdevstack/nest-common';
import { InjectQueue } from '@nestjs/bullmq';
import type { Queue } from 'bullmq';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { JwtPayload } from './types';
import { randomBytes } from 'crypto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtService } from './jwt.service';
import { createHash } from 'crypto';
import { TokenDto } from './dto/token.dto';
import { ReturnMessageDto } from './dto/return-message.dto';

interface GenerateConfirmationTokenReturn {
  token: string;
  expiresAt: Date;
}

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly accessTokenTtl: number;
  private readonly refreshTokenTtl: number;
  private readonly confirmationTokenTtl: number;
  private bcryptRounds!: number;
  private appUrl!: string;
  private readonly logger: LoggerService;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
    private secrets: SecretsService,
    @InjectQueue('notifications') private notificationQueue: Queue,
    @InjectQueue('welcome') private welcomeQueue: Queue,
    logger: LoggerService,
  ) {
    this.logger = logger.child('AuthService');
    this.accessTokenTtl = parseInt(
      this.config?.get('ACCESS_TOKEN_TTL', '900') ?? '900',
      10,
    ); // 15 minutes
    this.refreshTokenTtl = parseInt(
      this.config?.get('REFRESH_TOKEN_TTL', '604800') ?? '604800',
      10,
    ); // 7 days
    this.confirmationTokenTtl = parseInt(
      this.config?.get('CONFIRMATION_TOKEN_TTL', '86400') ?? '86400',
      10,
    ); // 24 hours in seconds
  }

  async onModuleInit(): Promise<void> {
    // Load secrets on module initialization
    this.bcryptRounds =
      parseInt(await this.secrets.get('BCRYPT_ROUNDS'), 10) || 12;
    this.appUrl = await this.secrets.get('APP_URL');
  }

  private generateConfirmationToken(): GenerateConfirmationTokenReturn {
    return {
      token: randomBytes(32).toString('hex'),
      expiresAt: new Date(Date.now() + this.confirmationTokenTtl * 1000),
    };
  }

  private createHash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private buildJwtPayload(user: {
    id: string;
    email: string;
    role: string;
    confirmed: boolean;
    status: string;
  }): Omit<JwtPayload, 'iat' | 'exp'> {
    return {
      sub: user.id,
      email: user.email,
      role: user.role,
      confirmed: user.confirmed,
      status: user.status as 'ACTIVE' | 'INACTIVE',
      iss: 'auth-service',
      aud: 'kong',
    };
  }

  private generateRefreshToken(): {
    token: string;
    hash: string;
    expiresAt: Date;
  } {
    const token = randomBytes(64).toString('hex');
    const hash = this.createHash(token);
    const expiresAt = new Date(Date.now() + this.refreshTokenTtl * 1000);
    return { token, hash, expiresAt };
  }

  async signup(signupDto: SignupDto): Promise<ReturnMessageDto> {
    const { firstName, lastName, email, password } = signupDto;

    this.logger.debug('Signup initiated', { email });

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    const passwordHash = await bcrypt.hash(password, this.bcryptRounds);

    // Generate confirmation token before transaction
    const confirmationToken = this.generateConfirmationToken();
    const tokenHash = this.createHash(confirmationToken.token);

    // Use transaction to ensure atomicity
    await this.prisma.$transaction(async (prisma) => {
      const user = await prisma.user.create({
        data: {
          firstName,
          lastName,
          email,
          passwordHash,
          confirmed: false,
          status: 'INACTIVE',
        },
      });

      await prisma.confirmationToken.create({
        data: {
          token: tokenHash, // Store hashed token
          userId: user.id,
          expiresAt: confirmationToken.expiresAt,
        },
      });
    });

    const confirmationUrl = `${this.appUrl}/confirm?token=${confirmationToken.token}`;

    // Log confirmation link in development (useful for testing without email)
    if (process.env.NODE_ENV === 'development') {
      this.logger.debug('Confirmation token generated', { confirmationUrl });
    }

    // Queue confirmation email (async via BullMQ)
    await this.notificationQueue.add('confirmation-email', {
      to: email,
      subject: 'Verify your email',
      html: `
        <h1>Welcome!</h1>
        <p>Thank you for signing up. Please click the link below to verify your email address:</p>
        <p><a href="${confirmationUrl}">Verify Email</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
      `,
    });

    return { message: 'Signed up successfully' };
  }

  async login(loginDto: LoginDto): Promise<TokenDto> {
    const { email, password } = loginDto;

    // Find user by email
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Allow login regardless of confirmation/status
    // We'll handle these checks in the frontend and API guards

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = this.buildJwtPayload(user);

    const accessToken = await this.jwtService.sign(
      payload,
      `${this.accessTokenTtl}s`,
    );

    // Generate a random refresh token
    const {
      token: refreshToken,
      hash,
      expiresAt,
    } = this.generateRefreshToken();

    // Store the refresh token hash in the DB
    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: hash,
        expiresAt,
      },
    });

    return { accessToken, refreshToken };
  }

  async confirmEmail(token: string): Promise<ReturnMessageDto> {
    // Hash the incoming token to match what's stored in DB
    const tokenHash = this.createHash(token);

    // Find the confirmation token by hash
    const confirmationToken = await this.prisma.confirmationToken.findUnique({
      where: { token: tokenHash },
      include: { user: true }, // Include the related user
    });

    // Check if token exists
    if (!confirmationToken) {
      throw new UnauthorizedException('Invalid confirmation token');
    }

    // Check if token is expired
    if (confirmationToken.expiresAt < new Date()) {
      await this.prisma.confirmationToken.delete({
        where: { id: confirmationToken.id },
      });

      throw new UnauthorizedException('Confirmation token has expired');
    }

    // Check if user is already confirmed
    if (confirmationToken.user.confirmed) {
      throw new UnauthorizedException('Email already confirmed');
    }

    // Update user to confirmed and active
    await this.prisma.user.update({
      where: { id: confirmationToken.userId },
      data: {
        confirmed: true,
        status: 'ACTIVE',
      },
    });

    // Delete the used token
    await this.prisma.confirmationToken.delete({
      where: { id: confirmationToken.id },
    });

    // Queue welcome email (processed by standalone worker)
    await this.welcomeQueue.add('welcome-email', {
      to: confirmationToken.user.email,
      firstName: confirmationToken.user.firstName,
    });

    return { message: 'Email confirmed successfully' };
  }

  async resendConfirmation(email: string): Promise<ReturnMessageDto> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      // Don't reveal if email exists or not (security)
      return {
        message:
          'If this email is registered, a confirmation email has been sent.',
      };
    }

    // Clean up existing tokens regardless of confirmation status
    await this.prisma.confirmationToken.deleteMany({
      where: { userId: user.id },
    });

    if (user.confirmed) {
      throw new UnauthorizedException('Email already confirmed');
    }

    // Generate and create new confirmation token (hash before storage)
    const confirmationToken = this.generateConfirmationToken();
    const tokenHash = this.createHash(confirmationToken.token);

    await this.prisma.confirmationToken.create({
      data: {
        token: tokenHash, // Store hashed token
        userId: user.id,
        expiresAt: confirmationToken.expiresAt,
      },
    });

    const confirmationUrl = `${this.appUrl}/confirm?token=${confirmationToken.token}`;

    // Log confirmation link in development (useful for testing without email)
    if (process.env.NODE_ENV === 'development') {
      this.logger.debug('Resend confirmation token generated', {
        confirmationUrl,
      });
    }

    // Queue confirmation email (async via BullMQ)
    await this.notificationQueue.add('confirmation-email', {
      to: email,
      subject: 'Verify your email',
      html: `
        <h1>Email Verification</h1>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="${confirmationUrl}">Verify Email</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
      `,
    });

    return { message: 'Confirmation email sent. Please check your inbox.' };
  }

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
  ): Promise<ReturnMessageDto> {
    const { email } = forgotPasswordDto;

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    // Don't reveal if email exists or not (security)
    if (!user) {
      return {
        message:
          "If your email is registered, you'll receive a reset link shortly.",
      };
    }

    // Delete any existing reset tokens for this user
    await this.prisma.passwordResetToken.deleteMany({
      where: { userId: user.id },
    });

    // Delete any existing refresh tokens for this user
    await this.prisma.refreshToken.deleteMany({
      where: { userId: user.id },
    });

    // Generate reset token
    const resetToken = this.generateConfirmationToken();
    const tokenHash = this.createHash(resetToken.token);

    // Create new reset token (hash before storage)
    await this.prisma.passwordResetToken.create({
      data: {
        token: tokenHash,
        userId: user.id,
        expiresAt: resetToken.expiresAt,
      },
    });

    const resetUrl = `${this.appUrl}/reset-password?token=${resetToken.token}`;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug('Password reset token generated', { resetUrl });
    }

    // Queue password reset email (async via BullMQ)
    await this.notificationQueue.add('password-reset', {
      to: email,
      subject: 'Reset your password',
      html: `
        <h1>Password Reset</h1>
        <p>You requested to reset your password. Click the link below to set a new password:</p>
        <p><a href="${resetUrl}">Reset Password</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't request a password reset, you can safely ignore this email.</p>
      `,
    });

    return {
      message:
        "If your email is registered, you'll receive a reset link shortly.",
    };
  }

  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
  ): Promise<ReturnMessageDto> {
    const { token, password } = resetPasswordDto;

    // Hash the incoming token to match what's stored in DB
    const tokenHash = this.createHash(token);

    // Find the reset token by hash
    const resetToken = await this.prisma.passwordResetToken.findUnique({
      where: { token: tokenHash },
      include: { user: true },
    });

    // Check if token exists
    if (!resetToken) {
      throw new UnauthorizedException('Invalid reset token');
    }

    // Check if token is expired
    if (resetToken.expiresAt < new Date()) {
      // Clean up expired token
      await this.prisma.passwordResetToken.delete({
        where: { id: resetToken.id },
      });
      throw new UnauthorizedException('Reset token has expired');
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(password, this.bcryptRounds);

    // Update user password
    await this.prisma.user.update({
      where: { id: resetToken.userId },
      data: { passwordHash },
    });

    // Delete the used token
    await this.prisma.passwordResetToken.delete({
      where: { id: resetToken.id },
    });

    // Delete any existing refresh tokens for this user
    await this.prisma.refreshToken.deleteMany({
      where: { userId: resetToken.userId },
    });

    return { message: 'Password reset successfully' };
  }

  async refreshToken(refreshToken: string): Promise<TokenDto> {
    // 1. Hash the incoming refresh token
    const tokenHash = this.createHash(refreshToken);

    // 2. Look up the hashed token in the DB
    const storedToken = await this.prisma.refreshToken.findFirst({
      where: { tokenHash },
      include: { user: true },
    });

    // 3. Check if token exists and is not expired
    if (!storedToken || storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const user = storedToken.user;

    // 4. Issue a new access token
    const payload = this.buildJwtPayload(user);

    const accessToken = await this.jwtService.sign(
      payload,
      `${this.accessTokenTtl}s`,
    );

    // 5. Implement refresh token rotation
    // Delete the old refresh token (use deleteMany to avoid P2025 if already deleted)
    await this.prisma.refreshToken.deleteMany({
      where: { id: storedToken.id },
    });

    // Generate a random refresh token
    const {
      token: newRefreshToken,
      hash,
      expiresAt,
    } = this.generateRefreshToken();

    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: hash,
        expiresAt,
      },
    });

    // 6. Return the new tokens
    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  }

  async logout(refreshToken: string): Promise<ReturnMessageDto> {
    const tokenHash = this.createHash(refreshToken);

    await this.prisma.refreshToken.deleteMany({ where: { tokenHash } });

    return { message: 'Logged out successfully' };
  }
}
