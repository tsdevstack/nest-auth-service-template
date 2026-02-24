import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException, ConflictException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { getQueueToken } from '@nestjs/bullmq';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from './jwt.service';
import { SecretsService, LoggerService } from '@tsdevstack/nest-common';
import * as bcrypt from 'bcrypt';
import { createHash, randomBytes } from 'crypto';

// Mock bcrypt
jest.mock('bcrypt');

describe('AuthService', () => {
  let service: AuthService;
  let mockPrismaService: {
    user: { findUnique: jest.Mock; create: jest.Mock; update: jest.Mock };
    confirmationToken: {
      findUnique: jest.Mock;
      create: jest.Mock;
      delete: jest.Mock;
      deleteMany: jest.Mock;
    };
    refreshToken: {
      findFirst: jest.Mock;
      create: jest.Mock;
      delete: jest.Mock;
      deleteMany: jest.Mock;
    };
    passwordResetToken: {
      findUnique: jest.Mock;
      create: jest.Mock;
      delete: jest.Mock;
      deleteMany: jest.Mock;
    };
    $transaction: jest.Mock;
  };
  let mockJwtService: { sign: jest.Mock };
  let mockConfigService: { get: jest.Mock };
  let mockSecretsService: { get: jest.Mock };
  let mockNotificationQueue: { add: jest.Mock };
  let mockLoggerService: {
    child: jest.Mock;
    debug: jest.Mock;
    info: jest.Mock;
    error: jest.Mock;
  };

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    firstName: 'John',
    lastName: 'Doe',
    passwordHash: 'hashed-password',
    role: 'USER',
    confirmed: true,
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    mockPrismaService = {
      user: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      confirmationToken: {
        findUnique: jest.fn(),
        create: jest.fn(),
        delete: jest.fn(),
        deleteMany: jest.fn(),
      },
      refreshToken: {
        findFirst: jest.fn(),
        create: jest.fn(),
        delete: jest.fn(),
        deleteMany: jest.fn(),
      },
      passwordResetToken: {
        findUnique: jest.fn(),
        create: jest.fn(),
        delete: jest.fn(),
        deleteMany: jest.fn(),
      },
      $transaction: jest.fn(
        <T>(callback: (prisma: typeof mockPrismaService) => Promise<T>) =>
          callback(mockPrismaService),
      ),
    };

    mockJwtService = {
      sign: jest.fn().mockResolvedValue('mock-access-token'),
    };

    mockConfigService = {
      get: jest.fn((key: string, defaultValue: string) => defaultValue),
    };

    mockSecretsService = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'BCRYPT_ROUNDS') return Promise.resolve('12');
        if (key === 'APP_URL') return Promise.resolve('http://localhost:3000');
        return Promise.resolve('');
      }),
    };

    mockNotificationQueue = {
      add: jest.fn().mockResolvedValue({ id: 'job-1' }),
    };

    mockLoggerService = {
      child: jest.fn().mockReturnThis(),
      debug: jest.fn(),
      info: jest.fn(),
      error: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: SecretsService, useValue: mockSecretsService },
        {
          provide: getQueueToken('notifications'),
          useValue: mockNotificationQueue,
        },
        { provide: LoggerService, useValue: mockLoggerService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    await service.onModuleInit();

    // Reset bcrypt mocks
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('onModuleInit', () => {
    it('should load bcrypt rounds and app url from secrets', () => {
      const calls = mockSecretsService.get.mock.calls.map(
        (c: unknown[]) => c[0],
      );
      expect(calls).toContain('BCRYPT_ROUNDS');
      expect(calls).toContain('APP_URL');
    });
  });

  describe('signup', () => {
    const signupDto = {
      firstName: 'John',
      lastName: 'Doe',
      email: 'new@example.com',
      password: 'password123',
    };

    it('should create a new user and send confirmation email', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);
      mockPrismaService.user.create.mockResolvedValue({
        ...mockUser,
        id: 'new-user-id',
        email: signupDto.email,
        confirmed: false,
        status: 'INACTIVE',
      });
      mockPrismaService.confirmationToken.create.mockResolvedValue({});

      const result = await service.signup(signupDto);

      expect(result.message).toBe('Signed up successfully');
      expect(mockPrismaService.user.findUnique).toHaveBeenCalledWith({
        where: { email: signupDto.email },
      });
      expect(bcrypt.hash).toHaveBeenCalledWith(signupDto.password, 12);
      expect(mockNotificationQueue.add).toHaveBeenCalledWith(
        'confirmation-email',
        expect.objectContaining({
          to: signupDto.email,
          subject: 'Verify your email',
        }),
      );
    });

    it('should throw ConflictException if email already exists', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await expect(service.signup(signupDto)).rejects.toThrow(
        ConflictException,
      );
      await expect(service.signup(signupDto)).rejects.toThrow(
        'Email already exists',
      );
    });

    it('should hash the confirmation token before storing', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);
      mockPrismaService.user.create.mockResolvedValue({
        ...mockUser,
        id: 'new-user-id',
        confirmed: false,
      });

      await service.signup(signupDto);

      // Verify token is hashed (64 char hex = SHA256)
      const createCalls = mockPrismaService.confirmationToken.create.mock
        .calls as Array<[{ data: { token: string } }]>;
      expect(createCalls).toHaveLength(1);
      const tokenData = createCalls[0][0].data.token;
      expect(tokenData).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('login', () => {
    const loginDto = { email: 'test@example.com', password: 'password123' };

    it('should return tokens for valid credentials', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);
      mockPrismaService.refreshToken.create.mockResolvedValue({});

      const result = await service.login(loginDto);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(mockJwtService.sign).toHaveBeenCalled();
      expect(mockPrismaService.refreshToken.create).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for non-existent user', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(service.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.login(loginDto)).rejects.toThrow(
        'Invalid credentials',
      );
    });

    it('should throw UnauthorizedException for wrong password', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(service.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.login(loginDto)).rejects.toThrow(
        'Invalid credentials',
      );
    });

    it('should include user info in JWT payload', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);
      mockPrismaService.refreshToken.create.mockResolvedValue({});

      await service.login(loginDto);

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: mockUser.id,
          email: mockUser.email,
          role: mockUser.role,
          confirmed: mockUser.confirmed,
          status: mockUser.status,
          iss: 'auth-service',
          aud: 'kong',
        }),
        expect.any(String),
      );
    });
  });

  describe('confirmEmail', () => {
    const token = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(token).digest('hex');

    it('should confirm user email with valid token', async () => {
      mockPrismaService.confirmationToken.findUnique.mockResolvedValue({
        id: 'token-id',
        token: tokenHash,
        expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
        user: { ...mockUser, confirmed: false },
        userId: mockUser.id,
      });
      mockPrismaService.user.update.mockResolvedValue({
        ...mockUser,
        confirmed: true,
        status: 'ACTIVE',
      });
      mockPrismaService.confirmationToken.delete.mockResolvedValue({});

      const result = await service.confirmEmail(token);

      expect(result.message).toBe('Email confirmed successfully');
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { confirmed: true, status: 'ACTIVE' },
      });
    });

    it('should throw UnauthorizedException for invalid token', async () => {
      mockPrismaService.confirmationToken.findUnique.mockResolvedValue(null);

      await expect(service.confirmEmail('invalid-token')).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.confirmEmail('invalid-token')).rejects.toThrow(
        'Invalid confirmation token',
      );
    });

    it('should throw UnauthorizedException for expired token', async () => {
      mockPrismaService.confirmationToken.findUnique.mockResolvedValue({
        id: 'token-id',
        token: tokenHash,
        expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        user: mockUser,
        userId: mockUser.id,
      });

      await expect(service.confirmEmail(token)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.confirmEmail(token)).rejects.toThrow(
        'Confirmation token has expired',
      );
    });

    it('should throw UnauthorizedException if already confirmed', async () => {
      mockPrismaService.confirmationToken.findUnique.mockResolvedValue({
        id: 'token-id',
        token: tokenHash,
        expiresAt: new Date(Date.now() + 3600000),
        user: { ...mockUser, confirmed: true },
        userId: mockUser.id,
      });

      await expect(service.confirmEmail(token)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.confirmEmail(token)).rejects.toThrow(
        'Email already confirmed',
      );
    });
  });

  describe('refreshToken', () => {
    const refreshToken = randomBytes(64).toString('hex');
    const tokenHash = createHash('sha256').update(refreshToken).digest('hex');

    it('should return new tokens for valid refresh token', async () => {
      mockPrismaService.refreshToken.findFirst.mockResolvedValue({
        id: 'token-id',
        tokenHash,
        expiresAt: new Date(Date.now() + 3600000),
        user: mockUser,
        userId: mockUser.id,
      });
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({ count: 1 });
      mockPrismaService.refreshToken.create.mockResolvedValue({});

      const result = await service.refreshToken(refreshToken);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(mockPrismaService.refreshToken.deleteMany).toHaveBeenCalled();
      expect(mockPrismaService.refreshToken.create).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for invalid refresh token', async () => {
      mockPrismaService.refreshToken.findFirst.mockResolvedValue(null);

      await expect(service.refreshToken('invalid-token')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for expired refresh token', async () => {
      mockPrismaService.refreshToken.findFirst.mockResolvedValue({
        id: 'token-id',
        tokenHash,
        expiresAt: new Date(Date.now() - 3600000), // Expired
        user: mockUser,
        userId: mockUser.id,
      });

      await expect(service.refreshToken(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('logout', () => {
    it('should delete refresh token', async () => {
      const refreshToken = 'some-refresh-token';
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({ count: 1 });

      const result = await service.logout(refreshToken);

      expect(result.message).toBe('Logged out successfully');
      expect(mockPrismaService.refreshToken.deleteMany).toHaveBeenCalled();
    });
  });

  describe('forgotPassword', () => {
    it('should send reset email for existing user', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);
      mockPrismaService.passwordResetToken.deleteMany.mockResolvedValue({});
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({});
      mockPrismaService.passwordResetToken.create.mockResolvedValue({});

      const result = await service.forgotPassword({ email: mockUser.email });

      expect(result.message).toContain('reset link');
      expect(mockNotificationQueue.add).toHaveBeenCalledWith(
        'password-reset',
        expect.objectContaining({
          to: mockUser.email,
          subject: 'Reset your password',
        }),
      );
    });

    it('should return success message even for non-existent user (security)', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      const result = await service.forgotPassword({
        email: 'nonexistent@example.com',
      });

      expect(result.message).toContain('reset link');
      expect(mockNotificationQueue.add).not.toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    const token = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const newPassword = 'newPassword123';

    it('should reset password with valid token', async () => {
      mockPrismaService.passwordResetToken.findUnique.mockResolvedValue({
        id: 'token-id',
        token: tokenHash,
        expiresAt: new Date(Date.now() + 3600000),
        user: mockUser,
        userId: mockUser.id,
      });
      mockPrismaService.user.update.mockResolvedValue(mockUser);
      mockPrismaService.passwordResetToken.delete.mockResolvedValue({});
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({});

      const result = await service.resetPassword({
        token,
        password: newPassword,
      });

      expect(result.message).toBe('Password reset successfully');
      expect(bcrypt.hash).toHaveBeenCalledWith(newPassword, 12);
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { passwordHash: 'hashed-password' },
      });
    });

    it('should throw UnauthorizedException for invalid token', async () => {
      mockPrismaService.passwordResetToken.findUnique.mockResolvedValue(null);

      await expect(
        service.resetPassword({ token: 'invalid', password: newPassword }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should invalidate all refresh tokens after password reset', async () => {
      mockPrismaService.passwordResetToken.findUnique.mockResolvedValue({
        id: 'token-id',
        token: tokenHash,
        expiresAt: new Date(Date.now() + 3600000),
        user: mockUser,
        userId: mockUser.id,
      });
      mockPrismaService.user.update.mockResolvedValue(mockUser);
      mockPrismaService.passwordResetToken.delete.mockResolvedValue({});
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({});

      await service.resetPassword({ token, password: newPassword });

      expect(mockPrismaService.refreshToken.deleteMany).toHaveBeenCalledWith({
        where: { userId: mockUser.id },
      });
    });
  });

  describe('resendConfirmation', () => {
    it('should send new confirmation email', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...mockUser,
        confirmed: false,
      });
      mockPrismaService.confirmationToken.deleteMany.mockResolvedValue({});
      mockPrismaService.confirmationToken.create.mockResolvedValue({});

      const result = await service.resendConfirmation(mockUser.email);

      expect(result.message).toContain('Confirmation email sent');
      expect(mockNotificationQueue.add).toHaveBeenCalled();
    });

    it('should return generic message for non-existent email (security)', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      const result = await service.resendConfirmation(
        'nonexistent@example.com',
      );

      expect(result.message).toContain('If this email is registered');
      expect(mockNotificationQueue.add).not.toHaveBeenCalled();
    });

    it('should throw if email already confirmed', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...mockUser,
        confirmed: true,
      });
      mockPrismaService.confirmationToken.deleteMany.mockResolvedValue({});

      await expect(service.resendConfirmation(mockUser.email)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.resendConfirmation(mockUser.email)).rejects.toThrow(
        'Email already confirmed',
      );
    });
  });
});
