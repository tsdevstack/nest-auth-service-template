import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { RateLimitGuard, EmailRateLimitGuard } from '@tsdevstack/nest-common';

describe('AuthController', () => {
  let controller: AuthController;
  let mockAuthService: jest.Mocked<AuthService>;

  const mockTokenResponse = {
    accessToken: 'access-token-123',
    refreshToken: 'refresh-token-456',
  };

  const mockMessageResponse = {
    message: 'Operation successful',
  };

  // Mock guard that always allows requests
  const mockGuard = { canActivate: () => true };

  beforeEach(async () => {
    mockAuthService = {
      signup: jest.fn(),
      login: jest.fn(),
      confirmEmail: jest.fn(),
      resendConfirmation: jest.fn(),
      forgotPassword: jest.fn(),
      resetPassword: jest.fn(),
      refreshToken: jest.fn(),
      logout: jest.fn(),
    } as unknown as jest.Mocked<AuthService>;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [{ provide: AuthService, useValue: mockAuthService }],
    })
      .overrideGuard(RateLimitGuard)
      .useValue(mockGuard)
      .overrideGuard(EmailRateLimitGuard)
      .useValue(mockGuard)
      .compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('signup', () => {
    const signupDto = {
      email: 'test@example.com',
      password: 'Password123!',
      firstName: 'John',
      lastName: 'Doe',
    };

    it('should call authService.signup with correct parameters', async () => {
      mockAuthService.signup.mockResolvedValue(mockMessageResponse);

      await controller.signup(signupDto);

      expect(mockAuthService.signup.mock.calls).toEqual([[signupDto]]);
    });

    it('should return the result from authService.signup', async () => {
      const expectedResponse = {
        message: 'Please check your email to confirm your account',
      };
      mockAuthService.signup.mockResolvedValue(expectedResponse);

      const result = await controller.signup(signupDto);

      expect(result).toEqual(expectedResponse);
    });
  });

  describe('login', () => {
    const loginDto = {
      email: 'test@example.com',
      password: 'Password123!',
    };

    it('should call authService.login with correct parameters', async () => {
      mockAuthService.login.mockResolvedValue(mockTokenResponse);

      await controller.login(loginDto);

      expect(mockAuthService.login.mock.calls).toEqual([[loginDto]]);
    });

    it('should return tokens from authService.login', async () => {
      mockAuthService.login.mockResolvedValue(mockTokenResponse);

      const result = await controller.login(loginDto);

      expect(result).toEqual(mockTokenResponse);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });
  });

  describe('confirmEmail', () => {
    const token = 'confirmation-token-123';

    it('should call authService.confirmEmail with the token', async () => {
      mockAuthService.confirmEmail.mockResolvedValue(mockMessageResponse);

      await controller.confirmEmail({ token });

      expect(mockAuthService.confirmEmail.mock.calls).toEqual([[token]]);
    });

    it('should return the result from authService.confirmEmail', async () => {
      const expectedResponse = { message: 'Email confirmed successfully' };
      mockAuthService.confirmEmail.mockResolvedValue(expectedResponse);

      const result = await controller.confirmEmail({ token });

      expect(result).toEqual(expectedResponse);
    });
  });

  describe('resendConfirmation', () => {
    const email = 'test@example.com';

    it('should call authService.resendConfirmation with the email', async () => {
      mockAuthService.resendConfirmation.mockResolvedValue(mockMessageResponse);

      await controller.resendConfirmation({ email });

      expect(mockAuthService.resendConfirmation.mock.calls).toEqual([[email]]);
    });

    it('should return the result from authService.resendConfirmation', async () => {
      const expectedResponse = {
        message: 'If your email exists, a confirmation link has been sent',
      };
      mockAuthService.resendConfirmation.mockResolvedValue(expectedResponse);

      const result = await controller.resendConfirmation({ email });

      expect(result).toEqual(expectedResponse);
    });
  });

  describe('forgotPassword', () => {
    const forgotPasswordDto = { email: 'test@example.com' };

    it('should call authService.forgotPassword with correct parameters', async () => {
      mockAuthService.forgotPassword.mockResolvedValue(mockMessageResponse);

      await controller.forgotPassword(forgotPasswordDto);

      expect(mockAuthService.forgotPassword.mock.calls).toEqual([
        [forgotPasswordDto],
      ]);
    });

    it('should return the result from authService.forgotPassword', async () => {
      const expectedResponse = {
        message: 'If your email exists, a password reset link has been sent',
      };
      mockAuthService.forgotPassword.mockResolvedValue(expectedResponse);

      const result = await controller.forgotPassword(forgotPasswordDto);

      expect(result).toEqual(expectedResponse);
    });
  });

  describe('resetPassword', () => {
    const resetPasswordDto = {
      token: 'reset-token-123',
      password: 'NewPassword123!',
    };

    it('should call authService.resetPassword with correct parameters', async () => {
      mockAuthService.resetPassword.mockResolvedValue(mockMessageResponse);

      await controller.resetPassword(resetPasswordDto);

      expect(mockAuthService.resetPassword.mock.calls).toEqual([
        [resetPasswordDto],
      ]);
    });

    it('should return the result from authService.resetPassword', async () => {
      const expectedResponse = { message: 'Password reset successfully' };
      mockAuthService.resetPassword.mockResolvedValue(expectedResponse);

      const result = await controller.resetPassword(resetPasswordDto);

      expect(result).toEqual(expectedResponse);
    });
  });

  describe('refreshToken', () => {
    const refreshTokenDto = { refreshToken: 'refresh-token-123' };

    it('should call authService.refreshToken with the refresh token', async () => {
      mockAuthService.refreshToken.mockResolvedValue(mockTokenResponse);

      await controller.refreshToken(refreshTokenDto);

      expect(mockAuthService.refreshToken.mock.calls).toEqual([
        [refreshTokenDto.refreshToken],
      ]);
    });

    it('should return new tokens from authService.refreshToken', async () => {
      mockAuthService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await controller.refreshToken(refreshTokenDto);

      expect(result).toEqual(mockTokenResponse);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });
  });

  describe('logout', () => {
    const refreshTokenDto = { refreshToken: 'refresh-token-123' };

    it('should call authService.logout with the refresh token', async () => {
      mockAuthService.logout.mockResolvedValue(mockMessageResponse);

      await controller.logout(refreshTokenDto);

      expect(mockAuthService.logout.mock.calls).toEqual([
        [refreshTokenDto.refreshToken],
      ]);
    });

    it('should return the result from authService.logout', async () => {
      const expectedResponse = { message: 'Logged out successfully' };
      mockAuthService.logout.mockResolvedValue(expectedResponse);

      const result = await controller.logout(refreshTokenDto);

      expect(result).toEqual(expectedResponse);
    });
  });
});
