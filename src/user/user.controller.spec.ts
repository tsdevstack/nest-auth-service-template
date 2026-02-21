import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { RateLimitGuard } from '@tsdevstack/nest-common';
import type { AuthenticatedRequest } from '@tsdevstack/nest-common';

/**
 * UserController Test Suite
 *
 * Tests the user account management endpoints which require authentication.
 * Both endpoints enforce email confirmation before allowing access.
 */
describe('UserController', () => {
  let controller: UserController;
  let mockUserService: {
    getUserAccount: jest.Mock;
    updateUserAccount: jest.Mock;
  };

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    firstName: 'John',
    lastName: 'Doe',
    role: 'USER',
    confirmed: true,
    status: 'ACTIVE',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
  };

  /**
   * Creates a mock AuthenticatedRequest with the specified user properties.
   * In production, this request object is populated by the AuthGuard after
   * validating the JWT token.
   */
  function createMockRequest(overrides: {
    id?: string;
    confirmed?: boolean;
    email?: string;
    role?: string;
  }): AuthenticatedRequest {
    return {
      user: {
        id: overrides.id ?? 'user-123',
        confirmed: overrides.confirmed ?? true,
        email: overrides.email ?? 'test@example.com',
        role: overrides.role ?? 'USER',
      },
    } as unknown as AuthenticatedRequest;
  }

  beforeEach(async () => {
    mockUserService = {
      getUserAccount: jest.fn(),
      updateUserAccount: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [{ provide: UserService, useValue: mockUserService }],
    })
      .overrideGuard(RateLimitGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<UserController>(UserController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('GET /user/account (getAccount)', () => {
    describe('when user is authenticated and confirmed', () => {
      it('should return the user account data', async () => {
        const request = createMockRequest({ confirmed: true });
        mockUserService.getUserAccount.mockResolvedValue(mockUser);

        const result = await controller.getAccount(request);

        expect(result).toEqual(mockUser);
      });

      it('should call userService.getUserAccount with the authenticated user ID', async () => {
        const request = createMockRequest({ id: 'user-456', confirmed: true });
        mockUserService.getUserAccount.mockResolvedValue(mockUser);

        await controller.getAccount(request);

        expect(mockUserService.getUserAccount).toHaveBeenCalledTimes(1);
        expect(mockUserService.getUserAccount).toHaveBeenCalledWith('user-456');
      });
    });

    describe('when user email is not confirmed', () => {
      it('should throw UnauthorizedException', async () => {
        const request = createMockRequest({ confirmed: false });

        await expect(controller.getAccount(request)).rejects.toThrow(
          UnauthorizedException,
        );
      });

      it('should include "Email not confirmed" in error message', async () => {
        const request = createMockRequest({ confirmed: false });

        await expect(controller.getAccount(request)).rejects.toThrow(
          'Email not confirmed',
        );
      });

      it('should not call userService.getUserAccount', async () => {
        const request = createMockRequest({ confirmed: false });

        await expect(controller.getAccount(request)).rejects.toThrow();

        expect(mockUserService.getUserAccount).not.toHaveBeenCalled();
      });
    });

    describe('when request has no user context', () => {
      it('should throw UnauthorizedException when user is undefined', async () => {
        const request = { user: undefined } as unknown as AuthenticatedRequest;

        await expect(controller.getAccount(request)).rejects.toThrow(
          UnauthorizedException,
        );
      });

      it('should throw UnauthorizedException when confirmed is undefined', async () => {
        const request = {
          user: { id: 'user-123' },
        } as unknown as AuthenticatedRequest;

        await expect(controller.getAccount(request)).rejects.toThrow(
          UnauthorizedException,
        );
      });
    });
  });

  describe('PUT /user/account (updateAccount)', () => {
    const updateData = { firstName: 'Jane', lastName: 'Smith' };

    describe('when user is authenticated and confirmed', () => {
      it('should update and return the updated user account', async () => {
        const request = createMockRequest({ confirmed: true });
        const updatedUser = { ...mockUser, ...updateData };
        mockUserService.updateUserAccount.mockResolvedValue(updatedUser);

        const result = await controller.updateAccount(request, updateData);

        expect(result).toEqual(updatedUser);
        expect(result.firstName).toBe('Jane');
        expect(result.lastName).toBe('Smith');
      });

      it('should call userService.updateUserAccount with user ID and update data', async () => {
        const request = createMockRequest({ id: 'user-789', confirmed: true });
        mockUserService.updateUserAccount.mockResolvedValue(mockUser);

        await controller.updateAccount(request, updateData);

        expect(mockUserService.updateUserAccount).toHaveBeenCalledTimes(1);
        expect(mockUserService.updateUserAccount).toHaveBeenCalledWith(
          'user-789',
          updateData,
        );
      });

      it('should handle partial updates (firstName only)', async () => {
        const request = createMockRequest({ confirmed: true });
        const partialUpdate = { firstName: 'Jane' };
        const updatedUser = { ...mockUser, firstName: 'Jane' };
        mockUserService.updateUserAccount.mockResolvedValue(updatedUser);

        const result = await controller.updateAccount(request, partialUpdate);

        expect(result.firstName).toBe('Jane');
        expect(result.lastName).toBe('Doe');
        expect(mockUserService.updateUserAccount).toHaveBeenCalledWith(
          'user-123',
          partialUpdate,
        );
      });

      it('should handle partial updates (lastName only)', async () => {
        const request = createMockRequest({ confirmed: true });
        const partialUpdate = { lastName: 'Smith' };
        const updatedUser = { ...mockUser, lastName: 'Smith' };
        mockUserService.updateUserAccount.mockResolvedValue(updatedUser);

        const result = await controller.updateAccount(request, partialUpdate);

        expect(result.firstName).toBe('John');
        expect(result.lastName).toBe('Smith');
      });

      it('should handle empty update data gracefully', async () => {
        const request = createMockRequest({ confirmed: true });
        mockUserService.updateUserAccount.mockResolvedValue(mockUser);

        const result = await controller.updateAccount(request, {});

        expect(result).toEqual(mockUser);
        expect(mockUserService.updateUserAccount).toHaveBeenCalledWith(
          'user-123',
          {},
        );
      });
    });

    describe('when user email is not confirmed', () => {
      it('should throw UnauthorizedException', async () => {
        const request = createMockRequest({ confirmed: false });

        await expect(
          controller.updateAccount(request, updateData),
        ).rejects.toThrow(UnauthorizedException);
      });

      it('should include "Email not confirmed" in error message', async () => {
        const request = createMockRequest({ confirmed: false });

        await expect(
          controller.updateAccount(request, updateData),
        ).rejects.toThrow('Email not confirmed');
      });

      it('should not call userService.updateUserAccount', async () => {
        const request = createMockRequest({ confirmed: false });

        await expect(
          controller.updateAccount(request, updateData),
        ).rejects.toThrow();

        expect(mockUserService.updateUserAccount).not.toHaveBeenCalled();
      });
    });

    describe('when request has no user context', () => {
      it('should throw UnauthorizedException when user is undefined', async () => {
        const request = { user: undefined } as unknown as AuthenticatedRequest;

        await expect(
          controller.updateAccount(request, updateData),
        ).rejects.toThrow(UnauthorizedException);
      });

      it('should throw UnauthorizedException when confirmed is undefined', async () => {
        const request = {
          user: { id: 'user-123' },
        } as unknown as AuthenticatedRequest;

        await expect(
          controller.updateAccount(request, updateData),
        ).rejects.toThrow(UnauthorizedException);
      });
    });
  });
});
