import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { ActiveAdminGuard } from './active-admin.guard';
import { PrismaService } from '../prisma/prisma.service';

describe('ActiveAdminGuard', () => {
  let guard: ActiveAdminGuard;
  let mockPrismaService: { user: { findUnique: jest.Mock } };

  function createContext(request: Record<string, unknown>): ExecutionContext {
    return {
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
  }

  const userRequest = (systemRole: string): Record<string, unknown> => ({
    authType: 'user',
    user: { id: 'admin-1', systemRole },
  });

  beforeEach(() => {
    mockPrismaService = { user: { findUnique: jest.fn() } };
    guard = new ActiveAdminGuard(mockPrismaService as unknown as PrismaService);
  });

  describe('Standard use cases', () => {
    it('should allow an active admin', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        systemRole: 'ADMIN',
        status: 'ACTIVE',
      });

      await expect(
        guard.canActivate(createContext(userRequest('ADMIN'))),
      ).resolves.toBe(true);
      expect(mockPrismaService.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'admin-1' },
        select: { systemRole: true, status: true },
      });
    });

    it('should reject a caller demoted since the token was issued', async () => {
      // Token still says ADMIN, the database says USER
      mockPrismaService.user.findUnique.mockResolvedValue({
        systemRole: 'USER',
        status: 'ACTIVE',
      });

      await expect(
        guard.canActivate(createContext(userRequest('ADMIN'))),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should reject an inactive admin', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        systemRole: 'ADMIN',
        status: 'INACTIVE',
      });

      await expect(
        guard.canActivate(createContext(userRequest('ADMIN'))),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('Edge cases', () => {
    it('should reject a caller that no longer exists', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        guard.canActivate(createContext(userRequest('ADMIN'))),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should reject partner API key requests without a database lookup', async () => {
      await expect(
        guard.canActivate(
          createContext({
            authType: 'apiKey',
            apiKey: { id: 'key-1', consumer: 'acme' },
          }),
        ),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.user.findUnique).not.toHaveBeenCalled();
    });

    it('should reject internal service calls', async () => {
      await expect(
        guard.canActivate(
          createContext({ authType: 'service', service: 'bff-service' }),
        ),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.user.findUnique).not.toHaveBeenCalled();
    });

    it('should reject anonymous requests', async () => {
      await expect(guard.canActivate(createContext({}))).rejects.toThrow(
        ForbiddenException,
      );
    });
  });
});
