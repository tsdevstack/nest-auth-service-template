import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { Reflector } from '@nestjs/core';
import { RateLimitGuard, RolesGuard, ROLES_KEY } from '@tsdevstack/nest-common';
import type { AuthenticatedRequest } from '@tsdevstack/nest-common';
import { AdminUsersController } from './admin-users.controller';
import { AdminUsersService } from './admin-users.service';
import { ActiveAdminGuard } from './active-admin.guard';

describe('AdminUsersController', () => {
  let controller: AdminUsersController;
  let mockAdminUsersService: {
    findByEmail: jest.Mock;
    updateSystemRole: jest.Mock;
    updateRoles: jest.Mock;
  };

  const adminRequest = {
    authType: 'user',
    user: { id: 'admin-1', systemRole: 'ADMIN', roles: [] },
  } as unknown as AuthenticatedRequest;

  beforeEach(async () => {
    mockAdminUsersService = {
      findByEmail: jest.fn(),
      updateSystemRole: jest.fn(),
      updateRoles: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminUsersController],
      providers: [
        { provide: AdminUsersService, useValue: mockAdminUsersService },
      ],
    })
      .overrideGuard(RateLimitGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(ActiveAdminGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AdminUsersController>(AdminUsersController);
  });

  describe('Permissions', () => {
    const handlers = [
      'findByEmail',
      'updateSystemRole',
      'updateRoles',
    ] as const;

    function createContext(
      handler: (typeof handlers)[number],
      request: Record<string, unknown>,
    ): ExecutionContext {
      return {
        getHandler: (): unknown =>
          Object.getOwnPropertyDescriptor(
            AdminUsersController.prototype,
            handler,
          )?.value,
        getClass: () => AdminUsersController,
        switchToHttp: () => ({ getRequest: () => request }),
      } as unknown as ExecutionContext;
    }

    it('should require the ADMIN role on the whole controller', () => {
      expect(Reflect.getMetadata(ROLES_KEY, AdminUsersController)).toEqual([
        'ADMIN',
      ]);
    });

    it('should run RolesGuard, then RateLimitGuard, then the database re-check', () => {
      const guards = Reflect.getMetadata(
        GUARDS_METADATA,
        AdminUsersController,
      ) as unknown[];

      expect(guards).toEqual([RolesGuard, RateLimitGuard, ActiveAdminGuard]);
    });

    it.each(handlers)(
      '%s: should reject a non-admin user with 403',
      (handler) => {
        const guard = new RolesGuard(new Reflector());

        expect(() =>
          guard.canActivate(
            createContext(handler, {
              authType: 'user',
              user: { id: 'user-1', systemRole: 'USER', roles: ['EDITOR'] },
            }),
          ),
        ).toThrow(ForbiddenException);
      },
    );

    it.each(handlers)('%s: should allow an admin', (handler) => {
      const guard = new RolesGuard(new Reflector());

      expect(
        guard.canActivate(createContext(handler, adminRequest as never)),
      ).toBe(true);
    });

    it.each(handlers)(
      '%s: should reject partner API keys with 403',
      (handler) => {
        const guard = new RolesGuard(new Reflector());

        expect(() =>
          guard.canActivate(
            createContext(handler, {
              authType: 'apiKey',
              apiKey: { id: 'key-1', consumer: 'acme' },
            }),
          ),
        ).toThrow(ForbiddenException);
      },
    );
  });

  describe('GET /admin/users (findByEmail)', () => {
    it('should look the user up by email', async () => {
      const user = { id: 'user-1', email: 'john@example.com' };
      mockAdminUsersService.findByEmail.mockResolvedValue(user);

      await expect(
        controller.findByEmail({ email: 'john@example.com' }),
      ).resolves.toEqual(user);
      expect(mockAdminUsersService.findByEmail).toHaveBeenCalledWith(
        'john@example.com',
      );
    });
  });

  describe('PUT /admin/users/:id/system-role (updateSystemRole)', () => {
    it('should pass the acting admin, target and new role', async () => {
      mockAdminUsersService.updateSystemRole.mockResolvedValue({
        id: 'user-1',
      });

      await controller.updateSystemRole(adminRequest, 'user-1', {
        systemRole: 'ADMIN',
      });

      expect(mockAdminUsersService.updateSystemRole).toHaveBeenCalledWith(
        'admin-1',
        'user-1',
        'ADMIN',
      );
    });
  });

  describe('PUT /admin/users/:id/roles (updateRoles)', () => {
    it('should pass the acting admin, target and roles', async () => {
      mockAdminUsersService.updateRoles.mockResolvedValue({ id: 'user-1' });

      await controller.updateRoles(adminRequest, 'user-1', {
        roles: ['EDITOR'],
      });

      expect(mockAdminUsersService.updateRoles).toHaveBeenCalledWith(
        'admin-1',
        'user-1',
        ['EDITOR'],
      );
    });
  });
});
