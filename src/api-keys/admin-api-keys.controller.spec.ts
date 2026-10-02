import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { Reflector } from '@nestjs/core';
import { RateLimitGuard, RolesGuard, ROLES_KEY } from '@tsdevstack/nest-common';
import type { AuthenticatedRequest } from '@tsdevstack/nest-common';
import { AdminApiKeysController } from './admin-api-keys.controller';
import { ApiKeysService } from './api-keys.service';
import { ActiveAdminGuard } from '../admin/active-admin.guard';

describe('AdminApiKeysController', () => {
  let controller: AdminApiKeysController;
  let service: {
    list: jest.Mock;
    create: jest.Mock;
    get: jest.Mock;
    update: jest.Mock;
    revoke: jest.Mock;
    rotate: jest.Mock;
    usage: jest.Mock;
  };

  const adminRequest = {
    authType: 'user',
    user: { id: 'admin-1', systemRole: 'ADMIN', roles: [] },
  } as unknown as AuthenticatedRequest;

  beforeEach(async () => {
    service = {
      list: jest.fn().mockResolvedValue([]),
      create: jest.fn().mockResolvedValue({ id: 'k1', key: 'tsk_x' }),
      get: jest.fn().mockResolvedValue({ id: 'k1' }),
      update: jest.fn().mockResolvedValue({ id: 'k1' }),
      revoke: jest.fn().mockResolvedValue({ id: 'k1' }),
      rotate: jest.fn().mockResolvedValue({}),
      usage: jest.fn().mockResolvedValue([]),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminApiKeysController],
      providers: [{ provide: ApiKeysService, useValue: service }],
    })
      .overrideGuard(RateLimitGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(ActiveAdminGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get(AdminApiKeysController);
  });

  describe('Permissions', () => {
    const handlers = [
      'list',
      'create',
      'get',
      'update',
      'revoke',
      'rotate',
      'usage',
    ] as const;

    function createContext(
      handler: (typeof handlers)[number],
      request: Record<string, unknown>,
    ): ExecutionContext {
      return {
        getHandler: (): unknown =>
          Object.getOwnPropertyDescriptor(
            AdminApiKeysController.prototype,
            handler,
          )?.value,
        getClass: () => AdminApiKeysController,
        switchToHttp: () => ({ getRequest: () => request }),
      } as unknown as ExecutionContext;
    }

    it('should require the ADMIN role on the whole controller', () => {
      expect(Reflect.getMetadata(ROLES_KEY, AdminApiKeysController)).toEqual([
        'ADMIN',
      ]);
    });

    it('should run RolesGuard, then RateLimitGuard, then the database re-check', () => {
      expect(
        Reflect.getMetadata(GUARDS_METADATA, AdminApiKeysController),
      ).toEqual([RolesGuard, RateLimitGuard, ActiveAdminGuard]);
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

  describe('Delegation', () => {
    it('list passes the consumer filter', async () => {
      await controller.list({ consumer: 'acme-corp' });
      expect(service.list).toHaveBeenCalledWith('acme-corp');
    });

    it('create passes the acting admin', async () => {
      const body = { name: 'n', consumer: 'acme-corp' };
      await expect(controller.create(adminRequest, body)).resolves.toEqual({
        id: 'k1',
        key: 'tsk_x',
      });
      expect(service.create).toHaveBeenCalledWith('admin-1', body);
    });

    it('get, update, revoke and usage pass the id', async () => {
      await controller.get('k1');
      await controller.update('k1', { limitPerMinute: null });
      await controller.revoke('k1');
      await controller.usage('k1');
      expect(service.get).toHaveBeenCalledWith('k1');
      expect(service.update).toHaveBeenCalledWith('k1', {
        limitPerMinute: null,
      });
      expect(service.revoke).toHaveBeenCalledWith('k1');
      expect(service.usage).toHaveBeenCalledWith('k1');
    });

    it('rotate passes the admin, id and grace (default when absent)', async () => {
      await controller.rotate(adminRequest, 'k1', { graceHours: 2 });
      await controller.rotate(adminRequest, 'k1', {});
      expect(service.rotate).toHaveBeenNthCalledWith(1, 'admin-1', 'k1', 2);
      expect(service.rotate).toHaveBeenNthCalledWith(
        2,
        'admin-1',
        'k1',
        undefined,
      );
    });
  });
});
