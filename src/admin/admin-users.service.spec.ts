import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { LoggerService } from '@tsdevstack/nest-common';
import { AdminUsersService } from './admin-users.service';
import { PrismaService } from '../prisma/prisma.service';

const mockCustomRoles: string[] = [];
jest.mock('../roles/roles.constants', () => ({
  get CUSTOM_ROLES(): readonly string[] {
    return mockCustomRoles;
  },
}));

describe('AdminUsersService', () => {
  let service: AdminUsersService;
  let mockPrismaService: {
    user: { findMany: jest.Mock; findUnique: jest.Mock; update: jest.Mock };
  };
  let mockLoggerService: { child: jest.Mock; info: jest.Mock };

  const storedUser = {
    id: 'user-1',
    email: 'john@example.com',
    firstName: 'John',
    lastName: 'Doe',
    passwordHash: 'hash-must-not-leak',
    confirmed: true,
    status: 'ACTIVE',
    systemRole: 'USER',
    roles: [] as string[],
    createdAt: new Date('2026-01-01'),
  };

  beforeEach(async () => {
    mockCustomRoles.length = 0;
    mockPrismaService = {
      user: {
        findMany: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
      },
    };
    mockLoggerService = {
      child: jest.fn().mockReturnThis(),
      info: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AdminUsersService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: LoggerService, useValue: mockLoggerService },
      ],
    }).compile();

    service = module.get<AdminUsersService>(AdminUsersService);
  });

  describe('findByEmail', () => {
    it('should find a user case-insensitively without the password hash', async () => {
      mockPrismaService.user.findMany.mockResolvedValue([storedUser]);

      const result = await service.findByEmail(' John@Example.com ');

      expect(mockPrismaService.user.findMany).toHaveBeenCalledWith({
        where: { email: { equals: 'John@Example.com', mode: 'insensitive' } },
        take: 2,
      });
      expect(result).not.toHaveProperty('passwordHash');
      expect(result.id).toBe('user-1');
    });

    it('should throw NotFoundException for an unknown email', async () => {
      mockPrismaService.user.findMany.mockResolvedValue([]);

      await expect(service.findByEmail('nobody@example.com')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should return 409 when several users match case-insensitively', async () => {
      mockPrismaService.user.findMany.mockResolvedValue([
        storedUser,
        { ...storedUser, id: 'user-2', email: 'JOHN@example.com' },
      ]);

      await expect(service.findByEmail('john@example.com')).rejects.toThrow(
        ConflictException,
      );
      await expect(service.findByEmail('john@example.com')).rejects.toThrow(
        'Several users have this email with different letter case',
      );
    });
  });

  describe('updateSystemRole', () => {
    it('should set the system role and log the actor', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({ id: 'user-1' });
      mockPrismaService.user.update.mockResolvedValue({
        ...storedUser,
        systemRole: 'ADMIN',
      });

      const result = await service.updateSystemRole(
        'admin-1',
        'user-1',
        'ADMIN',
      );

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: 'user-1' },
        data: { systemRole: 'ADMIN' },
      });
      expect(result.systemRole).toBe('ADMIN');
      expect(result).not.toHaveProperty('passwordHash');
      expect(mockLoggerService.info).toHaveBeenCalledWith(
        'System role changed',
        { actorId: 'admin-1', userId: 'user-1', systemRole: 'ADMIN' },
      );
    });

    it('should allow an admin to demote another admin (no last-admin guard)', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({ id: 'admin-2' });
      mockPrismaService.user.update.mockResolvedValue({
        ...storedUser,
        id: 'admin-2',
      });

      await service.updateSystemRole('admin-1', 'admin-2', 'USER');

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: 'admin-2' },
        data: { systemRole: 'USER' },
      });
    });

    it('should throw NotFoundException for an unknown user', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.updateSystemRole('admin-1', 'missing', 'ADMIN'),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });
  });

  describe('updateRoles', () => {
    it('should replace the custom roles with declared ones (deduplicated)', async () => {
      mockCustomRoles.push('EDITOR', 'BILLING');
      mockPrismaService.user.findUnique.mockResolvedValue({ id: 'user-1' });
      mockPrismaService.user.update.mockResolvedValue({
        ...storedUser,
        roles: ['EDITOR', 'BILLING'],
      });

      const result = await service.updateRoles('admin-1', 'user-1', [
        'EDITOR',
        'BILLING',
        'EDITOR',
      ]);

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: 'user-1' },
        data: { roles: ['EDITOR', 'BILLING'] },
      });
      expect(result.roles).toEqual(['EDITOR', 'BILLING']);
    });

    it('should accept an empty list to remove all custom roles', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({ id: 'user-1' });
      mockPrismaService.user.update.mockResolvedValue(storedUser);

      await service.updateRoles('admin-1', 'user-1', []);

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: 'user-1' },
        data: { roles: [] },
      });
    });

    it('should reject undeclared custom roles', async () => {
      mockCustomRoles.push('EDITOR');

      await expect(
        service.updateRoles('admin-1', 'user-1', ['EDITOR', 'SUPERUSER']),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.updateRoles('admin-1', 'user-1', ['SUPERUSER']),
      ).rejects.toThrow('Undeclared custom roles: SUPERUSER');
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('should reject any custom role with the default empty declaration', async () => {
      await expect(
        service.updateRoles('admin-1', 'user-1', ['EDITOR']),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject system role names even if declared as custom roles', async () => {
      mockCustomRoles.push('ADMIN');

      await expect(
        service.updateRoles('admin-1', 'user-1', ['ADMIN']),
      ).rejects.toThrow('System roles cannot be custom roles: ADMIN');
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException for an unknown user', async () => {
      mockCustomRoles.push('EDITOR');
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.updateRoles('admin-1', 'missing', ['EDITOR']),
      ).rejects.toThrow(NotFoundException);
    });
  });
});
