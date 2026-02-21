import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { UserService } from './user.service';
import { PrismaService } from '../prisma/prisma.service';

describe('UserService', () => {
  let service: UserService;
  let mockPrismaService: {
    user: {
      findUnique: jest.Mock;
      update: jest.Mock;
    };
  };

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    firstName: 'John',
    lastName: 'Doe',
    role: 'USER',
    confirmed: true,
    status: 'ACTIVE',
    passwordHash: 'hashed-password-should-be-excluded',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
  };

  beforeEach(async () => {
    mockPrismaService = {
      user: {
        findUnique: jest.fn(),
        update: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getUserAccount', () => {
    it('should return user without passwordHash', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      const result = await service.getUserAccount('user-123');

      expect(result).not.toHaveProperty('passwordHash');
      expect(result.id).toBe('user-123');
      expect(result.email).toBe('test@example.com');
      expect(result.firstName).toBe('John');
      expect(result.lastName).toBe('Doe');
    });

    it('should call prisma with correct user id', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await service.getUserAccount('user-123');

      expect(mockPrismaService.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-123' },
      });
    });

    it('should throw NotFoundException when user not found', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(service.getUserAccount('nonexistent')).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.getUserAccount('nonexistent')).rejects.toThrow(
        'User not found',
      );
    });
  });

  describe('updateUserAccount', () => {
    it('should update user and return without passwordHash', async () => {
      const updatedUser = { ...mockUser, firstName: 'Jane' };
      mockPrismaService.user.update.mockResolvedValue(updatedUser);

      const result = await service.updateUserAccount('user-123', {
        firstName: 'Jane',
      });

      expect(result).not.toHaveProperty('passwordHash');
      expect(result.firstName).toBe('Jane');
    });

    it('should call prisma with correct parameters', async () => {
      mockPrismaService.user.update.mockResolvedValue(mockUser);
      const updateData = { firstName: 'Jane', lastName: 'Smith' };

      await service.updateUserAccount('user-123', updateData);

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: 'user-123' },
        data: updateData,
      });
    });

    it('should handle partial updates', async () => {
      const updatedUser = { ...mockUser, lastName: 'Smith' };
      mockPrismaService.user.update.mockResolvedValue(updatedUser);

      const result = await service.updateUserAccount('user-123', {
        lastName: 'Smith',
      });

      expect(result.lastName).toBe('Smith');
      expect(result.firstName).toBe('John'); // Unchanged
    });

    it('should handle empty update data', async () => {
      mockPrismaService.user.update.mockResolvedValue(mockUser);

      const result = await service.updateUserAccount('user-123', {});

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: 'user-123' },
        data: {},
      });
      expect(result.id).toBe('user-123');
    });
  });
});
