import { Test, TestingModule } from '@nestjs/testing';
import { JobsService } from './jobs.service';
import { PrismaService } from '../prisma/prisma.service';

describe('JobsService', () => {
  let service: JobsService;
  let mockPrismaService: {
    refreshToken: { deleteMany: jest.Mock };
    confirmationToken: { deleteMany: jest.Mock };
    passwordResetToken: { deleteMany: jest.Mock };
  };

  beforeEach(async () => {
    mockPrismaService = {
      refreshToken: {
        deleteMany: jest.fn(),
      },
      confirmationToken: {
        deleteMany: jest.fn(),
      },
      passwordResetToken: {
        deleteMany: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JobsService,
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<JobsService>(JobsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('cleanupTokens', () => {
    it('should delete expired tokens and return counts', async () => {
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({ count: 3 });
      mockPrismaService.confirmationToken.deleteMany.mockResolvedValue({
        count: 2,
      });
      mockPrismaService.passwordResetToken.deleteMany.mockResolvedValue({
        count: 1,
      });

      const result = await service.cleanupTokens();

      expect(result).toEqual({
        success: true,
        deleted: {
          refresh: 3,
          confirmation: 2,
          passwordReset: 1,
        },
      });
    });

    it('should query with expiresAt less than current time', async () => {
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({ count: 0 });
      mockPrismaService.confirmationToken.deleteMany.mockResolvedValue({
        count: 0,
      });
      mockPrismaService.passwordResetToken.deleteMany.mockResolvedValue({
        count: 0,
      });

      const before = new Date();
      await service.cleanupTokens();

      const refreshCall = mockPrismaService.refreshToken.deleteMany.mock
        .calls[0] as [{ where: { expiresAt: { lt: Date } } }];
      const confirmCall = mockPrismaService.confirmationToken.deleteMany.mock
        .calls[0] as [{ where: { expiresAt: { lt: Date } } }];
      const resetCall = mockPrismaService.passwordResetToken.deleteMany.mock
        .calls[0] as [{ where: { expiresAt: { lt: Date } } }];

      expect(
        refreshCall[0].where.expiresAt.lt.getTime(),
      ).toBeGreaterThanOrEqual(before.getTime());
      expect(
        confirmCall[0].where.expiresAt.lt.getTime(),
      ).toBeGreaterThanOrEqual(before.getTime());
      expect(resetCall[0].where.expiresAt.lt.getTime()).toBeGreaterThanOrEqual(
        before.getTime(),
      );
    });

    it('should handle zero expired tokens', async () => {
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({ count: 0 });
      mockPrismaService.confirmationToken.deleteMany.mockResolvedValue({
        count: 0,
      });
      mockPrismaService.passwordResetToken.deleteMany.mockResolvedValue({
        count: 0,
      });

      const result = await service.cleanupTokens();

      expect(result).toEqual({
        success: true,
        deleted: {
          refresh: 0,
          confirmation: 0,
          passwordReset: 0,
        },
      });
    });

    it('should delete all three token types in parallel', async () => {
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({ count: 0 });
      mockPrismaService.confirmationToken.deleteMany.mockResolvedValue({
        count: 0,
      });
      mockPrismaService.passwordResetToken.deleteMany.mockResolvedValue({
        count: 0,
      });

      await service.cleanupTokens();

      expect(mockPrismaService.refreshToken.deleteMany).toHaveBeenCalledTimes(
        1,
      );
      expect(
        mockPrismaService.confirmationToken.deleteMany,
      ).toHaveBeenCalledTimes(1);
      expect(
        mockPrismaService.passwordResetToken.deleteMany,
      ).toHaveBeenCalledTimes(1);
    });
  });
});
