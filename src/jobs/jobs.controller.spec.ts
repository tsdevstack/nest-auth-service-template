import { Test, TestingModule } from '@nestjs/testing';
import { JobsController } from './jobs.controller';
import { JobsService } from './jobs.service';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { IS_PUBLIC_KEY, SchedulerGuard } from '@tsdevstack/nest-common';
import { ApiKeyUsageService } from '../api-keys/api-key-usage.service';

describe('JobsController', () => {
  let controller: JobsController;
  let mockJobsService: { cleanupTokens: jest.Mock };
  let mockApiKeyUsageService: { sync: jest.Mock };

  const mockGuard = { canActivate: () => true };

  beforeEach(async () => {
    mockJobsService = {
      cleanupTokens: jest.fn(),
    };
    mockApiKeyUsageService = {
      sync: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [JobsController],
      providers: [
        { provide: JobsService, useValue: mockJobsService },
        { provide: ApiKeyUsageService, useValue: mockApiKeyUsageService },
      ],
    })
      .overrideGuard(SchedulerGuard)
      .useValue(mockGuard)
      .compile();

    controller = module.get<JobsController>(JobsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('cleanupTokens', () => {
    it('should delegate to jobsService.cleanupTokens', async () => {
      const expectedResult = {
        success: true,
        deleted: { refresh: 3, confirmation: 2, passwordReset: 1 },
      };
      mockJobsService.cleanupTokens.mockResolvedValue(expectedResult);

      const result = await controller.cleanupTokens();

      expect(result).toEqual(expectedResult);
      expect(mockJobsService.cleanupTokens).toHaveBeenCalledTimes(1);
    });
  });

  describe('syncApiKeyUsage', () => {
    it('should delegate to the API key usage sync', async () => {
      const expectedResult = {
        success: true,
        rebuild: 'present',
        keys: 2,
        periodsUpdated: 3,
        lastUsedUpdated: 1,
      };
      mockApiKeyUsageService.sync.mockResolvedValue(expectedResult);

      await expect(controller.syncApiKeyUsage()).resolves.toEqual(
        expectedResult,
      );
      expect(mockApiKeyUsageService.sync).toHaveBeenCalledTimes(1);
    });

    it('should be public and guarded by SchedulerGuard like the other jobs', () => {
      const handler = Object.getOwnPropertyDescriptor(
        JobsController.prototype,
        'syncApiKeyUsage',
      )?.value as object;
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(GUARDS_METADATA, handler)).toEqual([
        SchedulerGuard,
      ]);
    });
  });

  describe('testJob', () => {
    it('should return success message', () => {
      const result = controller.testJob();

      expect(result).toEqual({
        success: true,
        message: 'Test job completed',
      });
    });
  });
});
