import { Test, TestingModule } from '@nestjs/testing';
import { JobsController } from './jobs.controller';
import { JobsService } from './jobs.service';
import { SchedulerGuard } from '@tsdevstack/nest-common';

describe('JobsController', () => {
  let controller: JobsController;
  let mockJobsService: { cleanupTokens: jest.Mock };

  const mockGuard = { canActivate: () => true };

  beforeEach(async () => {
    mockJobsService = {
      cleanupTokens: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [JobsController],
      providers: [{ provide: JobsService, useValue: mockJobsService }],
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
