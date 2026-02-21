import { Test, TestingModule } from '@nestjs/testing';
import { NotificationProcessor } from './notification.processor';
import { NotificationService } from '@tsdevstack/nest-common';
import type { Job } from 'bullmq';

interface EmailJobData {
  to: string;
  subject: string;
  html: string;
}

function createMockJob(
  overrides: Partial<Job<EmailJobData>> & { data: EmailJobData },
): Job<EmailJobData> {
  return {
    id: 'job-1',
    name: 'test',
    ...overrides,
  } as unknown as Job<EmailJobData>;
}

describe('NotificationProcessor', () => {
  let processor: NotificationProcessor;
  let mockNotificationService: { sendEmail: jest.Mock };

  beforeEach(async () => {
    mockNotificationService = {
      sendEmail: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NotificationProcessor,
        {
          provide: NotificationService,
          useValue: mockNotificationService,
        },
      ],
    }).compile();

    processor = module.get<NotificationProcessor>(NotificationProcessor);
  });

  it('should be defined', () => {
    expect(processor).toBeDefined();
  });

  describe('process', () => {
    const mockJobData: EmailJobData = {
      to: 'user@example.com',
      subject: 'Test Subject',
      html: '<p>Test email</p>',
    };

    it('should send email with job data for confirmation-email', async () => {
      const job = createMockJob({
        id: 'job-1',
        name: 'confirmation-email',
        data: mockJobData,
      });

      await processor.process(job);

      expect(mockNotificationService.sendEmail).toHaveBeenCalledWith(
        mockJobData,
      );
    });

    it('should send email with job data for password-reset', async () => {
      const job = createMockJob({
        id: 'job-2',
        name: 'password-reset',
        data: mockJobData,
      });

      await processor.process(job);

      expect(mockNotificationService.sendEmail).toHaveBeenCalledWith(
        mockJobData,
      );
    });

    it('should send email with job data for welcome-email', async () => {
      const job = createMockJob({
        id: 'job-3',
        name: 'welcome-email',
        data: mockJobData,
      });

      await processor.process(job);

      expect(mockNotificationService.sendEmail).toHaveBeenCalledWith(
        mockJobData,
      );
    });

    it('should handle unknown job names via default case', async () => {
      const job = createMockJob({
        id: 'job-4',
        name: 'unknown-type',
        data: mockJobData,
      });

      await processor.process(job);

      expect(mockNotificationService.sendEmail).toHaveBeenCalledWith(
        mockJobData,
      );
    });
  });

  describe('onCompleted', () => {
    it('should log job completion', () => {
      const job = { id: 'job-1' } as Job;

      expect(() => processor.onCompleted(job)).not.toThrow();
    });
  });

  describe('onFailed', () => {
    it('should log job failure', () => {
      const job = {
        id: 'job-1',
        attemptsMade: 1,
        opts: { attempts: 3 },
      } as unknown as Job;
      const error = new Error('Send failed');

      expect(() => processor.onFailed(job, error)).not.toThrow();
    });

    it('should log permanent failure when attempts exhausted', () => {
      const job = {
        id: 'job-1',
        attemptsMade: 3,
        opts: { attempts: 3 },
      } as unknown as Job;
      const error = new Error('Send failed');

      expect(() => processor.onFailed(job, error)).not.toThrow();
    });

    it('should handle undefined job', () => {
      const error = new Error('Send failed');

      expect(() => processor.onFailed(undefined, error)).not.toThrow();
    });
  });
});
