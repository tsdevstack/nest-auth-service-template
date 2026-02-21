import { Test, TestingModule } from '@nestjs/testing';
import { WelcomeProcessor } from './welcome.processor';
import { NotificationService } from '@tsdevstack/nest-common';
import type { Job } from 'bullmq';

interface WelcomeEmailJobData {
  to: string;
  firstName: string;
}

function createMockJob(
  overrides: Partial<Job<WelcomeEmailJobData>> & { data: WelcomeEmailJobData },
): Job<WelcomeEmailJobData> {
  return {
    id: 'job-1',
    name: 'welcome-email',
    ...overrides,
  } as unknown as Job<WelcomeEmailJobData>;
}

describe('WelcomeProcessor', () => {
  let processor: WelcomeProcessor;
  let mockNotificationService: { sendEmail: jest.Mock };

  beforeEach(async () => {
    mockNotificationService = {
      sendEmail: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WelcomeProcessor,
        {
          provide: NotificationService,
          useValue: mockNotificationService,
        },
      ],
    }).compile();

    processor = module.get<WelcomeProcessor>(WelcomeProcessor);
  });

  it('should be defined', () => {
    expect(processor).toBeDefined();
  });

  describe('process', () => {
    it('should send welcome email with correct data', async () => {
      const job = createMockJob({
        data: {
          to: 'user@example.com',
          firstName: 'John',
        },
      });

      await processor.process(job);

      expect(mockNotificationService.sendEmail).toHaveBeenCalledWith({
        to: 'user@example.com',
        subject: 'Welcome to Curated Sound!',
        html: expect.stringContaining('Welcome, John!') as string,
      });
    });

    it('should include firstName in the email HTML', async () => {
      const job = createMockJob({
        data: {
          to: 'jane@example.com',
          firstName: 'Jane',
        },
      });

      await processor.process(job);

      const calls = mockNotificationService.sendEmail.mock.calls as Array<
        [{ to: string; subject: string; html: string }]
      >;
      expect(calls[0][0].html).toContain('Jane');
    });
  });

  describe('onCompleted', () => {
    it('should log job completion', () => {
      const job = { id: 'job-1' } as unknown as Job;

      expect(() => processor.onCompleted(job)).not.toThrow();
    });
  });

  describe('onFailed', () => {
    it('should log job failure', () => {
      const job = { id: 'job-1' } as unknown as Job;
      const error = new Error('Send failed');

      expect(() => processor.onFailed(job, error)).not.toThrow();
    });

    it('should handle undefined job', () => {
      const error = new Error('Send failed');

      expect(() => processor.onFailed(undefined, error)).not.toThrow();
    });
  });
});
