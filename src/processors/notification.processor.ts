import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { NotificationService } from '@tsdevstack/nest-common';

interface EmailJobData {
  to: string;
  subject: string;
  html: string;
}

/**
 * NotificationProcessor
 *
 * Processes async notification jobs from the 'notifications' queue.
 * Uses WorkerHost pattern (BullMQ) with switch/case for job types.
 */
@Processor('notifications')
export class NotificationProcessor extends WorkerHost {
  private readonly logger = new Logger(NotificationProcessor.name);

  constructor(private readonly notifications: NotificationService) {
    super();
  }

  async process(job: Job<EmailJobData>): Promise<void> {
    this.logger.log(`Processing ${job.name} job ${job.id}`);

    switch (job.name) {
      case 'welcome-email':
      case 'confirmation-email':
      case 'password-reset':
      default:
        await this.notifications.sendEmail(job.data);
    }
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job): void {
    this.logger.log(`Job ${job.id} completed`);
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job | undefined, error: Error): void {
    this.logger.error(`Job ${job?.id} failed: ${error.message}`);

    if (job && job.attemptsMade >= (job.opts.attempts ?? 3)) {
      this.logger.error(
        `Job ${job.id} permanently failed after ${job.attemptsMade} attempts`,
      );
    }
  }
}
