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
 *
 * Sending an email waits on Resend's API, not the CPU, so the worker sends
 * up to 5 at once (with one at a time its CPU stays idle and CPU scaling
 * never adds a worker). The limiter holds the whole queue, across every
 * worker, to Resend's default limit of 10 requests per second per team;
 * jobs over it wait in the queue.
 */
@Processor('notifications', {
  concurrency: 5,
  limiter: { max: 10, duration: 1000 },
})
export class NotificationProcessor extends WorkerHost {
  private readonly logger = new Logger(NotificationProcessor.name);

  constructor(private readonly notifications: NotificationService) {
    super();
  }

  async process(job: Job<EmailJobData>): Promise<void> {
    this.logger.log(`Processing ${job.name} job ${job.id}`);

    switch (job.name) {
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
