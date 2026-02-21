import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { NotificationService } from '@tsdevstack/nest-common';

interface WelcomeEmailJobData {
  to: string;
  firstName: string;
}

@Processor('welcome')
export class WelcomeProcessor extends WorkerHost {
  private readonly logger = new Logger(WelcomeProcessor.name);

  constructor(private readonly notifications: NotificationService) {
    super();
  }

  async process(job: Job<WelcomeEmailJobData>): Promise<void> {
    this.logger.log(`Processing ${job.name} job ${job.id}`);

    const { to, firstName } = job.data;

    await this.notifications.sendEmail({
      to,
      subject: 'Welcome to Curated Sound!',
      html: `
        <h1>Welcome, ${firstName}!</h1>
        <p>Your email has been verified. You now have full access to Curated Sound.</p>
        <p>Get started by exploring our features.</p>
      `,
    });
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job): void {
    this.logger.log(`Job ${job.id} completed`);
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job | undefined, error: Error): void {
    this.logger.error(`Job ${job?.id} failed: ${error.message}`);
  }
}
