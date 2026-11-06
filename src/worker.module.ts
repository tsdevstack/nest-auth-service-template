import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { BullModule } from '@nestjs/bullmq';
import {
  BullConfigModule,
  SecretsModule,
  NotificationModule,
  ObservabilityModule,
} from '@tsdevstack/nest-common';
import { NotificationProcessor } from './processors/notification.processor';

/**
 * WorkerModule
 *
 * Queue processors run here, in the worker (always on), not in the service.
 * The service adds jobs to the queues; the worker processes them.
 */
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    SecretsModule,
    ObservabilityModule.forRoot(),
    NotificationModule,
    BullConfigModule.forRoot(),
    BullModule.registerQueue({ name: 'notifications' }),
  ],
  providers: [NotificationProcessor],
})
export class WorkerModule {}
