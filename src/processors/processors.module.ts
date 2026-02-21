import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { NotificationProcessor } from './notification.processor';
import { NotificationModule } from '@tsdevstack/nest-common';

/**
 * ProcessorsModule
 *
 * Contains BullMQ processors for async job handling.
 * Processors run embedded in the main service.
 */
@Module({
  imports: [
    BullModule.registerQueue({ name: 'notifications' }),
    NotificationModule,
  ],
  providers: [NotificationProcessor],
  exports: [BullModule],
})
export class ProcessorsModule {}
