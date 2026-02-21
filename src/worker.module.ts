import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { BullModule } from '@nestjs/bullmq';
import {
  BullConfigModule,
  SecretsModule,
  NotificationModule,
  ObservabilityModule,
} from '@tsdevstack/nest-common';
import { WelcomeProcessor } from './processors/welcome.processor';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    SecretsModule,
    ObservabilityModule.forRoot({ serviceName: 'auth-service' }),
    NotificationModule,
    BullConfigModule.forRoot(),
    BullModule.registerQueue({ name: 'welcome' }),
  ],
  providers: [WelcomeProcessor],
})
export class WorkerModule {}
