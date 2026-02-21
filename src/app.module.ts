import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR, APP_GUARD } from '@nestjs/core';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { JobsModule } from './jobs/jobs.module';
import {
  RateLimitHeadersInterceptor,
  RedisModule,
  RateLimitModule,
  EmailRateLimitModule,
  SecretsModule,
  AuthModule as CommonAuthModule,
  AuthGuard,
  ObservabilityModule,
  NotificationModule,
  BullConfigModule,
} from '@tsdevstack/nest-common';
import { PrismaModule } from './prisma/prisma.module';
import { ProcessorsModule } from './processors/processors.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    SecretsModule,
    ObservabilityModule,
    CommonAuthModule,
    PrismaModule,
    RedisModule,
    UserModule,
    AuthModule,
    RateLimitModule,
    EmailRateLimitModule,
    NotificationModule,
    BullConfigModule.forRoot(),
    ProcessorsModule,
    JobsModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: RateLimitHeadersInterceptor,
    },
  ],
})
export class AppModule {}
