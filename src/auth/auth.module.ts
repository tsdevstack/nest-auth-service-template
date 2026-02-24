import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { BullModule } from '@nestjs/bullmq';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtService } from './jwt.service';
import { JwksController } from './jwks.controller';

@Module({
  imports: [
    ConfigModule,
    BullModule.registerQueue({ name: 'notifications' }),
  ],
  controllers: [AuthController, JwksController],
  providers: [AuthService, JwtService],
  exports: [AuthService, JwtService],
})
export class AuthModule {}
