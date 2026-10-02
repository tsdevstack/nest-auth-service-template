import { Module } from '@nestjs/common';
import { JobsController } from './jobs.controller';
import { JobsService } from './jobs.service';
import { PrismaModule } from '../prisma/prisma.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';

@Module({
  imports: [PrismaModule, ApiKeysModule],
  controllers: [JobsController],
  providers: [JobsService],
})
export class JobsModule {}
