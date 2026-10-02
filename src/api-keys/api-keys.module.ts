import { Module } from '@nestjs/common';
import { AdminModule } from '../admin/admin.module';
import { AdminApiKeysController } from './admin-api-keys.controller';
import { ApiKeyIndexService } from './api-key-index.service';
import { ApiKeyUsageService } from './api-key-usage.service';
import { ApiKeysService } from './api-keys.service';

@Module({
  imports: [AdminModule],
  providers: [ApiKeysService, ApiKeyIndexService, ApiKeyUsageService],
  controllers: [AdminApiKeysController],
  exports: [ApiKeyUsageService],
})
export class ApiKeysModule {}
