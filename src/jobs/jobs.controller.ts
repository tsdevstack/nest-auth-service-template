import { Controller, Post, UseGuards, Logger } from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { SchedulerGuard, Public } from '@tsdevstack/nest-common';
import { JobsService } from './jobs.service';
import { ApiKeyUsageService } from '../api-keys/api-key-usage.service';
import type { ApiKeyUsageSyncResult } from '../api-keys/api-keys.types';

/**
 * Jobs controller for scheduled tasks.
 * @ApiExcludeController() ensures these routes are NOT exposed via Kong gateway.
 * Cloud Scheduler calls these endpoints directly via Cloud Run URL.
 * SchedulerGuard validates OIDC tokens in production, skips in development.
 */
@ApiExcludeController()
@Controller('jobs')
export class JobsController {
  private readonly logger = new Logger(JobsController.name);

  constructor(
    private readonly jobsService: JobsService,
    private readonly apiKeyUsageService: ApiKeyUsageService,
  ) {}

  @Post('cleanup-tokens')
  @Public()
  @UseGuards(SchedulerGuard)
  async cleanupTokens(): Promise<{
    success: boolean;
    deleted: { refresh: number; confirmation: number; passwordReset: number };
  }> {
    return this.jobsService.cleanupTokens();
  }

  /**
   * Copies API key week and month totals and last-used times from Redis to
   * Postgres, and rebuilds the Redis key index first when it is missing.
   * Scheduled every few minutes in the cloud; call it by hand locally.
   */
  @Post('sync-api-key-usage')
  @Public()
  @UseGuards(SchedulerGuard)
  async syncApiKeyUsage(): Promise<ApiKeyUsageSyncResult> {
    return this.apiKeyUsageService.sync();
  }

  @Post('test-job')
  @Public()
  @UseGuards(SchedulerGuard)
  testJob(): { success: boolean; message: string } {
    this.logger.log('Running test job');
    return { success: true, message: 'Test job completed' };
  }
}
