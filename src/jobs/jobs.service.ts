import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class JobsService {
  private readonly logger = new Logger(JobsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async cleanupTokens(): Promise<{
    success: boolean;
    deleted: { refresh: number; confirmation: number; passwordReset: number };
  }> {
    this.logger.log('Running cleanup-tokens job');
    const now = new Date();

    const [refresh, confirmation, passwordReset] = await Promise.all([
      this.prisma.refreshToken.deleteMany({
        where: { expiresAt: { lt: now } },
      }),
      this.prisma.confirmationToken.deleteMany({
        where: { expiresAt: { lt: now } },
      }),
      this.prisma.passwordResetToken.deleteMany({
        where: { expiresAt: { lt: now } },
      }),
    ]);

    const total = refresh.count + confirmation.count + passwordReset.count;
    this.logger.log(
      `Cleaned up ${total} expired tokens (refresh: ${refresh.count}, confirmation: ${confirmation.count}, passwordReset: ${passwordReset.count})`,
    );

    return {
      success: true,
      deleted: {
        refresh: refresh.count,
        confirmation: confirmation.count,
        passwordReset: passwordReset.count,
      },
    };
  }
}
