import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { AuthenticatedRequest } from '@tsdevstack/nest-common';
import { PrismaService } from '../prisma/prisma.service';
import { SystemRole, UserStatus } from '../generated/prisma/enums';

/**
 * Re-checks in the database that the caller is still an active admin.
 *
 * `@Roles('ADMIN')` trusts the role in the JWT, which stays valid until the
 * token expires even if the user was demoted meanwhile. Admin endpoints use
 * both: `@Roles('ADMIN')` rejects early, this guard reads the current state.
 */
@Injectable()
export class ActiveAdminGuard implements CanActivate {
  constructor(private readonly prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const userId = request.authType === 'user' ? request.user?.id : undefined;

    if (!userId) {
      throw new ForbiddenException('Admin access required');
    }

    const caller = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { systemRole: true, status: true },
    });

    if (
      !caller ||
      caller.systemRole !== SystemRole.ADMIN ||
      caller.status !== UserStatus.ACTIVE
    ) {
      throw new ForbiddenException('Admin access required');
    }

    return true;
  }
}
