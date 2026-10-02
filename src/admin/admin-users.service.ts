import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { LoggerService } from '@tsdevstack/nest-common';
import { PrismaService } from '../prisma/prisma.service';
import { UserDto } from '../user/dto/user.dto';
import { CUSTOM_ROLES } from '../roles/roles.constants';
import { SystemRole } from '../generated/prisma/enums';

/**
 * User lookup and role management for admins.
 *
 * Role changes are written to the database only; they reach the user's JWT
 * at the next token refresh (or login).
 */
@Injectable()
export class AdminUsersService {
  private readonly logger: LoggerService;

  constructor(
    private readonly prisma: PrismaService,
    logger: LoggerService,
  ) {
    this.logger = logger.child('AdminUsersService');
  }

  async findByEmail(email: string): Promise<UserDto> {
    // Emails are unique as stored, but not case-insensitively: two accounts
    // can differ only in case. Never pick one of them silently.
    const users = await this.prisma.user.findMany({
      where: { email: { equals: email.trim(), mode: 'insensitive' } },
      take: 2,
    });

    if (users.length === 0) {
      throw new NotFoundException('User not found');
    }

    if (users.length > 1) {
      throw new ConflictException(
        'Several users have this email with different letter case; the lookup cannot pick one',
      );
    }

    const [user] = users;

    const { passwordHash: _passwordHash, ...result } = user;
    return result;
  }

  async updateSystemRole(
    actorId: string,
    userId: string,
    systemRole: SystemRole,
  ): Promise<UserDto> {
    await this.ensureUserExists(userId);

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { systemRole },
    });

    this.logger.info('System role changed', { actorId, userId, systemRole });

    const { passwordHash: _passwordHash, ...result } = user;
    return result;
  }

  async updateRoles(
    actorId: string,
    userId: string,
    roles: string[],
  ): Promise<UserDto> {
    const uniqueRoles = Array.from(new Set(roles));
    this.validateCustomRoles(uniqueRoles);

    await this.ensureUserExists(userId);

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { roles: uniqueRoles },
    });

    this.logger.info('Custom roles changed', {
      actorId,
      userId,
      roles: uniqueRoles.join(','),
    });

    const { passwordHash: _passwordHash, ...result } = user;
    return result;
  }

  /**
   * Custom roles must be declared in roles.constants.ts and must not reuse a
   * system role name (`@Roles('ADMIN')` would match a custom `ADMIN`).
   */
  private validateCustomRoles(roles: string[]): void {
    const systemRoles = Object.values(SystemRole) as string[];
    const reserved = roles.filter((role) => systemRoles.includes(role));
    if (reserved.length > 0) {
      throw new BadRequestException(
        `System roles cannot be custom roles: ${reserved.join(', ')}. Use PUT /v1/admin/users/:id/system-role instead.`,
      );
    }

    const undeclared = roles.filter((role) => !CUSTOM_ROLES.includes(role));
    if (undeclared.length > 0) {
      throw new BadRequestException(
        `Undeclared custom roles: ${undeclared.join(', ')}. Declare them in src/roles/roles.constants.ts.`,
      );
    }
  }

  private async ensureUserExists(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
  }
}
