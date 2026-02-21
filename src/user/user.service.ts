import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserDto } from './dto/user.dto';
import { UpdateUserAccountDto } from './dto/update-user-account.dto';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async getUserAccount(userId: string): Promise<UserDto> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const { passwordHash: _passwordHash, ...result } = user;
    return result;
  }

  async updateUserAccount(
    userId: string,
    updateData: UpdateUserAccountDto,
  ): Promise<UserDto> {
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: updateData,
    });

    const { passwordHash: _passwordHash, ...result } = user;
    return result;
  }
}
