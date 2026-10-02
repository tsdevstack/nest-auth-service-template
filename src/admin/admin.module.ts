import { Module } from '@nestjs/common';
import { AdminUsersController } from './admin-users.controller';
import { AdminUsersService } from './admin-users.service';
import { ActiveAdminGuard } from './active-admin.guard';

@Module({
  providers: [AdminUsersService, ActiveAdminGuard],
  controllers: [AdminUsersController],
  exports: [ActiveAdminGuard],
})
export class AdminModule {}
