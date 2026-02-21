import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { createPrismaConnection } from '@tsdevstack/nest-common';
import { PrismaClient } from '../generated/prisma/client';
import type { Pool } from 'pg';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor() {
    const { config, pool } = createPrismaConnection();
    super(config);
    this.pool = pool;
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
    await this.pool.end();
  }
}
