import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import {
  createPrismaConnection,
  waitForDatabase,
} from '@tsdevstack/nest-common';
import { PrismaClient } from '../generated/prisma/client';
import type { Pool } from 'pg';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly pool: Pool;

  constructor() {
    const { config, pool } = createPrismaConnection();
    super(config);
    this.pool = pool;
  }

  /**
   * Startup gate: the app only starts listening (and passes its platform's
   * startup check) once the database answers
   */
  async onModuleInit(): Promise<void> {
    await waitForDatabase(this.pool);
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
    await this.pool.end();
  }
}
