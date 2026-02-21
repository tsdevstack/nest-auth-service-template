import 'dotenv/config';
import { PrismaClient } from '../src/generated/prisma/client';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import * as bcrypt from 'bcrypt';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('Starting seed...');

  // Create a user
  const passwordHash = await bcrypt.hash('test1234', 10);
  await prisma.user.upsert({
    where: { email: 'user@example.com' },
    update: {}, // Don't update anything if exists
    create: {
      email: 'user@example.com',
      passwordHash: passwordHash,
      firstName: 'Test',
      lastName: 'User',
      confirmed: true,
      status: 'ACTIVE',
    },
  });

  console.log('Seed completed!');
}

main()
  .then(async () => {
    await prisma.$disconnect();
    await pool.end();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    await pool.end();
    process.exit(1);
  });
