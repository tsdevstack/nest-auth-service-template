/**
 * Prisma configuration
 * https://www.prisma.io/docs/orm/reference/prisma-schema-reference#config-files
 */

require('dotenv').config();
const { defineConfig } = require('prisma/config');

module.exports = defineConfig({
  datasource: {
    url: process.env.DATABASE_URL,
  },
  migrations: {
    seed: 'ts-node --compiler-options {"module":"CommonJS"} prisma/seed.ts',
  },
});