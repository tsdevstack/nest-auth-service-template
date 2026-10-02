import { ApiProperty } from '@nestjs/swagger';

/** An API key as admins see it. Never contains the key itself. */
export class ApiKeyDto {
  @ApiProperty({
    description: 'Key identifier (X-Api-Key-Id at the backends)',
    example: 'c0a8f1d2-5b6e-4f3a-9d7c-1e2f3a4b5c6d',
    type: String,
  })
  id: string;

  @ApiProperty({
    description: 'Label for admins',
    example: 'Production integration',
    type: String,
  })
  name: string;

  @ApiProperty({
    description: 'First 12 characters of the key, to recognize it',
    example: 'tsk_Qm9vZ3Jh',
    type: String,
  })
  prefix: string;

  @ApiProperty({
    description: 'Who the key is for (X-Api-Key-Consumer at the backends)',
    example: 'acme-corp',
    type: String,
  })
  consumer: string;

  @ApiProperty({
    description: "Requests per minute; null uses the gateway's global default",
    example: 60,
    nullable: true,
    type: Number,
  })
  limitPerMinute: number | null;

  @ApiProperty({
    description: "Requests per hour; null uses the gateway's global default",
    example: null,
    nullable: true,
    type: Number,
  })
  limitPerHour: number | null;

  @ApiProperty({
    description: "Requests per day; null uses the gateway's global default",
    example: null,
    nullable: true,
    type: Number,
  })
  limitPerDay: number | null;

  @ApiProperty({
    description:
      "Requests per ISO week; null uses the gateway's global default",
    example: null,
    nullable: true,
    type: Number,
  })
  limitPerWeek: number | null;

  @ApiProperty({
    description:
      "Requests per calendar month; null uses the gateway's global default",
    example: 100000,
    nullable: true,
    type: Number,
  })
  limitPerMonth: number | null;

  @ApiProperty({
    description: 'ACTIVE or REVOKED (an active key can still be expired)',
    example: 'ACTIVE',
    enum: ['ACTIVE', 'REVOKED'],
    type: String,
  })
  status: 'ACTIVE' | 'REVOKED';

  @ApiProperty({
    description: 'Whether expiresAt has passed',
    example: false,
    type: Boolean,
  })
  expired: boolean;

  @ApiProperty({
    description: 'When the key stops working; null for no expiry',
    example: '2026-12-31T23:59:59Z',
    nullable: true,
    type: Date,
  })
  expiresAt: Date | null;

  @ApiProperty({
    description:
      'Last use seen by the usage sync job (updated every few minutes; never locally unless the job is called)',
    example: null,
    nullable: true,
    type: Date,
  })
  lastUsedAt: Date | null;

  @ApiProperty({
    description: 'When the key was revoked',
    example: null,
    nullable: true,
    type: Date,
  })
  revokedAt: Date | null;

  @ApiProperty({
    description: 'Admin who created the key',
    example: 'clx1234567890abcdef',
    type: String,
  })
  createdById: string;

  @ApiProperty({
    description: 'When the key was created',
    example: '2026-09-29T10:30:00Z',
    type: Date,
  })
  createdAt: Date;

  @ApiProperty({
    description: 'When the key was last changed',
    example: '2026-09-29T10:30:00Z',
    type: Date,
  })
  updatedAt: Date;
}
