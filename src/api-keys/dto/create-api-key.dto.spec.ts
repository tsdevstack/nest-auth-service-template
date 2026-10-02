import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { CreateApiKeyDto } from './create-api-key.dto';

describe('CreateApiKeyDto', () => {
  async function errors(body: unknown): Promise<string[]> {
    const result = await validate(plainToInstance(CreateApiKeyDto, body));
    return result.map((error) => error.property);
  }

  it('should accept a minimal and a full body', async () => {
    expect(await errors({ name: 'n', consumer: 'acme-corp' })).toEqual([]);
    expect(
      await errors({
        name: 'n',
        consumer: 'acme-corp',
        limitPerMinute: 1,
        limitPerHour: 2,
        limitPerDay: 3,
        limitPerWeek: 4,
        limitPerMonth: 2_147_483_647,
        expiresAt: '2026-12-31T23:59:59Z',
      }),
    ).toEqual([]);
  });

  it('should validate the consumer name', async () => {
    expect(await errors({ name: 'n', consumer: 'Acme' })).toEqual(['consumer']);
    expect(await errors({ name: 'n', consumer: 'partner' })).toEqual([
      'consumer',
    ]);
    expect(await errors({ name: 'n', consumer: 'auth-service' })).toEqual([
      'consumer',
    ]);
    expect(await errors({ name: 'n' })).toEqual(['consumer']);
  });

  it('should explain a rejected consumer name', async () => {
    const [error] = await validate(
      plainToInstance(CreateApiKeyDto, { name: 'n', consumer: 'internal' }),
    );
    expect(Object.values(error.constraints ?? {})).toEqual([
      'consumer must not be internal or partner',
    ]);
  });

  it('should reject empty names, bad limits and bad dates', async () => {
    expect(await errors({ name: '', consumer: 'a' })).toEqual(['name']);
    expect(
      await errors({ name: 'n', consumer: 'a', limitPerMinute: 0 }),
    ).toEqual(['limitPerMinute']);
    expect(
      await errors({ name: 'n', consumer: 'a', limitPerDay: 1.5 }),
    ).toEqual(['limitPerDay']);
    expect(
      await errors({ name: 'n', consumer: 'a', limitPerMonth: 2_147_483_648 }),
    ).toEqual(['limitPerMonth']);
    expect(
      await errors({ name: 'n', consumer: 'a', expiresAt: 'soon' }),
    ).toEqual(['expiresAt']);
  });

  it('should require Z or an explicit offset on the expiry', async () => {
    const withExpiry = (expiresAt: string): Promise<string[]> =>
      errors({ name: 'n', consumer: 'a', expiresAt });
    expect(await withExpiry('2026-12-31T23:59:59Z')).toEqual([]);
    expect(await withExpiry('2026-12-31T23:59:59+02:00')).toEqual([]);
    expect(await withExpiry('2026-12-31T23:59:59.123-0500')).toEqual([]);
    expect(await withExpiry('2026-12-31T23:59:59')).toEqual(['expiresAt']);
    expect(await withExpiry('2026-12-31')).toEqual(['expiresAt']);
    expect(await withExpiry('2026-02-30T00:00:00Z')).toEqual(['expiresAt']);
  });
});
