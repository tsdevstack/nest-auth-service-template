import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { UpdateApiKeyDto } from './update-api-key.dto';

describe('UpdateApiKeyDto', () => {
  async function errors(body: unknown): Promise<string[]> {
    const result = await validate(plainToInstance(UpdateApiKeyDto, body));
    return result.map((error) => error.property);
  }

  it('should accept an empty body, values and nulls', async () => {
    expect(await errors({})).toEqual([]);
    expect(
      await errors({
        name: 'x',
        limitPerHour: 5,
        limitPerDay: null,
        expiresAt: null,
      }),
    ).toEqual([]);
    expect(await errors({ expiresAt: '2027-01-01T00:00:00Z' })).toEqual([]);
  });

  it('should reject a null or empty name and bad limits', async () => {
    expect(await errors({ name: null })).toEqual(['name']);
    expect(await errors({ name: '' })).toEqual(['name']);
    expect(await errors({ limitPerWeek: -1 })).toEqual(['limitPerWeek']);
    expect(await errors({ expiresAt: 'tomorrow' })).toEqual(['expiresAt']);
    expect(await errors({ expiresAt: '2027-01-01T00:00:00' })).toEqual([
      'expiresAt',
    ]);
  });
});
