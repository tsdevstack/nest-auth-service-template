import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { RotateApiKeyDto } from './rotate-api-key.dto';

describe('RotateApiKeyDto', () => {
  async function errors(body: unknown): Promise<number> {
    return (await validate(plainToInstance(RotateApiKeyDto, body))).length;
  }

  it('should accept no grace, 0 and up to 90 days', async () => {
    expect(await errors({})).toBe(0);
    expect(await errors({ graceHours: 0 })).toBe(0);
    expect(await errors({ graceHours: 2160 })).toBe(0);
  });

  it('should reject negative, fractional and too long graces', async () => {
    expect(await errors({ graceHours: -1 })).toBe(1);
    expect(await errors({ graceHours: 1.5 })).toBe(1);
    expect(await errors({ graceHours: 2161 })).toBe(1);
  });
});
