import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { ListApiKeysQueryDto } from './list-api-keys-query.dto';

describe('ListApiKeysQueryDto', () => {
  async function errors(query: unknown): Promise<number> {
    return (await validate(plainToInstance(ListApiKeysQueryDto, query))).length;
  }

  it('should accept no filter and a kebab-case consumer', async () => {
    expect(await errors({})).toBe(0);
    expect(await errors({ consumer: 'acme-corp' })).toBe(0);
  });

  it('should reject other values', async () => {
    expect(await errors({ consumer: 'Acme Corp' })).toBe(1);
    expect(await errors({ consumer: 'a'.repeat(65) })).toBe(1);
  });
});
