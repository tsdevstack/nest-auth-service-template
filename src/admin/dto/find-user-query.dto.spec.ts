import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { FindUserQueryDto } from './find-user-query.dto';

describe('FindUserQueryDto', () => {
  async function errorsFor(query: unknown): Promise<number> {
    return (await validate(plainToInstance(FindUserQueryDto, query))).length;
  }

  it('should accept an email address', async () => {
    expect(await errorsFor({ email: 'john@example.com' })).toBe(0);
  });

  it('should reject a missing or invalid email', async () => {
    expect(await errorsFor({})).toBe(1);
    expect(await errorsFor({ email: 'not-an-email' })).toBe(1);
    expect(await errorsFor({ email: '' })).toBe(1);
  });
});
