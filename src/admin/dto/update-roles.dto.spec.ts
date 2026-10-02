import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { UpdateRolesDto } from './update-roles.dto';

describe('UpdateRolesDto', () => {
  async function errorsFor(body: unknown): Promise<number> {
    return (await validate(plainToInstance(UpdateRolesDto, body))).length;
  }

  it('should accept a list of strings, including an empty list', async () => {
    expect(await errorsFor({ roles: ['EDITOR', 'BILLING'] })).toBe(0);
    expect(await errorsFor({ roles: [] })).toBe(0);
  });

  it('should reject a value that is not an array', async () => {
    expect(await errorsFor({ roles: 'EDITOR' })).toBe(1);
    expect(await errorsFor({})).toBe(1);
  });

  it('should reject non-string items', async () => {
    expect(await errorsFor({ roles: ['EDITOR', 42] })).toBe(1);
    expect(await errorsFor({ roles: [{ name: 'EDITOR' }] })).toBe(1);
  });
});
