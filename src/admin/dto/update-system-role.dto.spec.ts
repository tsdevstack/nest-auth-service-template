import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { UpdateSystemRoleDto } from './update-system-role.dto';

describe('UpdateSystemRoleDto', () => {
  async function errorsFor(body: unknown): Promise<number> {
    const dto = plainToInstance(UpdateSystemRoleDto, body);
    return (await validate(dto)).length;
  }

  it('should accept USER and ADMIN', async () => {
    expect(await errorsFor({ systemRole: 'USER' })).toBe(0);
    expect(await errorsFor({ systemRole: 'ADMIN' })).toBe(0);
  });

  it('should reject any other value', async () => {
    expect(await errorsFor({ systemRole: 'SUPERADMIN' })).toBe(1);
    expect(await errorsFor({ systemRole: 'admin' })).toBe(1);
    expect(await errorsFor({})).toBe(1);
  });
});
