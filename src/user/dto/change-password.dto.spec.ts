import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { ChangePasswordDto } from './change-password.dto';

describe('ChangePasswordDto', () => {
  async function failedProperties(body: unknown): Promise<string[]> {
    const dto = plainToInstance(ChangePasswordDto, body);
    return (await validate(dto)).map((error) => error.property);
  }

  it('should accept a valid current and new password', async () => {
    expect(
      await failedProperties({
        currentPassword: 'anything',
        newPassword: 'NewPass123',
      }),
    ).toEqual([]);
  });

  it('should apply the signup password rules to the new password', async () => {
    for (const newPassword of [
      'Short1',
      'nouppercase1',
      'NOLOWERCASE1',
      'NoNumbers',
    ]) {
      expect(
        await failedProperties({ currentPassword: 'anything', newPassword }),
      ).toEqual(['newPassword']);
    }
  });

  it('should require the current password', async () => {
    expect(
      await failedProperties({
        currentPassword: '',
        newPassword: 'NewPass123',
      }),
    ).toEqual(['currentPassword']);
  });
});
