import type { ValidationArguments } from 'class-validator';
import { ConsumerNameConstraint } from './consumer-name.constraint';

describe('ConsumerNameConstraint', () => {
  const constraint = new ConsumerNameConstraint();

  it('should accept valid names and reject invalid ones', () => {
    expect(constraint.validate('acme-corp')).toBe(true);
    expect(constraint.validate('bff-service')).toBe(false);
  });

  it('should report the reason as the message', () => {
    expect(
      constraint.defaultMessage({ value: 'partner' } as ValidationArguments),
    ).toBe('consumer must not be internal or partner');
  });
});
