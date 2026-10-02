import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';
import { getConsumerNameError } from '../utils/get-consumer-name-error';

/**
 * class-validator rule for consumer names (see `getConsumerNameError`).
 * Use with `@Validate(ConsumerNameConstraint)`.
 */
@ValidatorConstraint({ name: 'consumerName', async: false })
export class ConsumerNameConstraint implements ValidatorConstraintInterface {
  validate(value: unknown): boolean {
    return getConsumerNameError(value) === null;
  }

  defaultMessage(args: ValidationArguments): string {
    return getConsumerNameError(args.value) ?? 'consumer is invalid';
  }
}
