import { getConsumerNameError } from './get-consumer-name-error';

describe('getConsumerNameError', () => {
  it.each(['acme-corp', 'acme', 'a1', 'big-partner-2', 'x'])(
    'should accept %s',
    (name) => {
      expect(getConsumerNameError(name)).toBeNull();
    },
  );

  it.each([
    ['', /required/],
    ['Acme', /kebab-case/],
    ['acme_corp', /kebab-case/],
    ['acme--corp', /kebab-case/],
    ['-acme', /kebab-case/],
    ['acme-', /kebab-case/],
    ['1acme', /kebab-case/],
    ['acme corp', /kebab-case/],
    ['internal', /must not be internal or partner/],
    ['partner', /must not be internal or partner/],
    ['auth-service', /service name/],
    ['billing-service', /service name/],
    ['a'.repeat(65), /at most 64/],
  ])('should reject %j', (name, message) => {
    expect(getConsumerNameError(name)).toMatch(message);
  });

  it('should reject non-strings', () => {
    expect(getConsumerNameError(undefined)).toMatch(/required/);
    expect(getConsumerNameError(42)).toMatch(/required/);
  });
});
