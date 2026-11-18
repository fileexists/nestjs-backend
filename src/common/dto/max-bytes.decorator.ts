import { ValidateBy, ValidationOptions } from 'class-validator';

/**
 * Maximum length in BYTES (UTF-8). bcrypt only considers the first 72 bytes: with
 * multibyte characters `MaxLength(72)` is not enough and the part beyond the limit would be ignored.
 */
export function MaxBytes(
  max: number,
  options?: ValidationOptions,
): PropertyDecorator {
  return ValidateBy(
    {
      name: 'maxBytes',
      constraints: [max],
      validator: {
        validate: (value: unknown) =>
          typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= max,
        defaultMessage: (args) =>
          `${args?.property ?? 'value'} must be at most ${max} bytes`,
      },
    },
    options,
  );
}
