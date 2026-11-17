import { ValidateBy, ValidationOptions } from 'class-validator';

/**
 * Lunghezza massima in BYTE (UTF-8). bcrypt considera solo i primi 72 byte: con
 * caratteri multibyte `MaxLength(72)` non basta e la parte oltre il limite verrebbe ignorata.
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
