import { Transform } from 'class-transformer';
import { normalizeEmail } from '../utils/email';

/**
 * Normalizes (trim + lowercase) BEFORE validation: ValidationPipe runs the
 * transformation before class-validator, so `@IsEmail()` and the rest
 * of the code always see the canonical form.
 */
export const NormalizeEmail = (): PropertyDecorator =>
  Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? normalizeEmail(value) : value,
  );
