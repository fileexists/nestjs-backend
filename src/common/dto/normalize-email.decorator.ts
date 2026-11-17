import { Transform } from 'class-transformer';
import { normalizeEmail } from '../utils/email';

/**
 * Normalizza (trim + minuscolo) PRIMA della validazione: ValidationPipe esegue
 * la trasformazione prima di class-validator, quindi `@IsEmail()` e il resto
 * del codice vedono sempre la forma canonica.
 */
export const NormalizeEmail = (): PropertyDecorator =>
  Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? normalizeEmail(value) : value,
  );
