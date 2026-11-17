import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { UserAuthDTO, RegisterUserDTO } from './register-user.dto';

describe('UserAuthDTO', () => {
  it('should pass validation with a valid email and password', async () => {
    const dto = plainToInstance(UserAuthDTO, {
      email: 'user@example.com',
      password: 'Pass1234!',
    });

    const errors = await validate(dto);

    expect(errors).toHaveLength(0);
  });

  it('should pass validation without a password (Google-only login)', async () => {
    const dto = plainToInstance(UserAuthDTO, { email: 'user@example.com' });

    const errors = await validate(dto);

    expect(errors).toHaveLength(0);
  });

  it('should fail validation when the password is shorter than 8 characters', async () => {
    const dto = plainToInstance(UserAuthDTO, {
      email: 'user@example.com',
      password: 'short',
    });

    const errors = await validate(dto);

    expect(errors.some((e) => e.property === 'password')).toBe(true);
  });

  it('should fail validation when the password is longer than 72 characters (bcrypt truncation guard)', async () => {
    const dto = plainToInstance(UserAuthDTO, {
      email: 'user@example.com',
      password: 'a'.repeat(73),
    });

    const errors = await validate(dto);

    expect(errors.some((e) => e.property === 'password')).toBe(true);
  });

  it('should accept a password exactly at the 72 character boundary', async () => {
    const dto = plainToInstance(UserAuthDTO, {
      email: 'user@example.com',
      password: 'a'.repeat(72),
    });

    const errors = await validate(dto);

    expect(errors).toHaveLength(0);
  });

  it('should fail validation with an invalid email', async () => {
    const dto = plainToInstance(UserAuthDTO, {
      email: 'not-an-email',
      password: 'Pass1234!',
    });

    const errors = await validate(dto);

    expect(errors.some((e) => e.property === 'email')).toBe(true);
  });
});

describe('RegisterUserDTO', () => {
  it('should pass validation with a valid email and password', async () => {
    const dto = plainToInstance(RegisterUserDTO, {
      email: 'user@example.com',
      password: 'Pass1234!',
    });

    const errors = await validate(dto);

    expect(errors).toHaveLength(0);
  });

  it('should fail validation when password is missing (registration requires a password)', async () => {
    const dto = plainToInstance(RegisterUserDTO, { email: 'user@example.com' });

    const errors = await validate(dto);

    expect(errors.some((e) => e.property === 'password')).toBe(true);
  });

  it('should fail validation when the password is shorter than 8 characters', async () => {
    const dto = plainToInstance(RegisterUserDTO, {
      email: 'user@example.com',
      password: 'short',
    });

    const errors = await validate(dto);

    expect(errors.some((e) => e.property === 'password')).toBe(true);
  });

  it('should fail validation when the password is longer than 72 characters', async () => {
    const dto = plainToInstance(RegisterUserDTO, {
      email: 'user@example.com',
      password: 'a'.repeat(73),
    });

    const errors = await validate(dto);

    expect(errors.some((e) => e.property === 'password')).toBe(true);
  });
});

describe('normalizzazione email nei DTO (B2)', () => {
  it.each([
    ['UserAuthDTO', UserAuthDTO, { password: 'Pass1234!' }],
    ['RegisterUserDTO', RegisterUserDTO, { password: 'Pass1234!' }],
  ])(
    '%s: trim + minuscolo prima della validazione',
    async (_name, Dto, extra) => {
      const dto = plainToInstance(Dto, {
        email: '  Mario.Rossi@Example.COM ',
        ...extra,
      });

      expect(dto.email).toBe('mario.rossi@example.com');
      expect(await validate(dto)).toHaveLength(0);
    },
  );

  it('un valore non stringa non viene toccato e fallisce la validazione come prima', async () => {
    const dto = plainToInstance(RegisterUserDTO, {
      email: 12345,
      password: 'Pass1234!',
    });

    expect(dto.email).toBe(12345);
    expect((await validate(dto)).some((e) => e.property === 'email')).toBe(
      true,
    );
  });

  it('spazi interni restano un errore (non vengono "aggiustati")', async () => {
    const dto = plainToInstance(RegisterUserDTO, {
      email: 'ma rio@example.com',
      password: 'Pass1234!',
    });

    expect((await validate(dto)).some((e) => e.property === 'email')).toBe(
      true,
    );
  });
});

describe('password: limite di 72 byte (bcrypt)', () => {
  // 25 caratteri da 3 byte = 75 byte: passerebbe MaxLength(72) ma bcrypt ne ignorerebbe 3.
  const multibyte = '€'.repeat(25);

  // Il login non lo applica: chi ha gia' una password multibyte lunga deve poter entrare
  // (bcrypt la tronca allo stesso modo di quando fu creata).
  it('registrazione: rifiuta una password oltre 72 byte anche se ha meno di 72 caratteri', async () => {
    const dto = plainToInstance(RegisterUserDTO, {
      email: 'user@example.com',
      password: multibyte,
    });

    const errors = await validate(dto);

    expect(errors.some((e) => e.property === 'password')).toBe(true);
  });

  it('login: non cambia, accetta la stessa password', async () => {
    const dto = plainToInstance(UserAuthDTO, {
      email: 'user@example.com',
      password: multibyte,
    });

    expect(await validate(dto)).toHaveLength(0);
  });

  it('accetta 24 caratteri da 3 byte (72 byte esatti)', async () => {
    const dto = plainToInstance(RegisterUserDTO, {
      email: 'user@example.com',
      password: '€'.repeat(24),
    });

    expect(await validate(dto)).toHaveLength(0);
  });
});
