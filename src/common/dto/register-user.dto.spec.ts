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
