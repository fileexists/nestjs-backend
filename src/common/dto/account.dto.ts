import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';
import { MaxBytes } from './max-bytes.decorator';
import { NormalizeEmail } from './normalize-email.decorator';

export class VerifyEmailDTO {
  @ApiProperty({ description: 'Token ricevuto via email (link di verifica)' })
  @IsString()
  @MinLength(20)
  @MaxLength(200)
  token: string;
}

export class ResendVerificationDTO {
  @ApiProperty({ example: 'user@example.com' })
  @NormalizeEmail()
  @IsEmail()
  email: string;
}

export class ForgotPasswordDTO {
  @ApiProperty({ example: 'user@example.com' })
  @NormalizeEmail()
  @IsEmail()
  email: string;
}

export class ResetPasswordDTO {
  @ApiProperty({ description: 'Token ricevuto via email (link di reset)' })
  @IsString()
  @MinLength(20)
  @MaxLength(200)
  token: string;

  @ApiProperty({
    example: 'NewStrongPassword123!',
    minLength: 8,
    maxLength: 72,
  })
  @IsString()
  @MinLength(8)
  @MaxLength(72)
  @MaxBytes(72)
  password: string;
}
