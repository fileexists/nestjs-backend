import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';
import { MaxBytes } from './max-bytes.decorator';
import { NormalizeEmail } from './normalize-email.decorator';

export class VerifyEmailDTO {
  @ApiProperty({ description: 'Token received by email (verification link)' })
  @IsString()
  @MinLength(20)
  @MaxLength(200)
  token: string;

  @ApiProperty({
    example: 'MyStrongPassword123!',
    minLength: 8,
    maxLength: 72,
    description:
      'Account password, chosen by whoever confirms the email: replaces the one entered at registration',
  })
  @IsString()
  @MinLength(8)
  @MaxLength(72)
  @MaxBytes(72)
  password: string;
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
  @ApiProperty({ description: 'Token received by email (reset link)' })
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
