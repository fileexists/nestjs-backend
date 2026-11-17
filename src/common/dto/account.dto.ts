import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class VerifyEmailDTO {
  @ApiProperty({ description: 'Token ricevuto via email (link di verifica)' })
  @IsString()
  @MinLength(20)
  @MaxLength(200)
  token: string;
}

export class ResendVerificationDTO {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  email: string;
}
