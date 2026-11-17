import { ApiProperty } from '@nestjs/swagger';
import { Expose, Transform, Type } from 'class-transformer';
import { IsEmail, IsOptional, IsString, Length } from 'class-validator';
import { Permission } from '../entities/permission.entity';
import { NormalizeEmail } from './normalize-email.decorator';

export class CreateUserDto {
  @NormalizeEmail()
  @IsEmail()
  email: string;

  @IsOptional()
  @IsString()
  @Length(8, 255)
  password?: string;

  @IsOptional()
  @IsString()
  @Length(1, 255)
  googleId?: string;

  @IsOptional()
  @IsString()
  @Length(1, 50)
  provider?: string;

  permissions: Permission[];
}

export class UpdateUserDto {
  @IsOptional()
  @NormalizeEmail()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  @Length(8, 255)
  password?: string;

  @IsOptional()
  @IsString()
  googleId?: string;

  @IsOptional()
  @IsString()
  @Length(1, 50)
  provider?: string;

  @IsOptional()
  permissions?: Permission[];
}

/** Permesso come lo vede il client: niente relazione `users`, niente altro. */
export class PermissionResponseDto {
  @Expose()
  @ApiProperty()
  id: string;

  @Expose()
  @ApiProperty()
  name: string;

  @Expose()
  @ApiProperty()
  description: string;
}

/**
 * Risposta pubblica di GET /user/me. E' una WHITELIST: si usa con
 * `plainToInstance(UserResponseDto, user, { excludeExtraneousValues: true })`, quindi
 * solo i campi marcati @Expose() escono. Campi interni come `password`, `tokenVersion`,
 * `googleId` ed `emailVerifiedAt` non possono comparire nemmeno aggiungendoli all'entita'.
 */
export class UserResponseDto {
  @Expose()
  @ApiProperty()
  id: string;

  @Expose()
  @ApiProperty()
  email: string;

  @Expose()
  @ApiProperty({ required: false, example: 'local' })
  provider?: string;

  @Expose()
  // toClassOnly: si calcola dall'entita'; nella serializzazione di ritorno (instanceToPlain)
  // il valore e' gia' quello giusto e `obj` non ha piu' emailVerifiedAt.
  @Transform(
    ({ obj }: { obj: { emailVerifiedAt?: Date | null } }) =>
      Boolean(obj.emailVerifiedAt),
    { toClassOnly: true },
  )
  @ApiProperty({ description: "True se l'email e' stata verificata" })
  emailVerified: boolean;

  @Expose()
  @Type(() => PermissionResponseDto)
  @ApiProperty({ type: () => [PermissionResponseDto] })
  permissions: PermissionResponseDto[];

  @Expose()
  @ApiProperty()
  createdAt: Date;

  @Expose()
  @ApiProperty()
  updatedAt: Date;
}
