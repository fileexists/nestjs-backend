import { ApiProperty } from '@nestjs/swagger';
import { Expose, Transform, Type } from 'class-transformer';

/** Permission as the client sees it: no `users` relation, nothing else. */
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
 * Public response of GET /user/me. It is a WHITELIST: use it with
 * `plainToInstance(UserResponseDto, user, { excludeExtraneousValues: true })`, so
 * only the fields marked @Expose() come out. Internal fields such as `password`, `tokenVersion`,
 * `googleId` and `emailVerifiedAt` cannot show up even if they are added to the entity.
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
  // toClassOnly: computed from the entity; on the way back (instanceToPlain)
  // the value is already the right one and `obj` no longer has emailVerifiedAt.
  @Transform(
    ({ obj }: { obj: { emailVerifiedAt?: Date | null } }) =>
      Boolean(obj.emailVerifiedAt),
    { toClassOnly: true },
  )
  @ApiProperty({ description: 'True if the email has been verified' })
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
