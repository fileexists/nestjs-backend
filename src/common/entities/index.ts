import { AuthToken } from './auth-token.entity';
import { LoginAttempt } from './login-attempt.entity';
import { Permission } from './permission.entity';
import { RefreshToken } from './refresh-token.entity';
import { User } from './user.entity';

export { AuthToken, LoginAttempt, Permission, RefreshToken, User };

/** Single list of the entities: used by AppModule and by the migrations CLI. */
export const ENTITIES = [
  User,
  Permission,
  AuthToken,
  RefreshToken,
  LoginAttempt,
];
