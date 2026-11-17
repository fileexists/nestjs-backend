import { AuthToken } from './auth-token.entity';
import { Permission } from './permission.entity';
import { RefreshToken } from './refresh-token.entity';
import { User } from './user.entity';

export { AuthToken, Permission, RefreshToken, User };

/** Elenco unico delle entità: usato da AppModule e dalla CLI delle migrazioni. */
export const ENTITIES = [User, Permission, AuthToken, RefreshToken];
