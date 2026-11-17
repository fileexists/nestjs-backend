import { AuthToken } from './auth-token.entity';
import { Permission } from './permission.entity';
import { User } from './user.entity';

export { AuthToken, Permission, User };

/** Elenco unico delle entità: usato da AppModule e dalla CLI delle migrazioni. */
export const ENTITIES = [User, Permission, AuthToken];
