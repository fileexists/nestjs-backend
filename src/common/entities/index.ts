import { Permission } from './permission.entity';
import { User } from './user.entity';

export { Permission, User };

/** Elenco unico delle entità: usato da AppModule e dalla CLI delle migrazioni. */
export const ENTITIES = [User, Permission];
