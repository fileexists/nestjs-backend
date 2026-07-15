import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';
import { User } from './src/common/entities/user.entity';
import { Permission } from './src/common/entities/permission.entity';

dotenv.config();

export default new DataSource({
  type: 'postgres',
  url: process.env.DATABASE_URL,
  entities: [User, Permission],
  migrations: ['database/migrations/*.ts'],
  synchronize: false,
  logging: process.env.NODE_ENV === 'development',
});
