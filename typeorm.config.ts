import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';
import { ENTITIES } from './src/common/entities';

dotenv.config();

export default new DataSource({
  type: 'postgres',
  url: process.env.DATABASE_URL,
  entities: ENTITIES,
  migrations: ['database/migrations/*.ts'],
  synchronize: false,
  logging: process.env.NODE_ENV === 'development',
});
