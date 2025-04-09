import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { PermissionSeeder } from './permission.seed';
import { UserSeeder } from './user.seed';

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const args = process.argv.slice(2);
  const argv: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].substring(2);
      const value = args[i + 1];
      argv[key] = value;
      i++;
    }
  }

  const permissionSeeder = app.get(PermissionSeeder);
  await permissionSeeder.seedPermissions();

  if (argv.email && argv.password && argv.permission) {
    const userSeeder = app.get(UserSeeder);
    await userSeeder.seedUser({
      email: argv.email,
      password: argv.password,
      permission: argv.permission,
    });
  } else {
    console.log(
      'Skipping user seeding. Provide --email, --password, and --permission arguments to seed a user.'
    );
  }

  await app.close();
}

bootstrap().catch((err) => {
  console.error('Failed to seed database', err);
  process.exit(1);
});
