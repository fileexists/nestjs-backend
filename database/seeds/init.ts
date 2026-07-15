import { NestFactory } from '@nestjs/core';
import { SeedModule } from './seed.module';
import { PermissionSeeder } from './permission.seed';
import { UserSeeder } from './user.seed';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.createApplicationContext(SeedModule);

  const args = process.argv.slice(2);
  const argv: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      argv[args[i].substring(2)] = args[i + 1];
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
  } else if (argv.email && !argv.password && argv.permission) {
    const userSeeder = app.get(UserSeeder);
    await userSeeder.seedGoogleUser({ email: argv.email, permission: argv.permission });
  } else {
    console.log(
      'Skipping user seeding. Pass --email, --password, and --permission to seed a local user, ' +
        'or --email and --permission for a Google user.',
    );
  }

  await app.close();
}

bootstrap().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
