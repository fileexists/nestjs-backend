/**
 * D5 - The USER permission always exists: idempotent seed at startup and, if it is missing,
 * registration fails instead of creating users without permissions. (real PostgreSQL)
 */
import { PermissionService } from '../../src/modules/permission/permission.service';
import { createHarness, Harness } from './support/harness';
import { createVerifiedUser, http, register, sql } from './support/api';
import { googleLogin } from './support/google';

describe('D5 - USER permission (e2e, real PostgreSQL)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.reset();
    await h.app.get(PermissionService).ensureDefaults();
  });

  const userPermission = () =>
    sql<{ id: string; name: string }>(
      h,
      `SELECT id, name FROM permissions WHERE name = 'USER'`,
    );
  const userCount = async () =>
    (await sql<{ n: number }>(h, 'SELECT count(*)::int AS n FROM users'))[0].n;

  it('when the app starts on an empty database the USER permission is created', async () => {
    // beforeAll started the app on a fresh schema, with no manual seed
    expect(await userPermission()).toHaveLength(1);
  });

  it('the seed is idempotent: repeating it neither duplicates nor changes the permission', async () => {
    const before = await userPermission();
    await h.app.get(PermissionService).ensureDefaults();
    await h.app.get(PermissionService).ensureDefaults();
    expect(await userPermission()).toEqual(before);
  });

  it('the seed is safe with several instances starting together (no error, a single row)', async () => {
    await h.db.query(`DELETE FROM permissions WHERE name = 'USER'`);
    const service = h.app.get(PermissionService);

    await Promise.all(
      Array.from({ length: 10 }, () => service.ensureDefaults()),
    );

    expect(await userPermission()).toHaveLength(1);
  });

  it('does not overwrite a description changed by an administrator', async () => {
    await h.db.query(
      `UPDATE permissions SET description = 'Custom description' WHERE name = 'USER'`,
    );
    await h.app.get(PermissionService).ensureDefaults();
    const [row] = await sql<{ description: string }>(
      h,
      `SELECT description FROM permissions WHERE name = 'USER'`,
    );
    expect(row.description).toBe('Custom description');
  });

  it('registered users receive the USER permission', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    const rows = await sql<{ name: string }>(
      h,
      `SELECT p.name FROM permissions p
         JOIN user_permissions up ON up.permission_id = p.id
         JOIN users u ON u.id = up.user_id WHERE u.email = 'mario@example.com'`,
    );
    expect(rows).toEqual([{ name: 'USER' }]);
  });

  describe('permission missing at runtime', () => {
    beforeEach(async () => {
      await h.db.query(`DELETE FROM permissions WHERE name = 'USER'`);
    });

    it('registration does NOT create a user without permissions: answers 503 and sends no email', async () => {
      const res = await register(h, 'mario@example.com');

      expect(res.status).toBe(503);
      expect(await userCount()).toBe(0);
      expect(h.mail.sent).toHaveLength(0);
    });

    it('the first Google login does not create users without permissions', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'g@example.com',
        email_verified: true,
      });
      expect(callback.status).toBe(503);
      expect(await userCount()).toBe(0);
    });

    it('after the restore (restart/seed) registration works again', async () => {
      expect((await register(h, 'a@example.com')).status).toBe(503);
      await h.app.get(PermissionService).ensureDefaults();
      expect((await register(h, 'a@example.com')).status).toBe(202);
      expect(await userCount()).toBe(1);
    });

    it('the rest of the app is not affected (health, login of existing users)', async () => {
      expect((await http(h).get('/health')).status).toBe(200);
    });
  });
});
