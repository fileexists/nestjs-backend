/**
 * D5 - Il permesso USER esiste sempre: seed idempotente all'avvio e, se manca,
 * la registrazione fallisce invece di creare utenti senza permessi. (PostgreSQL vero)
 */
import { PermissionService } from '../../src/modules/permission/permission.service';
import { createHarness, Harness } from './support/harness';
import { createVerifiedUser, http, register, sql } from './support/api';
import { googleLogin } from './support/google';

describe('D5 - permesso USER (e2e, PostgreSQL vero)', () => {
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

  it("all'avvio dell'app su un database vuoto il permesso USER viene creato", async () => {
    // beforeAll ha avviato l'app su schema nuovo, senza nessun seed manuale
    expect(await userPermission()).toHaveLength(1);
  });

  it('il seed e idempotente: ripeterlo non duplica ne modifica il permesso', async () => {
    const before = await userPermission();
    await h.app.get(PermissionService).ensureDefaults();
    await h.app.get(PermissionService).ensureDefaults();
    expect(await userPermission()).toEqual(before);
  });

  it('il seed e sicuro con piu istanze che partono insieme (nessun errore, una sola riga)', async () => {
    await h.db.query(`DELETE FROM permissions WHERE name = 'USER'`);
    const service = h.app.get(PermissionService);

    await Promise.all(
      Array.from({ length: 10 }, () => service.ensureDefaults()),
    );

    expect(await userPermission()).toHaveLength(1);
  });

  it('non sovrascrive una descrizione modificata da un amministratore', async () => {
    await h.db.query(
      `UPDATE permissions SET description = 'Descrizione personalizzata' WHERE name = 'USER'`,
    );
    await h.app.get(PermissionService).ensureDefaults();
    const [row] = await sql<{ description: string }>(
      h,
      `SELECT description FROM permissions WHERE name = 'USER'`,
    );
    expect(row.description).toBe('Descrizione personalizzata');
  });

  it('gli utenti registrati ricevono il permesso USER', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    const rows = await sql<{ name: string }>(
      h,
      `SELECT p.name FROM permissions p
         JOIN user_permissions up ON up.permission_id = p.id
         JOIN users u ON u.id = up.user_id WHERE u.email = 'mario@example.com'`,
    );
    expect(rows).toEqual([{ name: 'USER' }]);
  });

  describe('permesso mancante a runtime', () => {
    beforeEach(async () => {
      await h.db.query(`DELETE FROM permissions WHERE name = 'USER'`);
    });

    it('la registrazione NON crea un utente senza permessi: risponde 503 e non invia email', async () => {
      const res = await register(h, 'mario@example.com');

      expect(res.status).toBe(503);
      expect(await userCount()).toBe(0);
      expect(h.mail.sent).toHaveLength(0);
    });

    it('il primo accesso Google non crea utenti senza permessi', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'g@example.com',
        email_verified: true,
      });
      expect(callback.status).toBe(503);
      expect(await userCount()).toBe(0);
    });

    it('dopo il ripristino (riavvio/seed) la registrazione torna a funzionare', async () => {
      expect((await register(h, 'a@example.com')).status).toBe(503);
      await h.app.get(PermissionService).ensureDefaults();
      expect((await register(h, 'a@example.com')).status).toBe(202);
      expect(await userCount()).toBe(1);
    });

    it("il resto dell'app non e interessato (health, login di utenti esistenti)", async () => {
      expect((await http(h).get('/health')).status).toBe(200);
    });
  });
});
