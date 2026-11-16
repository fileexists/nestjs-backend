/**
 * Smoke test dell'harness: l'app parte contro un PostgreSQL vero con lo schema
 * creato dalle migrazioni (nessun `synchronize`).
 *
 * Prerequisito: docker compose --profile test up -d postgres-test
 */
import { createHarness, Harness } from './support/harness';
import { req } from '../utils/http';

describe('Harness e2e su PostgreSQL vero', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });

  afterAll(async () => {
    await h?.close();
  });

  it('applica le migrazioni (tabella users presente, nessun synchronize)', async () => {
    const [{ count }] = await h.db.query(
      `SELECT count(*)::int AS count FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name IN ('users','permissions','migrations')`,
    );
    expect(count).toBe(3);
    const [{ applied }] = await h.db.query(
      'SELECT count(*)::int AS applied FROM migrations',
    );
    expect(applied).toBeGreaterThan(0);
  });

  it('GET /health risponde 200', async () => {
    const res = await req(h.app).get('/health');
    expect(res.status).toBe(200);
  });

  it('una rotta protetta senza credenziali risponde 401', async () => {
    const res = await req(h.app).get('/api/user/me');
    expect(res.status).toBe(401);
  });
});
