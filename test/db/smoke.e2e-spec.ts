/**
 * Harness smoke test: the app starts against a real PostgreSQL with the schema
 * created by the migrations (no `synchronize`).
 *
 * Prerequisite: docker compose --profile test up -d postgres-test
 */
import { createHarness, Harness } from './support/harness';
import { req } from '../utils/http';
import { sql } from './support/api';

describe('e2e harness on real PostgreSQL', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });

  afterAll(async () => {
    await h?.close();
  });

  it('applies the migrations (users table present, no synchronize)', async () => {
    const [{ count }] = await sql<{ count: number }>(
      h,
      `SELECT count(*)::int AS count FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name IN ('users','permissions','migrations')`,
    );
    expect(count).toBe(3);
    const [{ applied }] = await sql<{ applied: number }>(
      h,
      'SELECT count(*)::int AS applied FROM migrations',
    );
    expect(applied).toBeGreaterThan(0);
  });

  it('GET /health answers 200', async () => {
    const res = await req(h.app).get('/health');
    expect(res.status).toBe(200);
  });

  it('a protected route without credentials answers 401', async () => {
    const res = await req(h.app).get('/api/user/me');
    expect(res.status).toBe(401);
  });
});
