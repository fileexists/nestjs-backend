/**
 * X-Request-Id (real PostgreSQL): a client-supplied id is only accepted if it is short and made of
 * letters, digits and hyphens; anything else is replaced by a UUID. Guard rejections (401) get an
 * id too, because the filter makes sure there is one.
 */
import { createHarness, Harness } from './support/harness';
import { http } from './support/api';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('X-Request-Id (e2e, real PostgreSQL)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });
  afterAll(async () => {
    await h?.close();
  });

  const idOf = (res: { headers: Record<string, unknown> }) =>
    res.headers['x-request-id'] as string;

  it('echoes a well formed id sent by the client', async () => {
    const res = await http(h).get('/health').set('X-Request-Id', 'abc-123');

    expect(idOf(res)).toBe('abc-123');
  });

  it.each([
    ['has a space', 'has space'],
    ['is longer than 64 characters', 'a'.repeat(65)],
    ['has an underscore', 'abc_123'],
    ['looks like markup', '<script>'],
  ])('replaces an id that %s with a UUID', async (_label, supplied) => {
    const res = await http(h).get('/health').set('X-Request-Id', supplied);

    expect(idOf(res)).toMatch(UUID);
  });

  it('generates one when the client sends none', async () => {
    const res = await http(h).get('/health');

    expect(idOf(res)).toMatch(UUID);
  });

  it('a 401 from a guard (before any interceptor runs) carries an id as well', async () => {
    const res = await http(h)
      .get('/api/user/me')
      .set('X-Request-Id', 'trace-7');

    expect(res.status).toBe(401);
    expect(idOf(res)).toBe('trace-7');

    const anonymous = await http(h).get('/api/user/me');
    expect(anonymous.status).toBe(401);
    expect(idOf(anonymous)).toMatch(UUID);
  });
});
