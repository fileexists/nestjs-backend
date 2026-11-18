/**
 * TRUST_PROXY default (1 hop, real PostgreSQL): behind a reverse proxy the client IP comes from
 * X-Forwarded-For, so every client has its own rate-limit bucket.
 */
import { createHarness, Harness } from './support/harness';
import { http } from './support/api';

describe('TRUST_PROXY default of 1 hop (e2e, real PostgreSQL)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness({ throttle: true });
  });
  afterAll(async () => {
    await h?.close();
  });

  it('clients behind the proxy are limited one by one, using the forwarded address', async () => {
    const login = (ip: string, n: number) =>
      http(h)
        .post('/api/auth/login')
        .set('X-Forwarded-For', ip)
        .send({ email: `nobody${n}@example.com`, password: 'Wrong-Passw0rd!' });

    // One client uses up its 5 requests...
    for (let i = 0; i < 5; i++) {
      expect((await login('203.0.113.10', i)).status).toBe(401);
    }
    expect((await login('203.0.113.10', 5)).status).toBe(429);

    // ...and another one, behind the same proxy, is not affected.
    expect((await login('203.0.113.11', 6)).status).toBe(401);
  });
});
