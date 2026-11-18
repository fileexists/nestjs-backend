/**
 * TRUST_PROXY=0 (real PostgreSQL): no proxy in front of the app, so X-Forwarded-For is ignored.
 * Otherwise anyone could send a different value on every request and sidestep the per-IP limits.
 */
// Before importing AppModule: ConfigModule reads the environment when the module loads.
process.env.TRUST_PROXY = '0';

import { createHarness, Harness } from './support/harness';
import { http } from './support/api';

describe('TRUST_PROXY=0 (e2e, real PostgreSQL)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness({ throttle: true });
  });
  afterAll(async () => {
    await h?.close();
  });

  it('a spoofed X-Forwarded-For does not give a request a fresh rate-limit bucket', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) {
      const res = await http(h)
        .post('/api/auth/login')
        .set('X-Forwarded-For', `203.0.113.${i + 1}`)
        .send({ email: `nobody${i}@example.com`, password: 'Wrong-Passw0rd!' });
      statuses.push(res.status);
    }

    // The login route allows 5 requests a minute per IP: the 6th is refused whatever the header says.
    expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(statuses.slice(5)).toEqual([429, 429, 429]);
  });
});
