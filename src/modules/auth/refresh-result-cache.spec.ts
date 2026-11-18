import { RefreshResultCache } from './refresh-result-cache';

describe('RefreshResultCache', () => {
  let now: number;
  const clock = () => now;
  const owner = { familyId: 'f1', userId: 'u1' };

  beforeEach(() => {
    now = 1_000_000;
  });

  it('returns what was stored until the ttl elapses, then forgets it', async () => {
    const cache = new RefreshResultCache<string>(10_000, clock);
    cache.set('jti-1', Promise.resolve('pair'), owner);

    await expect(cache.get('jti-1')).resolves.toBe('pair');
    now += 9_999;
    await expect(cache.get('jti-1')).resolves.toBe('pair');
    now += 1;
    expect(cache.get('jti-1')).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it('stores the promise, so a request that arrives while the rotation is running shares it', async () => {
    const cache = new RefreshResultCache<string>(10_000, clock);
    let finish!: (value: string) => void;
    cache.set('jti-1', new Promise<string>((r) => (finish = r)), owner);

    const waiting = cache.get('jti-1');
    finish('pair');

    await expect(waiting).resolves.toBe('pair');
  });

  it('is disabled with a ttl of 0 (nothing is ever stored)', () => {
    const cache = new RefreshResultCache<string>(0, clock);

    cache.set('jti-1', Promise.resolve('pair'), owner);

    expect(cache.enabled).toBe(false);
    expect(cache.get('jti-1')).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it('drops the entries of a revoked family only', () => {
    const cache = new RefreshResultCache<string>(10_000, clock);
    cache.set('a', Promise.resolve('1'), { familyId: 'f1', userId: 'u1' });
    cache.set('b', Promise.resolve('2'), { familyId: 'f1', userId: 'u1' });
    cache.set('c', Promise.resolve('3'), { familyId: 'f2', userId: 'u1' });

    cache.invalidateFamily('f1');

    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('c')).toBeDefined();
  });

  it('drops the entries of every session of a user only', () => {
    const cache = new RefreshResultCache<string>(10_000, clock);
    cache.set('a', Promise.resolve('1'), { familyId: 'f1', userId: 'u1' });
    cache.set('b', Promise.resolve('2'), { familyId: 'f2', userId: 'u1' });
    cache.set('c', Promise.resolve('3'), { familyId: 'f3', userId: 'u2' });

    cache.invalidateUser('u1');

    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('c')).toBeDefined();
  });

  it('delete removes a single entry', () => {
    const cache = new RefreshResultCache<string>(10_000, clock);
    cache.set('a', Promise.resolve('1'), owner);

    cache.delete('a');

    expect(cache.get('a')).toBeUndefined();
  });

  it('sweeps the expired entries when a new one is added, so memory does not grow', () => {
    const cache = new RefreshResultCache<string>(1_000, clock);
    cache.set('old-1', Promise.resolve('1'), owner);
    cache.set('old-2', Promise.resolve('2'), owner);
    now += 5_000;

    cache.set('fresh', Promise.resolve('3'), owner);

    expect(cache.size).toBe(1);
    expect(cache.get('fresh')).toBeDefined();
  });

  it('never holds more than the cap: the oldest entries go first', () => {
    const cache = new RefreshResultCache<number>(60_000, clock);
    for (let i = 0; i < 5_050; i++) {
      cache.set(`jti-${i}`, Promise.resolve(i), owner);
    }

    expect(cache.size).toBe(5_000);
    expect(cache.get('jti-0')).toBeUndefined();
    expect(cache.get('jti-5049')).toBeDefined();
  });
});
