import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { LoginAttempt } from '../../common/entities/login-attempt.entity';
import { LoginAttemptService } from './login-attempt.service';

describe('LoginAttemptService (D2)', () => {
  const sha = (v: string) => createHash('sha256').update(v).digest('hex');
  const queryBuilder = {
    delete: jest.fn().mockReturnThis(),
    from: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    execute: jest.fn(),
  };
  const tx = { query: jest.fn() };
  const repository = {
    delete: jest.fn(),
    createQueryBuilder: jest.fn(() => queryBuilder),
    manager: {
      transaction: jest.fn((work: (t: typeof tx) => Promise<unknown>) =>
        work(tx),
      ),
    },
  };
  let service: LoginAttemptService;

  async function build(values: Record<string, number> = {}) {
    const module = await Test.createTestingModule({
      providers: [
        LoginAttemptService,
        { provide: getRepositoryToken(LoginAttempt), useValue: repository },
        { provide: ConfigService, useValue: { get: (k: string) => values[k] } },
      ],
    }).compile();
    return module.get(LoginAttemptService);
  }

  beforeEach(async () => {
    jest.clearAllMocks();
    service = await build();
  });

  it('identifierFor: hash of the NORMALIZED email (case and spaces do not change the key)', () => {
    expect(LoginAttemptService.identifierFor('  Mario@Example.COM ')).toBe(
      sha('mario@example.com'),
    );
    expect(LoginAttemptService.identifierFor('mario@example.com')).toBe(
      LoginAttemptService.identifierFor('MARIO@example.com'),
    );
  });

  describe('registerAttempt', () => {
    const row = (over: Partial<Record<string, unknown>> = {}) => ({
      failedCount: 0,
      lockLevel: 0,
      locked: false,
      stale: false,
      ...over,
    });
    const update = (call: number) =>
      tx.query.mock.calls[call] as [string, unknown[]];

    it('first locks the row (dummy upsert) in a transaction, then updates', async () => {
      tx.query.mockResolvedValueOnce([row()]).mockResolvedValueOnce([]);

      await expect(service.registerAttempt('a@example.com')).resolves.toEqual({
        locked: false,
      });

      expect(repository.manager.transaction).toHaveBeenCalledTimes(1);
      const [sql, params] = update(0);
      expect(sql).toMatch(/INSERT INTO "login_attempts"/);
      expect(sql).toMatch(/ON CONFLICT \("identifier"\) DO UPDATE/);
      expect(params).toEqual([sha('a@example.com'), 1800]);
    });

    it('below the threshold: counts the attempt and does not lock', async () => {
      tx.query
        .mockResolvedValueOnce([row({ failedCount: 2, lockLevel: 1 })])
        .mockResolvedValueOnce([]);

      const result = await service.registerAttempt('a@example.com');

      expect(result).toEqual({ locked: false });
      expect(tx.query).toHaveBeenCalledTimes(2);
      const [sql, params] = update(1);
      expect(sql).not.toContain('"lockedUntil"');
      expect(params).toEqual([sha('a@example.com'), 3, 1]);
    });

    it('the attempt that reaches the threshold triggers the lock, but goes through (the password is verified)', async () => {
      tx.query
        .mockResolvedValueOnce([row({ failedCount: 4, lockLevel: 2 })])
        .mockResolvedValueOnce([]);

      const result = await service.registerAttempt('a@example.com');

      expect(result).toEqual({ locked: false });
      const [sql, params] = update(1);
      expect(sql).toContain('power(2, $4::int)');
      expect(sql).toContain('LEAST(');
      expect(sql).toContain('"failedCount" = 0');
      // duration = min(cap, base * 2^level); the level grows by one
      expect(params).toEqual([sha('a@example.com'), 900, 60, 2]);
    });

    it('account already locked: says so without counting anything (does not extend the lock)', async () => {
      tx.query.mockResolvedValueOnce([row({ failedCount: 0, locked: true })]);

      await expect(service.registerAttempt('a@example.com')).resolves.toEqual({
        locked: true,
      });

      expect(tx.query).toHaveBeenCalledTimes(1);
    });

    it('outside the window it starts again from zero: counter and level reset', async () => {
      tx.query
        .mockResolvedValueOnce([
          row({ failedCount: 4, lockLevel: 3, stale: true }),
        ])
        .mockResolvedValueOnce([]);

      await service.registerAttempt('a@example.com');

      const [, params] = update(1);
      expect(params).toEqual([sha('a@example.com'), 1, 0]);
    });

    it('the parameters are configurable', async () => {
      const custom = await build({
        LOGIN_MAX_FAILED_ATTEMPTS: 3,
        LOGIN_LOCK_BASE_SECONDS: 10,
        LOGIN_LOCK_MAX_SECONDS: 100,
        LOGIN_ATTEMPT_WINDOW_SECONDS: 600,
      });
      tx.query
        .mockResolvedValueOnce([row({ failedCount: 2 })])
        .mockResolvedValueOnce([]);

      await custom.registerAttempt('a@example.com');

      expect(update(0)[1]).toEqual([sha('a@example.com'), 600]);
      expect(update(1)[1]).toEqual([sha('a@example.com'), 100, 10, 0]);
    });

    it('a database error is propagated (no attempt goes through silently)', async () => {
      tx.query.mockRejectedValueOnce(new Error('db down'));

      await expect(service.registerAttempt('a@example.com')).rejects.toThrow(
        'db down',
      );
    });
  });

  it('reset deletes the account record', async () => {
    await service.reset('A@Example.com');
    expect(repository.delete).toHaveBeenCalledWith({
      identifier: sha('a@example.com'),
    });
  });

  it('deleteStale removes the records that are not locked and outside the window and returns the count', async () => {
    queryBuilder.execute.mockResolvedValue({ affected: 7 });
    await expect(service.deleteStale()).resolves.toBe(7);
    const [condition] = queryBuilder.where.mock.calls[0] as [string];
    expect(condition).toContain(
      '"lockedUntil" IS NULL OR "lockedUntil" < now()',
    );
  });
});
