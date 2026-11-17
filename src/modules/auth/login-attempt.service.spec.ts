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

  it("identifierFor: hash dell'email NORMALIZZATA (maiuscole e spazi non cambiano la chiave)", () => {
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

    it('prima blocca la riga (upsert fittizio) in una transazione, poi aggiorna', async () => {
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

    it('sotto soglia: conta il tentativo e non blocca', async () => {
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

    it('il tentativo che raggiunge la soglia fa scattare il blocco, ma passa (la password si verifica)', async () => {
      tx.query
        .mockResolvedValueOnce([row({ failedCount: 4, lockLevel: 2 })])
        .mockResolvedValueOnce([]);

      const result = await service.registerAttempt('a@example.com');

      expect(result).toEqual({ locked: false });
      const [sql, params] = update(1);
      expect(sql).toContain('power(2, $4::int)');
      expect(sql).toContain('LEAST(');
      expect(sql).toContain('"failedCount" = 0');
      // durata = min(tetto, base * 2^livello); il livello cresce di uno
      expect(params).toEqual([sha('a@example.com'), 900, 60, 2]);
    });

    it('account gia bloccato: lo dice senza contare nulla (non prolunga il blocco)', async () => {
      tx.query.mockResolvedValueOnce([row({ failedCount: 0, locked: true })]);

      await expect(service.registerAttempt('a@example.com')).resolves.toEqual({
        locked: true,
      });

      expect(tx.query).toHaveBeenCalledTimes(1);
    });

    it('fuori finestra riparte da zero: contatore e livello azzerati', async () => {
      tx.query
        .mockResolvedValueOnce([
          row({ failedCount: 4, lockLevel: 3, stale: true }),
        ])
        .mockResolvedValueOnce([]);

      await service.registerAttempt('a@example.com');

      const [, params] = update(1);
      expect(params).toEqual([sha('a@example.com'), 1, 0]);
    });

    it('i parametri sono configurabili', async () => {
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

    it('un errore del database si propaga (nessun tentativo passa in silenzio)', async () => {
      tx.query.mockRejectedValueOnce(new Error('db down'));

      await expect(service.registerAttempt('a@example.com')).rejects.toThrow(
        'db down',
      );
    });
  });

  it("reset cancella il record dell'account", async () => {
    await service.reset('A@Example.com');
    expect(repository.delete).toHaveBeenCalledWith({
      identifier: sha('a@example.com'),
    });
  });

  it('deleteStale elimina i record non bloccati e fuori finestra e ritorna il conteggio', async () => {
    queryBuilder.execute.mockResolvedValue({ affected: 7 });
    await expect(service.deleteStale()).resolves.toBe(7);
    const [condition] = queryBuilder.where.mock.calls[0] as [string];
    expect(condition).toContain(
      '"lockedUntil" IS NULL OR "lockedUntil" < now()',
    );
  });
});
