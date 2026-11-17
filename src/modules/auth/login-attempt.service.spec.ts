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
  const repository = {
    query: jest.fn(),
    delete: jest.fn(),
    createQueryBuilder: jest.fn(() => queryBuilder),
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

  describe('getLockedUntil', () => {
    it('ritorna la scadenza del blocco (orologio del database) o null', async () => {
      const until = new Date(Date.now() + 60_000);
      repository.query
        .mockResolvedValueOnce([{ lockedUntil: until }])
        .mockResolvedValueOnce([]);

      await expect(service.getLockedUntil('a@example.com')).resolves.toBe(
        until,
      );
      await expect(service.getLockedUntil('a@example.com')).resolves.toBeNull();

      const [sql, params] = repository.query.mock.calls[0] as [
        string,
        string[],
      ];
      expect(sql).toContain('"lockedUntil" > now()');
      expect(params).toEqual([sha('a@example.com')]);
    });
  });

  describe('recordFailure', () => {
    it('sotto soglia: un solo upsert e nessun blocco', async () => {
      repository.query.mockResolvedValueOnce([{ failedCount: 4 }]);

      await service.recordFailure('a@example.com');

      expect(repository.query).toHaveBeenCalledTimes(1);
      const [sql, params] = repository.query.mock.calls[0] as [
        string,
        unknown[],
      ];
      expect(sql).toMatch(/INSERT INTO "login_attempts"/);
      expect(sql).toMatch(/ON CONFLICT/);
      expect(params).toEqual([sha('a@example.com'), 1800]);
    });

    it('alla soglia: applica il blocco con durata raddoppiata per livello e tetto massimo, in modo idempotente', async () => {
      repository.query
        .mockResolvedValueOnce([{ failedCount: 5 }])
        .mockResolvedValueOnce([]);

      await service.recordFailure('a@example.com');

      expect(repository.query).toHaveBeenCalledTimes(2);
      const [sql, params] = repository.query.mock.calls[1] as [
        string,
        unknown[],
      ];
      expect(sql).toContain('power(2, "lockLevel")');
      expect(sql).toContain('LEAST(');
      expect(sql).toContain('"failedCount" = 0');
      expect(sql).toMatch(/WHERE "identifier" = \$1 AND "failedCount" >= \$4/); // scatta una volta sola
      expect(params).toEqual([sha('a@example.com'), 900, 60, 5]);
    });

    it('i parametri sono configurabili', async () => {
      const custom = await build({
        LOGIN_MAX_FAILED_ATTEMPTS: 3,
        LOGIN_LOCK_BASE_SECONDS: 10,
        LOGIN_LOCK_MAX_SECONDS: 100,
        LOGIN_ATTEMPT_WINDOW_SECONDS: 600,
      });
      repository.query
        .mockResolvedValueOnce([{ failedCount: 3 }])
        .mockResolvedValueOnce([]);

      await custom.recordFailure('a@example.com');

      expect((repository.query.mock.calls[0] as unknown[][])[1]).toEqual([
        sha('a@example.com'),
        600,
      ]);
      expect((repository.query.mock.calls[1] as unknown[][])[1]).toEqual([
        sha('a@example.com'),
        100,
        10,
        3,
      ]);
    });

    it("la finestra azzera contatore e livello se l'ultimo errore e vecchio", async () => {
      repository.query.mockResolvedValueOnce([{ failedCount: 1 }]);
      await service.recordFailure('a@example.com');
      const [sql] = repository.query.mock.calls[0] as [string];
      expect(sql).toMatch(/"lastFailedAt" < now\(\) - make_interval/);
      expect(sql).toMatch(/THEN 1 ELSE/);
      expect(sql).toMatch(/THEN 0 ELSE/);
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
