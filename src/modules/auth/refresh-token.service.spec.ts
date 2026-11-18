import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { RefreshTokenService } from './refresh-token.service';
import { RefreshToken } from '../../common/entities/refresh-token.entity';

describe('RefreshTokenService', () => {
  const execute = jest.fn();
  const getRawOne = jest.fn();
  const queryBuilder = {
    update: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    returning: jest.fn().mockReturnThis(),
    execute,
    innerJoin: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    andWhere: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    getRawOne,
  };
  const repository = {
    insert: jest.fn(),
    findOne: jest.fn(),
    query: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    createQueryBuilder: jest.fn(() => queryBuilder),
  };
  const sha = (value: string) =>
    createHash('sha256').update(value).digest('hex');
  let service: RefreshTokenService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module = await Test.createTestingModule({
      providers: [
        RefreshTokenService,
        { provide: getRepositoryToken(RefreshToken), useValue: repository },
      ],
    }).compile();
    service = module.get(RefreshTokenService);
  });

  it('create: stores only the hash of the jti', async () => {
    const expiresAt = new Date(Date.now() + 1000);
    await service.create({
      userId: 'u1',
      jti: 'my-jti',
      familyId: 'f1',
      expiresAt,
    });

    const row = (repository.insert.mock.calls as unknown[][])[0][0] as Record<
      string,
      unknown
    >;
    expect(row).toEqual({
      userId: 'u1',
      familyId: 'f1',
      jtiHash: sha('my-jti'),
      expiresAt,
    });
    expect(JSON.stringify(row)).not.toContain('my-jti');
  });

  describe('findActiveSession', () => {
    it('a single query: family and user together, only tokens that are not revoked and not expired', async () => {
      getRawOne.mockResolvedValue({ tokenVersion: 4 });

      await expect(service.findActiveSession('u1', 'f1')).resolves.toEqual({
        tokenVersion: 4,
      });

      expect(repository.createQueryBuilder).toHaveBeenCalledTimes(1);
      expect(queryBuilder.innerJoin).toHaveBeenCalledWith('rt.user', 'u');
      expect(queryBuilder.where).toHaveBeenCalledWith(
        expect.stringContaining('rt.familyId = :familyId'),
        { familyId: 'f1', userId: 'u1' },
      );
      const conditions = (queryBuilder.andWhere.mock.calls as string[][])
        .map((c) => c[0])
        .join(' ');
      expect(conditions).toContain('rt.revokedAt IS NULL');
      expect(conditions).toContain('rt.expiresAt > now()');
      expect(queryBuilder.limit).toHaveBeenCalledWith(1);
    });

    it("with no rows (family revoked, expired, someone else's, or user deleted) returns null", async () => {
      getRawOne.mockResolvedValue(undefined);

      await expect(service.findActiveSession('u1', 'f1')).resolves.toBeNull();
    });
  });

  describe('rotate', () => {
    const futureRow = (overrides: Record<string, unknown> = {}) => ({
      usedAt: new Date(),
      revokedAt: null,
      expired: false,
      withinGrace: false,
      familyId: 'f1',
      ...overrides,
    });

    it('marks the token as used with a single conditional UPDATE (not used, not revoked, not expired)', async () => {
      execute.mockResolvedValue({
        raw: [{ id: 'r1', userId: 'u1', familyId: 'f1' }],
      });

      const result = await service.rotate('jti-1', 10);

      expect(result).toEqual({
        status: 'rotated',
        token: { id: 'r1', userId: 'u1', familyId: 'f1' },
      });
      const [condition, params] = queryBuilder.where.mock.calls[0] as [
        string,
        { hash: string },
      ];
      expect(condition).toContain('"usedAt" IS NULL');
      expect(condition).toContain('"revokedAt" IS NULL');
      expect(condition).toContain('"expiresAt" > now()');
      expect(params.hash).toBe(sha('jti-1'));
      expect(repository.query).not.toHaveBeenCalled();
    });

    it('unknown -> invalid', async () => {
      execute.mockResolvedValue({ raw: [] });
      repository.query.mockResolvedValue([]);

      await expect(service.rotate('x')).resolves.toEqual({ status: 'invalid' });
    });

    it.each([
      ['inside the grace period', true],
      ['outside the grace period', false],
    ])('already used, %s -> reused with the record', async (_label, within) => {
      execute.mockResolvedValue({ raw: [] });
      const row = futureRow({ withinGrace: within });
      repository.query.mockResolvedValue([row]);

      await expect(service.rotate('x', 10)).resolves.toEqual({
        status: 'reused',
        token: row,
        withinGrace: within,
      });
    });

    it('judges the grace period and the expiry with the database clock, not the application one', async () => {
      execute.mockResolvedValue({ raw: [] });
      repository.query.mockResolvedValue([futureRow()]);

      await service.rotate('jti-1', 7);

      const [sql, params] = repository.query.mock.calls[0] as [
        string,
        unknown[],
      ];
      expect(sql).toContain('now() - make_interval(secs => $2)');
      expect(sql).toContain('"expiresAt" <= now()');
      expect(params).toEqual([sha('jti-1'), 7]);
    });

    it('a null window (token never used) is not "within grace"', async () => {
      execute.mockResolvedValue({ raw: [] });
      repository.query.mockResolvedValue([
        futureRow({ usedAt: new Date(), withinGrace: null }),
      ]);

      await expect(service.rotate('x', 10)).resolves.toMatchObject({
        status: 'reused',
        withinGrace: false,
      });
    });

    it.each([
      ['revoked', futureRow({ revokedAt: new Date() })],
      ['expired', futureRow({ usedAt: null, expired: true })],
      ['expired and used', futureRow({ expired: true })],
      [
        'not used (so it was not rotatable for another reason)',
        futureRow({ usedAt: null }),
      ],
    ])('%s -> invalid (no chained revocation)', async (_label, row) => {
      execute.mockResolvedValue({ raw: [] });
      repository.query.mockResolvedValue([row]);

      await expect(service.rotate('x')).resolves.toEqual({ status: 'invalid' });
    });
  });

  it("revokeFamily: sets revokedAt only on the family's tokens that are not yet revoked", async () => {
    await service.revokeFamily('f1');
    const [where, set] = repository.update.mock.calls[0] as [
      Record<string, unknown>,
      Record<string, unknown>,
    ];
    expect(where.familyId).toBe('f1');
    expect(where.revokedAt).toBeDefined();
    expect(set.revokedAt).toBeInstanceOf(Date);
  });

  it("revokeAllForUser: revokes all the user's sessions", async () => {
    await service.revokeAllForUser('u1');
    const [where] = repository.update.mock.calls[0] as [
      Record<string, unknown>,
    ];
    expect(where.userId).toBe('u1');
  });

  it('deleteExpired: returns how many it deleted', async () => {
    repository.delete.mockResolvedValue({ affected: 4 });
    await expect(service.deleteExpired()).resolves.toBe(4);
  });
});
