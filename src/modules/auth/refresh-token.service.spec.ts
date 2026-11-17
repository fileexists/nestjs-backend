import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { RefreshTokenService } from './refresh-token.service';
import { RefreshToken } from '../../common/entities/refresh-token.entity';

describe('RefreshTokenService', () => {
  const execute = jest.fn();
  const queryBuilder = {
    update: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    returning: jest.fn().mockReturnThis(),
    execute,
  };
  const repository = {
    insert: jest.fn(),
    findOne: jest.fn(),
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

  it('create: salva solo l hash del jti', async () => {
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

  describe('rotate', () => {
    it("usa un solo UPDATE condizionale (non usato, non revocato, non scaduto) per marcare 'usato'", async () => {
      execute.mockResolvedValue({
        raw: [{ id: 'r1', userId: 'u1', familyId: 'f1' }],
      });

      const result = await service.rotate('jti-1');

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
    });

    it('sconosciuto -> invalid', async () => {
      execute.mockResolvedValue({ raw: [] });
      repository.findOne.mockResolvedValue(null);
      await expect(service.rotate('x')).resolves.toEqual({ status: 'invalid' });
    });

    it('gia usato (e non revocato/scaduto) -> reused, con il record per poter revocare la famiglia', async () => {
      execute.mockResolvedValue({ raw: [] });
      const row = {
        usedAt: new Date(),
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
        familyId: 'f1',
      };
      repository.findOne.mockResolvedValue(row);
      await expect(service.rotate('x')).resolves.toEqual({
        status: 'reused',
        token: row,
      });
    });

    it.each([
      [
        'revocato',
        {
          usedAt: new Date(),
          revokedAt: new Date(),
          expiresAt: new Date(Date.now() + 60_000),
        },
      ],
      [
        'scaduto',
        {
          usedAt: null,
          revokedAt: null,
          expiresAt: new Date(Date.now() - 1000),
        },
      ],
      [
        'scaduto e usato',
        {
          usedAt: new Date(),
          revokedAt: null,
          expiresAt: new Date(Date.now() - 1000),
        },
      ],
    ])('%s -> invalid (nessuna revoca a catena)', async (_label, row) => {
      execute.mockResolvedValue({ raw: [] });
      repository.findOne.mockResolvedValue(row);
      await expect(service.rotate('x')).resolves.toEqual({ status: 'invalid' });
    });
  });

  it('revokeFamily: imposta revokedAt solo sui token non ancora revocati della famiglia', async () => {
    await service.revokeFamily('f1');
    const [where, set] = repository.update.mock.calls[0] as [
      Record<string, unknown>,
      Record<string, unknown>,
    ];
    expect(where.familyId).toBe('f1');
    expect(where.revokedAt).toBeDefined();
    expect(set.revokedAt).toBeInstanceOf(Date);
  });

  it('revokeAllForUser: revoca tutte le sessioni dell utente', async () => {
    await service.revokeAllForUser('u1');
    const [where] = repository.update.mock.calls[0] as [
      Record<string, unknown>,
    ];
    expect(where.userId).toBe('u1');
  });

  it('deleteExpired: ritorna quanti ne ha eliminati', async () => {
    repository.delete.mockResolvedValue({ affected: 4 });
    await expect(service.deleteExpired()).resolves.toBe(4);
  });
});
