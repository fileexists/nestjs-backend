import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { AuthTokenService } from './auth-token.service';
import {
  AuthToken,
  AuthTokenType,
} from '../../common/entities/auth-token.entity';

describe('AuthTokenService', () => {
  const execute = jest.fn();
  const queryBuilder = {
    update: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    returning: jest.fn().mockReturnThis(),
    execute,
  };
  const repository = {
    delete: jest.fn(),
    insert: jest.fn(),
    findOne: jest.fn(),
    createQueryBuilder: jest.fn(() => queryBuilder),
  };
  let service: AuthTokenService;

  beforeEach(async () => {
    jest.clearAllMocks();
    repository.delete.mockResolvedValue({ affected: 0 });
    const module = await Test.createTestingModule({
      providers: [
        AuthTokenService,
        { provide: getRepositoryToken(AuthToken), useValue: repository },
      ],
    }).compile();
    service = module.get(AuthTokenService);
  });

  describe('issue', () => {
    it('stores only the SHA-256 of the token, never the token in clear', async () => {
      const raw = await service.issue(
        'user-1',
        AuthTokenType.EMAIL_VERIFICATION,
        60_000,
      );

      const inserted = (
        repository.insert.mock.calls as unknown[][]
      )[0][0] as Record<string, unknown>;
      expect(inserted.tokenHash).toBe(
        createHash('sha256').update(raw).digest('hex'),
      );
      expect(JSON.stringify(inserted)).not.toContain(raw);
      expect(raw.length).toBeGreaterThanOrEqual(40);
    });

    it('sets the expiry from the TTL', async () => {
      const before = Date.now();
      await service.issue('user-1', AuthTokenType.PASSWORD_RESET, 3_600_000);
      const { expiresAt } = (
        repository.insert.mock.calls as unknown[][]
      )[0][0] as {
        expiresAt: Date;
      };
      expect(expiresAt.getTime()).toBeGreaterThanOrEqual(before + 3_600_000);
      expect(expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 3_600_000);
    });

    it('invalidates the unused tokens of the same type before creating a new one', async () => {
      await service.issue('user-1', AuthTokenType.EMAIL_VERIFICATION, 60_000);
      expect(repository.delete).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-1',
          type: AuthTokenType.EMAIL_VERIFICATION,
        }),
      );
      expect(repository.delete.mock.invocationCallOrder[0]).toBeLessThan(
        repository.insert.mock.invocationCallOrder[0],
      );
    });

    it('generates different tokens on every call', async () => {
      const a = await service.issue(
        'user-1',
        AuthTokenType.EMAIL_VERIFICATION,
        60_000,
      );
      const b = await service.issue(
        'user-1',
        AuthTokenType.EMAIL_VERIFICATION,
        60_000,
      );
      expect(a).not.toBe(b);
    });
  });

  describe('consume', () => {
    it('returns the userId and looks up by hash, type, unused and not expired (atomic UPDATE)', async () => {
      execute.mockResolvedValue({ raw: [{ userId: 'user-1' }] });

      const userId = await service.consume(
        'raw-token',
        AuthTokenType.EMAIL_VERIFICATION,
      );

      expect(userId).toBe('user-1');
      const [condition, params] = queryBuilder.where.mock.calls[0] as [
        string,
        Record<string, string>,
      ];
      expect(condition).toContain('"usedAt" IS NULL');
      expect(condition).toContain('"expiresAt" > now()');
      expect(params).toEqual({
        hash: createHash('sha256').update('raw-token').digest('hex'),
        type: AuthTokenType.EMAIL_VERIFICATION,
      });
    });

    it('returns null if no row matches (unknown, expired or already used)', async () => {
      execute.mockResolvedValue({ raw: [] });
      await expect(
        service.consume('raw-token', AuthTokenType.EMAIL_VERIFICATION),
      ).resolves.toBeNull();
    });
  });

  describe('invalidateAll / deleteExpired / findLatestActive', () => {
    it("invalidateAll deletes the user's unused tokens", async () => {
      await service.invalidateAll('user-1');
      expect(repository.delete).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1' }),
      );
    });

    it('deleteExpired returns the number of rows removed', async () => {
      repository.delete.mockResolvedValue({ affected: 3 });
      await expect(service.deleteExpired()).resolves.toBe(3);
    });

    it('findLatestActive takes the most recent unused one', async () => {
      repository.findOne.mockResolvedValue(null);
      await service.findLatestActive(
        'user-1',
        AuthTokenType.EMAIL_VERIFICATION,
      );
      expect(repository.findOne).toHaveBeenCalledWith(
        expect.objectContaining({ order: { createdAt: 'DESC' } }),
      );
    });
  });
});
