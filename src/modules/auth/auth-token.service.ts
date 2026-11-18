import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash, randomBytes } from 'crypto';
import { IsNull, LessThan, Repository } from 'typeorm';
import {
  AuthToken,
  AuthTokenType,
} from '../../common/entities/auth-token.entity';

/**
 * Single-use token with an expiry (email verification, password reset).
 * The plain token only exists in the email: the database only holds the SHA-256.
 */
@Injectable()
export class AuthTokenService {
  constructor(
    @InjectRepository(AuthToken)
    private readonly repository: Repository<AuthToken>,
  ) {}

  static hash(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
  }

  /** Creates a new token; the unused ones of the same type are invalidated. */
  async issue(
    userId: string,
    type: AuthTokenType,
    ttlMs: number,
  ): Promise<string> {
    const rawToken = randomBytes(32).toString('base64url');
    await this.repository.delete({ userId, type, usedAt: IsNull() });
    await this.repository.insert({
      userId,
      type,
      tokenHash: AuthTokenService.hash(rawToken),
      expiresAt: new Date(Date.now() + ttlMs),
    });
    return rawToken;
  }

  /**
   * Consumes the token atomically (a single conditional UPDATE): two concurrent
   * requests with the same token cannot both succeed.
   * Returns the userId, or null if the token is unknown, expired or already used.
   */
  async consume(rawToken: string, type: AuthTokenType): Promise<string | null> {
    const result = await this.repository
      .createQueryBuilder()
      .update(AuthToken)
      .set({ usedAt: () => 'now()' })
      .where(
        `"tokenHash" = :hash AND "type" = :type AND "usedAt" IS NULL AND "expiresAt" > now()`,
        { hash: AuthTokenService.hash(rawToken), type },
      )
      .returning('"userId"')
      .execute();
    const rows = result.raw as { userId: string }[];
    return rows[0]?.userId ?? null;
  }

  /** Most recent unused token (used to limit resends). */
  findLatestActive(
    userId: string,
    type: AuthTokenType,
  ): Promise<AuthToken | null> {
    return this.repository.findOne({
      where: { userId, type, usedAt: IsNull() },
      order: { createdAt: 'DESC' },
    });
  }

  /** Invalidates all the user's unused tokens (optionally of a single type). */
  async invalidateAll(userId: string, type?: AuthTokenType): Promise<void> {
    await this.repository.delete(
      type ? { userId, type, usedAt: IsNull() } : { userId, usedAt: IsNull() },
    );
  }

  /** Periodic cleanup: deletes the expired tokens. Returns how many were removed. */
  async deleteExpired(): Promise<number> {
    const result = await this.repository.delete({
      expiresAt: LessThan(new Date()),
    });
    return result.affected ?? 0;
  }
}
