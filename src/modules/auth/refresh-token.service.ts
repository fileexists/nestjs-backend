import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { IsNull, LessThan, Repository } from 'typeorm';
import { RefreshToken } from '../../common/entities/refresh-token.entity';

export type RotationResult =
  /** The token was valid and has been marked as used: the next one can be issued. */
  | { status: 'rotated'; token: RefreshToken }
  /**
   * Token already used. `withinGrace` (judged by the database clock) tells a parallel request made
   * just after the rotation (harmless) from a real replay (theft: the family must be revoked).
   */
  | { status: 'reused'; token: RefreshToken; withinGrace: boolean }
  /** Unknown, revoked or expired. */
  | { status: 'invalid' };

export interface NewRefreshToken {
  userId: string;
  jti: string;
  familyId: string;
  expiresAt: Date;
}

@Injectable()
export class RefreshTokenService {
  constructor(
    @InjectRepository(RefreshToken)
    private readonly repository: Repository<RefreshToken>,
  ) {}

  static hash(jti: string): string {
    return createHash('sha256').update(jti).digest('hex');
  }

  async create(data: NewRefreshToken): Promise<void> {
    await this.repository.insert({
      userId: data.userId,
      familyId: data.familyId,
      jtiHash: RefreshTokenService.hash(data.jti),
      expiresAt: data.expiresAt,
    });
  }

  /**
   * Marks the token as used with a SINGLE conditional UPDATE: of two concurrent
   * requests with the same token only one gets 'rotated', the other sees the
   * token already used ('reused'). No race between read and write.
   *
   * Whether a reuse is inside the grace period, and whether the token has expired, is decided
   * by the database clock (`now()`), not by the application's: the two can drift apart.
   */
  async rotate(jti: string, graceSeconds = 0): Promise<RotationResult> {
    const hash = RefreshTokenService.hash(jti);
    const result = await this.repository
      .createQueryBuilder()
      .update(RefreshToken)
      .set({ usedAt: () => 'now()' })
      .where(
        `"jtiHash" = :hash AND "usedAt" IS NULL AND "revokedAt" IS NULL AND "expiresAt" > now()`,
        { hash },
      )
      .returning('*')
      .execute();

    const rotated = (result.raw as RefreshToken[])[0];
    if (rotated) return { status: 'rotated', token: rotated };

    const rows = await this.repository.query<
      (RefreshToken & { withinGrace: boolean | null; expired: boolean })[]
    >(
      `SELECT rt.*,
              rt."usedAt" > now() - make_interval(secs => $2) AS "withinGrace",
              rt."expiresAt" <= now() AS "expired"
         FROM "refresh_tokens" rt
        WHERE rt."jtiHash" = $1`,
      [hash, graceSeconds],
    );

    const existing = rows[0];
    if (!existing || existing.revokedAt || existing.expired) {
      return { status: 'invalid' };
    }
    return existing.usedAt
      ? {
          status: 'reused',
          token: existing,
          withinGrace: existing.withinGrace === true,
        }
      : { status: 'invalid' };
  }

  /**
   * State of the session an access token belongs to, with ONE query (index on the family):
   * the row exists only if the family belongs to the given user, is not revoked and is not expired.
   * It also returns the user's `tokenVersion`, so whoever checks the session does not have to read
   * `users` separately. After a rotation the old tokens have `usedAt` but not `revokedAt`: the
   * family stays active as long as a valid one exists (the last issued).
   */
  async findActiveSession(
    userId: string,
    familyId: string,
  ): Promise<{ tokenVersion: number } | null> {
    const row = await this.repository
      .createQueryBuilder('rt')
      .innerJoin('rt.user', 'u')
      .select('u.tokenVersion', 'tokenVersion')
      .where('rt.familyId = :familyId AND rt.userId = :userId', {
        familyId,
        userId,
      })
      .andWhere('rt.revokedAt IS NULL AND rt.expiresAt > now()')
      .limit(1)
      .getRawOne<{ tokenVersion: number }>();
    return row ?? null;
  }

  /** Revokes all the tokens of a session (family). */
  async revokeFamily(familyId: string): Promise<void> {
    await this.repository.update(
      { familyId, revokedAt: IsNull() },
      { revokedAt: new Date() },
    );
  }

  /** Revokes all the sessions of a user. */
  async revokeAllForUser(userId: string): Promise<void> {
    await this.repository.update(
      { userId, revokedAt: IsNull() },
      { revokedAt: new Date() },
    );
  }

  /** Deletes the expired tokens (used/revoked ones stay until they expire: reuse detection needs them). */
  async deleteExpired(): Promise<number> {
    const result = await this.repository.delete({
      expiresAt: LessThan(new Date()),
    });
    return result.affected ?? 0;
  }
}
