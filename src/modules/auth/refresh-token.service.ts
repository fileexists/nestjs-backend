import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { IsNull, LessThan, Repository } from 'typeorm';
import { RefreshToken } from '../../common/entities/refresh-token.entity';

export type RotationResult =
  /** Il token era valido ed e' stato marcato come usato: si puo' emettere il successivo. */
  | { status: 'rotated'; token: RefreshToken }
  /** Token gia' usato (furto o replay): va revocata la famiglia. */
  | { status: 'reused'; token: RefreshToken }
  /** Sconosciuto, revocato o scaduto. */
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
   * Marca il token come usato con UN solo UPDATE condizionale: di due richieste
   * concorrenti con lo stesso token una sola ottiene 'rotated', l'altra vede il
   * token gia' usato ('reused'). Niente race tra lettura e scrittura.
   */
  async rotate(jti: string): Promise<RotationResult> {
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

    const existing = await this.repository.findOne({
      where: { jtiHash: hash },
    });
    if (!existing) return { status: 'invalid' };
    if (existing.revokedAt || existing.expiresAt.getTime() <= Date.now()) {
      return { status: 'invalid' };
    }
    return existing.usedAt
      ? { status: 'reused', token: existing }
      : { status: 'invalid' };
  }

  /** Revoca tutti i token di una sessione (famiglia). */
  async revokeFamily(familyId: string): Promise<void> {
    await this.repository.update(
      { familyId, revokedAt: IsNull() },
      { revokedAt: new Date() },
    );
  }

  /** Revoca tutte le sessioni di un utente. */
  async revokeAllForUser(userId: string): Promise<void> {
    await this.repository.update(
      { userId, revokedAt: IsNull() },
      { revokedAt: new Date() },
    );
  }

  /** Elimina i token scaduti (quelli usati/revocati restano fino alla scadenza: servono al reuse detection). */
  async deleteExpired(): Promise<number> {
    const result = await this.repository.delete({
      expiresAt: LessThan(new Date()),
    });
    return result.affected ?? 0;
  }
}
