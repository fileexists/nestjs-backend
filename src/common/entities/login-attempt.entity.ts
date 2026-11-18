import { Column, Entity, Index, PrimaryColumn } from 'typeorm';

/**
 * Failed login attempts per ACCOUNT. The key is the SHA-256 of the normalized email
 * (not the email): it also applies to non-existent addresses, so the
 * lock does not reveal whether an account exists.
 */
@Entity('login_attempts')
@Index('IDX_login_attempts_locked_until', ['lockedUntil'])
export class LoginAttempt {
  @PrimaryColumn({ type: 'varchar', length: 64 })
  identifier: string;

  /** Consecutive failures since the last lock (or since the start of the window). */
  @Column({ type: 'int', default: 0 })
  failedCount: number;

  /** How many consecutive locks: determines the length of the next one (doubles up to the maximum). */
  @Column({ type: 'int', default: 0 })
  lockLevel: number;

  @Column({ type: 'timestamptz', nullable: true })
  lockedUntil: Date | null;

  @Column({ type: 'timestamptz', default: () => 'now()' })
  lastFailedAt: Date;
}
