import { Column, Entity, Index, PrimaryColumn } from 'typeorm';

/**
 * Tentativi di login falliti per ACCOUNT. La chiave e' lo SHA-256 dell'email
 * normalizzata (non l'email): vale anche per indirizzi inesistenti, cosi' il
 * blocco non rivela se un account esiste.
 */
@Entity('login_attempts')
@Index('IDX_login_attempts_locked_until', ['lockedUntil'])
export class LoginAttempt {
  @PrimaryColumn({ type: 'varchar', length: 64 })
  identifier: string;

  /** Errori consecutivi dall'ultimo blocco (o dall'inizio della finestra). */
  @Column({ type: 'int', default: 0 })
  failedCount: number;

  /** Quanti blocchi consecutivi: determina la durata del prossimo (raddoppia fino al massimo). */
  @Column({ type: 'int', default: 0 })
  lockLevel: number;

  @Column({ type: 'timestamptz', nullable: true })
  lockedUntil: Date | null;

  @Column({ type: 'timestamptz', default: () => 'now()' })
  lastFailedAt: Date;
}
