import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from './user.entity';

export enum AuthTokenType {
  EMAIL_VERIFICATION = 'email_verification',
  PASSWORD_RESET = 'password_reset',
  /** Non e' un token: registra l'invio dell'avviso "registrazione su email gia' presente" per limitarne la frequenza. */
  REGISTRATION_NOTICE = 'registration_notice',
}

/**
 * Token monouso con scadenza (verifica email, reset password).
 * Nel database si conserva solo lo SHA-256 del token: chi legge la tabella
 * non puo' ricostruire un link valido.
 */
@Entity('auth_tokens')
@Index('IDX_auth_tokens_user_type', ['userId', 'type'])
@Index('IDX_auth_tokens_expires_at', ['expiresAt'])
export class AuthToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ type: 'varchar', length: 30 })
  type: AuthTokenType;

  @Column({ type: 'varchar', length: 64, unique: true })
  tokenHash: string;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  usedAt: Date | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
