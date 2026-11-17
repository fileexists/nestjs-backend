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

/**
 * Un refresh token emesso (uno per ogni rotazione). Tutti i token di una stessa
 * sessione condividono `familyId`: se ne viene ripresentato uno gia' usato
 * (furto) si revoca l'intera famiglia. Nel database c'e' solo lo SHA-256 del jti.
 */
@Entity('refresh_tokens')
@Index('IDX_refresh_tokens_family', ['familyId'])
@Index('IDX_refresh_tokens_user', ['userId'])
@Index('IDX_refresh_tokens_expires_at', ['expiresAt'])
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ type: 'varchar', length: 64, unique: true })
  jtiHash: string;

  @Column({ type: 'uuid' })
  familyId: string;

  /** Impostato alla rotazione: un token usato non puo' essere usato di nuovo. */
  @Column({ type: 'timestamptz', nullable: true })
  usedAt: Date | null;

  /** Impostato alla revoca (logout, reuse detection, logout-all). */
  @Column({ type: 'timestamptz', nullable: true })
  revokedAt: Date | null;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
