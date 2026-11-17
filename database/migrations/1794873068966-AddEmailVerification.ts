import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * A1 - Verifica dell'email.
 *
 * - users."emailVerifiedAt": quando la proprieta' dell'email e' stata dimostrata.
 * - auth_tokens: token monouso con scadenza (verifica email, reset password).
 *
 * Backfill: sono considerati verificati SOLO gli account creati da Google
 * (nessuna password). Tutti gli altri (locali e "combined") restano non
 * verificati: la password di un account locale non e' mai stata associata a
 * una prova di possesso dell'email e potrebbe essere stata scelta da un
 * attaccante (pre-hijacking). Per accedere con la password dovranno verificare
 * l'email; con Google (email verificata da Google) l'account viene "rivendicato"
 * dal proprietario reale.
 */
export class AddEmailVerification1794873068966 implements MigrationInterface {
  name = 'AddEmailVerification1794873068966';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    await queryRunner.query(
      `ALTER TABLE "users" ADD "emailVerifiedAt" TIMESTAMP WITH TIME ZONE`,
    );
    await queryRunner.query(
      `UPDATE "users" SET "emailVerifiedAt" = "createdAt" WHERE "password" IS NULL AND "googleId" IS NOT NULL`,
    );
    await queryRunner.query(
      `CREATE TABLE "auth_tokens" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "userId" uuid NOT NULL, "type" character varying(30) NOT NULL, "tokenHash" character varying(64) NOT NULL, "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "usedAt" TIMESTAMP WITH TIME ZONE, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_323c4ca6708c6a8b81af2b4ee06" UNIQUE ("tokenHash"), CONSTRAINT "PK_41e9ddfbb32da18c4e85e45c2fd" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_auth_tokens_expires_at" ON "auth_tokens" ("expiresAt")`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_auth_tokens_user_type" ON "auth_tokens" ("userId", "type")`,
    );
    await queryRunner.query(
      `ALTER TABLE "auth_tokens" ADD CONSTRAINT "FK_c25fb956ebada4b256501585cca" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "auth_tokens" DROP CONSTRAINT "FK_c25fb956ebada4b256501585cca"`,
    );
    await queryRunner.query(`DROP INDEX "public"."IDX_auth_tokens_user_type"`);
    await queryRunner.query(`DROP INDEX "public"."IDX_auth_tokens_expires_at"`);
    await queryRunner.query(`DROP TABLE "auth_tokens"`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "emailVerifiedAt"`);
  }
}
