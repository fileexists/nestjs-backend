import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * A1 - Email verification.
 *
 * - users."emailVerifiedAt": when ownership of the email was proven.
 * - auth_tokens: single-use tokens with an expiry (email verification, password reset).
 *
 * Backfill: ONLY accounts created by Google (no password) are considered verified.
 * All the others (local and "combined") stay unverified: the password of a local account
 * was never tied to proof of owning the email and may have been chosen by an attacker
 * (pre-hijacking). To log in with the password they must verify the email; with Google
 * (email verified by Google) the account is "claimed" by the real owner.
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
