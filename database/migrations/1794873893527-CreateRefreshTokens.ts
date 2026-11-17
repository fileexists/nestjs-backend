import { MigrationInterface, QueryRunner } from "typeorm";

/**
 * B1 - Rotazione reale dei refresh token: un record per ogni token emesso
 * (hash del jti, famiglia di sessione, usato/revocato, scadenza).
 */
export class CreateRefreshTokens1794873893527 implements MigrationInterface {
    name = 'CreateRefreshTokens1794873893527'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "refresh_tokens" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "userId" uuid NOT NULL, "jtiHash" character varying(64) NOT NULL, "familyId" uuid NOT NULL, "usedAt" TIMESTAMP WITH TIME ZONE, "revokedAt" TIMESTAMP WITH TIME ZONE, "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_73b55a937d55dfbcd90b7dde272" UNIQUE ("jtiHash"), CONSTRAINT "PK_7d8bee0204106019488c4c50ffa" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_refresh_tokens_expires_at" ON "refresh_tokens"  ("expiresAt") `);
        await queryRunner.query(`CREATE INDEX "IDX_refresh_tokens_user" ON "refresh_tokens"  ("userId") `);
        await queryRunner.query(`CREATE INDEX "IDX_refresh_tokens_family" ON "refresh_tokens"  ("familyId") `);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD CONSTRAINT "FK_610102b60fea1455310ccd299de" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP CONSTRAINT "FK_610102b60fea1455310ccd299de"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_refresh_tokens_family"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_refresh_tokens_user"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_refresh_tokens_expires_at"`);
        await queryRunner.query(`DROP TABLE "refresh_tokens"`);
    }

}
