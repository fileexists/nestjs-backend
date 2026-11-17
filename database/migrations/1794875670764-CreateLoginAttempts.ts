import { MigrationInterface, QueryRunner } from "typeorm";

/**
 * D2 - Blocco progressivo per account: un record per identificatore (SHA-256 dell'email
 * normalizzata) con errori consecutivi, livello di blocco e scadenza del blocco.
 */
export class CreateLoginAttempts1794875670764 implements MigrationInterface {
    name = 'CreateLoginAttempts1794875670764'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "login_attempts" ("identifier" character varying(64) NOT NULL, "failedCount" integer NOT NULL DEFAULT '0', "lockLevel" integer NOT NULL DEFAULT '0', "lockedUntil" TIMESTAMP WITH TIME ZONE, "lastFailedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_5aee045e7a38bb7908bb87a056b" PRIMARY KEY ("identifier"))`);
        await queryRunner.query(`CREATE INDEX "IDX_login_attempts_locked_until" ON "login_attempts"  ("lockedUntil") `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "public"."IDX_login_attempts_locked_until"`);
        await queryRunner.query(`DROP TABLE "login_attempts"`);
    }

}
