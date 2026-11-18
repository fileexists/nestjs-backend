import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * B2 - Case-insensitive email.
 *
 * 1. Normalizes the existing emails (trim + lowercase).
 * 2. Handles duplicates (same email apart from case/spaces) WITHOUT losing data:
 *    - the most trustworthy account stays "canonical": first the one with a verified email,
 *      then the one with Google linked, then the oldest;
 *    - the others are NOT deleted: the row stays (permissions and data included), but
 *      the email becomes `local+dup-<n>-<id>@domain` (<n> = position in the group, so it is unique),
 *      the password is disabled, the email is marked unverified and the sessions are
 *      invalidated (tokenVersion + 1);
 *    - every change is recorded in `user_email_changes` (original email and password)
 *      for a possible manual merge and for `down`. The table is only created when there is
 *      something to record: a new or already tidy database does not get it.
 * 3. Creates the unique index on lower(email).
 *
 * Note: TypeORM can neither describe expression indexes nor knows the archive table:
 * `migration:generate` ignores them (verified), so they must not be declared in the
 * entities and they do not show up as differences.
 */
export class NormalizeEmails1794874500000 implements MigrationInterface {
  name = 'NormalizeEmails1794874500000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // A case-insensitive duplicate necessarily has at least one non-normalized email (exact
    // uniqueness on the email already exists), so looking at this is enough.
    const [{ dirty }] = (await queryRunner.query(
      `SELECT EXISTS (SELECT 1 FROM "users" WHERE "email" <> lower(btrim("email"))) AS dirty`,
    )) as { dirty: boolean }[];

    if (dirty) {
      await this.archiveAndNormalize(queryRunner);
    }

    // Constraint: no case-insensitive duplicates, not even with direct SQL.
    await queryRunner.query(
      `CREATE UNIQUE INDEX "UQ_users_email_lower" ON "users" (lower("email"))`,
    );
  }

  private async archiveAndNormalize(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "user_email_changes" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId" uuid NOT NULL,
        "originalEmail" character varying(255) NOT NULL,
        "newEmail" character varying(255) NOT NULL,
        "reason" character varying(20) NOT NULL,
        "canonicalUserId" uuid,
        "originalPasswordHash" character varying(255),
        "originalEmailVerifiedAt" TIMESTAMP WITH TIME ZONE,
        "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
        CONSTRAINT "PK_user_email_changes" PRIMARY KEY ("id")
      )
    `);

    // 1) Duplicates: archive (with the data needed to restore them) and rename.
    await queryRunner.query(`
      INSERT INTO "user_email_changes"
        ("userId", "originalEmail", "newEmail", "reason", "canonicalUserId",
         "originalPasswordHash", "originalEmailVerifiedAt")
      SELECT r.id, r.email,
             CASE WHEN strpos(r.norm, '@') > 0
                  THEN split_part(r.norm, '@', 1) || '+dup-' || r.rn || '-' || substr(replace(r.id::text, '-', ''), 1, 8)
                       || '@' || substr(r.norm, strpos(r.norm, '@') + 1)
                  ELSE r.norm || '+dup-' || r.rn || '-' || substr(replace(r.id::text, '-', ''), 1, 8)
             END,
             'duplicate', r.canonical_id, r.password, r."emailVerifiedAt"
        FROM (
          SELECT u.id, u.email, u.password, u."emailVerifiedAt",
                 lower(btrim(u.email)) AS norm,
                 row_number() OVER w AS rn,
                 first_value(u.id) OVER w AS canonical_id
            FROM "users" u
          WINDOW w AS (
            PARTITION BY lower(btrim(u.email))
            ORDER BY (u."emailVerifiedAt" IS NOT NULL) DESC,
                     (u."googleId" IS NOT NULL) DESC,
                     u."createdAt" ASC, u.id ASC
          )
        ) r
       WHERE r.rn > 1
    `);
    await queryRunner.query(`
      UPDATE "users" u
         SET "email" = c."newEmail",
             "password" = NULL,
             "emailVerifiedAt" = NULL,
             "tokenVersion" = u."tokenVersion" + 1
        FROM "user_email_changes" c
       WHERE c."userId" = u.id AND c."reason" = 'duplicate'
    `);

    // 2) Everyone else: normalization only (with a record of the change).
    await queryRunner.query(`
      INSERT INTO "user_email_changes" ("userId", "originalEmail", "newEmail", "reason")
      SELECT u.id, u.email, lower(btrim(u.email)), 'normalized'
        FROM "users" u
       WHERE u.email <> lower(btrim(u.email))
    `);
    await queryRunner.query(
      `UPDATE "users" SET "email" = lower(btrim("email")) WHERE "email" <> lower(btrim("email"))`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."UQ_users_email_lower"`);

    // Without an archive there is nothing to restore (new or already tidy database).
    const [{ archive }] = (await queryRunner.query(
      `SELECT to_regclass('public.user_email_changes') IS NOT NULL AS archive`,
    )) as { archive: boolean }[];
    if (!archive) return;

    // Restore in TWO phases: the exact uniqueness constraint on the email is checked row by
    // row, so first the original emails of the canonical/normalized accounts are put back
    // (they now hold the lowercase form) and only then those of the duplicates.
    await queryRunner.query(`
      UPDATE "users" u
         SET "email" = c."originalEmail"
        FROM "user_email_changes" c
       WHERE c."userId" = u.id AND c."reason" = 'normalized'
    `);
    await queryRunner.query(`
      UPDATE "users" u
         SET "email" = c."originalEmail",
             "password" = c."originalPasswordHash",
             "emailVerifiedAt" = c."originalEmailVerifiedAt"
        FROM "user_email_changes" c
       WHERE c."userId" = u.id AND c."reason" = 'duplicate'
    `);
    await queryRunner.query(`DROP TABLE "user_email_changes"`);
  }
}
