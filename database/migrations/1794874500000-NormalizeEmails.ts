import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * B2 - Email case-insensitive.
 *
 * 1. Normalizza le email esistenti (trim + minuscolo).
 * 2. Gestisce i duplicati (stessa email a meno di maiuscole/spazi) SENZA perdere dati:
 *    - resta "canonico" l'account piu' affidabile: prima quello con email verificata,
 *      poi quello con Google collegato, poi il piu' vecchio;
 *    - gli altri NON vengono cancellati: la riga resta (permessi e dati compresi), ma
 *      l'email diventa `local+dup-<n>-<id>@dominio` (<n> = posizione nel gruppo, quindi unica), la password viene disattivata, l'email
 *      risulta non verificata e le sessioni sono invalidate (tokenVersion + 1);
 *    - ogni modifica e' registrata in `user_email_changes` (email e password originali)
 *      per un eventuale merge manuale e per il `down`. La tabella nasce solo se c'e'
 *      qualcosa da registrare: un database nuovo, o gia' in regola, non la riceve.
 * 3. Crea l'indice univoco su lower(email).
 *
 * Nota: TypeORM non sa descrivere indici su espressione ne conosce la tabella di
 * archivio: `migration:generate` li ignora (verificato), quindi non vanno dichiarati
 * nelle entita' e non compaiono come differenze.
 */
export class NormalizeEmails1794874500000 implements MigrationInterface {
  name = 'NormalizeEmails1794874500000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Un duplicato case-insensitive ha per forza almeno un'email non normalizzata (l'unicita'
    // esatta sull'email esiste gia'), quindi basta guardare questo.
    const [{ dirty }] = (await queryRunner.query(
      `SELECT EXISTS (SELECT 1 FROM "users" WHERE "email" <> lower(btrim("email"))) AS dirty`,
    )) as { dirty: boolean }[];

    if (dirty) {
      await this.archiveAndNormalize(queryRunner);
    }

    // Vincolo: nessun duplicato case-insensitive, nemmeno con SQL diretto.
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

    // 1) Duplicati: archivia (con i dati da ripristinare) e rinomina.
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

    // 2) Tutti gli altri: solo normalizzazione (con registro della modifica).
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

    // Senza registro non c'e' nulla da ripristinare (database nuovo o gia' in regola).
    const [{ archive }] = (await queryRunner.query(
      `SELECT to_regclass('public.user_email_changes') IS NOT NULL AS archive`,
    )) as { archive: boolean }[];
    if (!archive) return;

    // Ripristino in DUE fasi: il vincolo di unicita' esatto sull'email e' controllato riga per
    // riga, quindi prima si rimettono le email originali degli account canonici/normalizzati
    // (che oggi occupano la forma minuscola) e solo dopo quelle dei duplicati.
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
