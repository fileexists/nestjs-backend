/**
 * Integrazione con un SMTP VERO (Mailpit): il MailService reale spedisce l'email
 * di verifica e il token estratto dal messaggio conferma davvero l'account.
 *
 * Si esegue solo se E2E_MAILPIT_API e' impostata (in CI: service container mailpit;
 * in locale: `docker compose up -d mailpit` e
 * E2E_MAILPIT_API=http://localhost:8025 yarn test:e2e:db).
 */
import { createHarness, Harness } from './support/harness';
import { PASSWORD, http, register, userRow } from './support/api';

const MAILPIT_API = process.env.E2E_MAILPIT_API;
const suite = MAILPIT_API ? describe : describe.skip;

interface MailpitSummary {
  ID: string;
  Subject: string;
  To: { Address: string }[];
}

async function mailpit<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${MAILPIT_API}${path}`, init);
  if (!res.ok) throw new Error(`Mailpit ${path} -> ${res.status}`);
  const text = await res.text();
  // DELETE risponde "ok" in testo semplice, le GET rispondono JSON.
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as T;
  }
}

async function waitForMessage(to: string): Promise<MailpitSummary> {
  for (let attempt = 0; attempt < 50; attempt++) {
    const { messages } = await mailpit<{ messages: MailpitSummary[] }>(
      '/api/v1/messages',
    );
    const found = messages.find((m) => m.To.some((t) => t.Address === to));
    if (found) return found;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Nessuna email arrivata a ${to}`);
}

suite('SMTP reale (Mailpit)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness({ realMail: true });
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.reset();
    await mailpit('/api/v1/messages', { method: 'DELETE' });
  });

  it("la registrazione spedisce un'email vera il cui link conferma l'account", async () => {
    const email = 'smtp-user@example.com';
    expect((await register(h, email)).status).toBeLessThan(300);

    const summary = await waitForMessage(email);
    expect(summary.Subject).toMatch(/conferma/i);
    const message = await mailpit<{ Text: string; HTML: string }>(
      `/api/v1/message/${summary.ID}`,
    );
    const match =
      /http:\/\/localhost:3000\/verify-email\?token=([\w%.-]+)/.exec(
        message.Text,
      );
    expect(match).not.toBeNull();
    expect(message.HTML).toContain('/verify-email?token=');

    const token = decodeURIComponent(match![1]);
    expect(
      (
        await http(h)
          .post('/api/auth/verify-email')
          .send({ token, password: PASSWORD })
      ).status,
    ).toBe(200);
    expect((await userRow(h, email))?.emailVerifiedAt).not.toBeNull();
  });
});
