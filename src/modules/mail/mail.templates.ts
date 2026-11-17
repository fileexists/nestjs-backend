export interface MailContent {
  subject: string;
  text: string;
  html: string;
}

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

/** "24 ore", "1 ora", "30 minuti": per dire all'utente quanto vale il link. */
export function humanizeTtl(ms: number): string {
  const minutes = Math.max(1, Math.round(ms / 60_000));
  if (minutes < 60) return minutes === 1 ? '1 minuto' : `${minutes} minuti`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return hours === 1 ? '1 ora' : `${hours} ore`;
  const days = Math.round(hours / 24);
  return `${days} giorni`;
}

function layout(
  subject: string,
  paragraphs: string[],
  action?: { label: string; url: string },
): MailContent {
  const text = [
    ...paragraphs,
    ...(action ? [`${action.label}: ${action.url}`] : []),
  ].join('\n\n');
  const html = [
    `<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#1f2933">`,
    ...paragraphs.map((p) => `<p>${escapeHtml(p)}</p>`),
    ...(action
      ? [
          `<p><a href="${escapeHtml(action.url)}" style="display:inline-block;padding:10px 18px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none">${escapeHtml(action.label)}</a></p>`,
          `<p style="font-size:13px;color:#52606d">Se il pulsante non funziona, copia questo indirizzo nel browser:<br>${escapeHtml(action.url)}</p>`,
        ]
      : []),
    `</div>`,
  ].join('');
  return { subject, text, html };
}

export function verificationEmail(link: string, ttlMs: number): MailContent {
  return layout(
    'Conferma il tuo indirizzo email',
    [
      'Ciao,',
      `abbiamo ricevuto una richiesta di registrazione con questo indirizzo. Per attivare l'account conferma la tua email: il link vale ${humanizeTtl(ttlMs)} e si può usare una sola volta.`,
      "Se non sei stato tu, ignora questo messaggio: senza conferma l'account non viene attivato.",
    ],
    { label: 'Conferma email', url: link },
  );
}
