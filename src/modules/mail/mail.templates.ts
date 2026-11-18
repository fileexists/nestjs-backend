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

/** "24 hours", "1 hour", "30 minutes": to tell the user how long the link is valid. */
export function humanizeTtl(ms: number): string {
  const minutes = Math.max(1, Math.round(ms / 60_000));
  if (minutes < 60) return minutes === 1 ? '1 minute' : `${minutes} minutes`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return hours === 1 ? '1 hour' : `${hours} hours`;
  const days = Math.round(hours / 24);
  return `${days} days`;
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
          `<p style="font-size:13px;color:#52606d">If the button does not work, copy this address into your browser:<br>${escapeHtml(action.url)}</p>`,
        ]
      : []),
    `</div>`,
  ].join('');
  return { subject, text, html };
}

export function verificationEmail(link: string, ttlMs: number): MailContent {
  return layout(
    'Confirm your email address',
    [
      'Hi,',
      `we received a registration request with this address. To activate the account, confirm your email and choose your password: the link is valid for ${humanizeTtl(ttlMs)} and can be used only once.`,
      'If this was not you, ignore this message: the account is not activated without confirmation.',
    ],
    { label: 'Confirm email and choose a password', url: link },
  );
}

export function registrationNoticeEmail(
  loginUrl: string,
  resetUrl: string,
): MailContent {
  return layout(
    'Registration attempt with your address',
    [
      'Hi,',
      'someone tried to register with this email address, but an account already exists for it.',
      'If it was you, sign in with your credentials or, if you do not remember your password, reset it. If it was not you, ignore this message: your account has not been changed.',
      `Reset your password: ${resetUrl}`,
    ],
    { label: 'Sign in', url: loginUrl },
  );
}

export function passwordResetEmail(link: string, ttlMs: number): MailContent {
  return layout(
    'Reset your password',
    [
      'Hi,',
      `we received a request to reset the password of this account. The link is valid for ${humanizeTtl(ttlMs)} and can be used only once; after the change all active sessions will be closed.`,
      'If this was not you, ignore this message: your password will not change.',
    ],
    { label: 'Reset your password', url: link },
  );
}
