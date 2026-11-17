import { BadRequestException } from '@nestjs/common';
import {
  buildFrontendRedirect,
  resolveRedirectIndex,
} from './frontend-redirect';

const ORIGINS = ['https://app.example.com', 'https://admin.example.com:8443'];

describe('buildFrontendRedirect (C1)', () => {
  it('costruisce l URL di successo dalla prima origine con percorso fisso', () => {
    expect(buildFrontendRedirect(ORIGINS, 0, { status: 'success' })).toBe(
      'https://app.example.com/auth/callback?status=success',
    );
  });

  it('usa l origine all indice scelto e aggiunge il motivo in caso di errore', () => {
    expect(
      buildFrontendRedirect(ORIGINS, 1, {
        status: 'error',
        reason: 'email_unverified',
      }),
    ).toBe(
      'https://admin.example.com:8443/auth/callback?status=error&reason=email_unverified',
    );
  });

  it('un indice fuori range ricade sull origine predefinita (mai su valori esterni)', () => {
    expect(buildFrontendRedirect(ORIGINS, 99, { status: 'success' })).toMatch(
      /^https:\/\/app\.example\.com\//,
    );
    expect(buildFrontendRedirect(ORIGINS, -1, { status: 'success' })).toMatch(
      /^https:\/\/app\.example\.com\//,
    );
  });

  it('il motivo viene codificato nell URL', () => {
    const url = buildFrontendRedirect(ORIGINS, 0, {
      status: 'error',
      reason: 'a&b=c',
    });
    expect(new URL(url).searchParams.get('reason')).toBe('a&b=c');
    expect(new URL(url).origin).toBe('https://app.example.com');
  });
});

describe('resolveRedirectIndex (C1: nessun open redirect)', () => {
  it.each([
    ['https://app.example.com', 0],
    ['https://app.example.com/', 0],
    ['https://app.example.com/qualsiasi/percorso?x=1', 0],
    ['https://admin.example.com:8443', 1],
  ])('%s -> indice %i', (value, index) => {
    expect(resolveRedirectIndex(ORIGINS, value)).toBe(index);
  });

  it.each([
    'https://evil.com',
    'http://app.example.com',
    'https://app.example.com.evil.com',
    'https://app.example.com@evil.com',
    'https://evil.com/https://app.example.com',
    'https://admin.example.com',
    '//evil.com',
    'javascript:alert(1)',
    'data:text/html,x',
    '',
    'app.example.com',
  ])('rifiuta %j', (value) => {
    expect(() => resolveRedirectIndex(ORIGINS, value)).toThrow(
      BadRequestException,
    );
  });

  it.each([undefined, null, 42, {}, ['https://app.example.com']])(
    'rifiuta il valore non stringa %j',
    (value) => {
      expect(() => resolveRedirectIndex(ORIGINS, value)).toThrow(
        BadRequestException,
      );
    },
  );
});
