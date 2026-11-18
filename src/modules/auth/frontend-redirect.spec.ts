import { BadRequestException } from '@nestjs/common';
import {
  buildFrontendRedirect,
  resolveRedirectIndex,
} from './frontend-redirect';

const ORIGINS = ['https://app.example.com', 'https://admin.example.com:8443'];

describe('buildFrontendRedirect (C1)', () => {
  it('builds the success URL from the first origin with a fixed path', () => {
    expect(buildFrontendRedirect(ORIGINS, 0, { status: 'success' })).toBe(
      'https://app.example.com/auth/callback?status=success',
    );
  });

  it('uses the origin at the chosen index and adds the reason on error', () => {
    expect(
      buildFrontendRedirect(ORIGINS, 1, {
        status: 'error',
        reason: 'email_unverified',
      }),
    ).toBe(
      'https://admin.example.com:8443/auth/callback?status=error&reason=email_unverified',
    );
  });

  it('an out-of-range index falls back to the default origin (never to outside values)', () => {
    expect(buildFrontendRedirect(ORIGINS, 99, { status: 'success' })).toMatch(
      /^https:\/\/app\.example\.com\//,
    );
    expect(buildFrontendRedirect(ORIGINS, -1, { status: 'success' })).toMatch(
      /^https:\/\/app\.example\.com\//,
    );
  });

  it('the reason is encoded in the URL', () => {
    const url = buildFrontendRedirect(ORIGINS, 0, {
      status: 'error',
      reason: 'a&b=c',
    });
    expect(new URL(url).searchParams.get('reason')).toBe('a&b=c');
    expect(new URL(url).origin).toBe('https://app.example.com');
  });
});

describe('resolveRedirectIndex (C1: no open redirect)', () => {
  it.each([
    ['https://app.example.com', 0],
    ['https://app.example.com/', 0],
    ['https://app.example.com/qualsiasi/percorso?x=1', 0],
    ['https://admin.example.com:8443', 1],
  ])('%s -> index %i', (value, index) => {
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
  ])('rejects %j', (value) => {
    expect(() => resolveRedirectIndex(ORIGINS, value)).toThrow(
      BadRequestException,
    );
  });

  it.each([undefined, null, 42, {}, ['https://app.example.com']])(
    'rejects the non-string value %j',
    (value) => {
      expect(() => resolveRedirectIndex(ORIGINS, value)).toThrow(
        BadRequestException,
      );
    },
  );
});
