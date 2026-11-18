import { parseFrontendUrls, parseOrigins } from './frontend-url';

describe('parseFrontendUrls', () => {
  it('accepts a single origin and normalizes it', () => {
    expect(parseFrontendUrls('http://localhost:3000')).toEqual([
      'http://localhost:3000',
    ]);
    expect(parseFrontendUrls('https://app.example.com/')).toEqual([
      'https://app.example.com',
    ]);
  });

  it('accepts several comma-separated origins, without duplicates, keeping the order', () => {
    expect(
      parseFrontendUrls(
        'https://app.example.com, https://admin.example.com,https://app.example.com',
      ),
    ).toEqual(['https://app.example.com', 'https://admin.example.com']);
  });

  it.each([
    ['', 'at least one URL'],
    ['   ,  ', 'at least one URL'],
    ['not a url', 'invalid URL'],
    ['javascript:alert(1)', 'non-http(s) scheme'],
    ['ftp://example.com', 'non-http(s) scheme'],
    ['https://user:pass@example.com', 'credentials'],
    ['https://example.com/path', 'path'],
    ['https://example.com/?next=evil', 'query'],
    ['https://example.com/#frag', 'fragment'],
  ])('rejects "%s" (%s)', (value) => {
    expect(() => parseFrontendUrls(value)).toThrow();
  });

  it('with requireHttps rejects http', () => {
    expect(() =>
      parseFrontendUrls('http://app.example.com', { requireHttps: true }),
    ).toThrow(/https/);
    expect(
      parseFrontendUrls('https://app.example.com', { requireHttps: true }),
    ).toEqual(['https://app.example.com']);
  });
});

describe('parseOrigins', () => {
  it('names the variable in the error messages', () => {
    expect(() => parseOrigins('', { name: 'CORS_ORIGIN' })).toThrow(
      /CORS_ORIGIN must contain/,
    );
    expect(() =>
      parseOrigins('http://a.example.com', {
        name: 'CORS_ORIGIN',
        requireHttps: true,
      }),
    ).toThrow(/CORS_ORIGIN must use https/);
    expect(() =>
      parseOrigins('https://a.example.com/x', { name: 'CORS_ORIGIN' }),
    ).toThrow(/CORS_ORIGIN must be a bare origin/);
  });

  it('keeps FRONTEND_URL as the default name', () => {
    expect(() => parseOrigins('nope')).toThrow(/FRONTEND_URL/);
  });
});
