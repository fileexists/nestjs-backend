import { parseFrontendUrls } from './frontend-url';

describe('parseFrontendUrls', () => {
  it('accetta una singola origine e la normalizza', () => {
    expect(parseFrontendUrls('http://localhost:3000')).toEqual([
      'http://localhost:3000',
    ]);
    expect(parseFrontendUrls('https://app.example.com/')).toEqual([
      'https://app.example.com',
    ]);
  });

  it('accetta piu origini separate da virgola, senza duplicati, mantenendo l ordine', () => {
    expect(
      parseFrontendUrls(
        'https://app.example.com, https://admin.example.com,https://app.example.com',
      ),
    ).toEqual(['https://app.example.com', 'https://admin.example.com']);
  });

  it.each([
    ['', 'almeno un URL'],
    ['   ,  ', 'almeno un URL'],
    ['not a url', 'URL non valido'],
    ['javascript:alert(1)', 'schema non http(s)'],
    ['ftp://example.com', 'schema non http(s)'],
    ['https://user:pass@example.com', 'credenziali'],
    ['https://example.com/path', 'path'],
    ['https://example.com/?next=evil', 'query'],
    ['https://example.com/#frag', 'fragment'],
  ])('rifiuta "%s" (%s)', (value) => {
    expect(() => parseFrontendUrls(value)).toThrow();
  });

  it('con requireHttps rifiuta http', () => {
    expect(() =>
      parseFrontendUrls('http://app.example.com', { requireHttps: true }),
    ).toThrow(/https/);
    expect(
      parseFrontendUrls('https://app.example.com', { requireHttps: true }),
    ).toEqual(['https://app.example.com']);
  });
});
