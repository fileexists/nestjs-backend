# Progetto: autenticazione Bearer per le API pubbliche (widget)

> **Stato: solo progettazione.** Nulla di quanto descritto qui è implementato. Il flusso a cookie per lo
> staff (login, refresh, logout, Google) **non cambia**.

## 1. Problema

Il widget gira sui siti dei clienti, quindi su un **dominio diverso** da quello dell'API. Le richieste del
widget sono *cross-site*: i cookie `sameSite=lax` (quelli usati oggi per lo staff) **non vengono inviati**.
Servono quindi credenziali che viaggino in un header, legate al **negozio** e **separate dal login utente**.

Non si risolve con `SameSite=None; Secure`: i browser bloccano sempre più spesso i cookie di terze parti
(Safari ITP, Chrome), esporrebbe a CSRF e legherebbe il widget a una sessione utente che non esiste (il
visitatore del sito del cliente non è un utente dello staff).

## 2. Obiettivi e non-obiettivi

| Obiettivo | Non-obiettivo |
| --- | --- |
| Identificare **quale negozio** chiama le API pubbliche | Autenticare il singolo visitatore finale (fuori ambito) |
| Chiavi revocabili, ruotabili, con scope minimi | Sostituire o modificare il login staff |
| Funzionare senza cookie, da qualsiasi origine autorizzata | Proteggere da chi controlla il sito del cliente |
| Limitare l'abuso (rate limit per chiave) | Garantire che una chiave pubblica resti segreta (non può) |

## 3. Modello: due tipi di chiave

| | **Publishable** (`pk_live_…`) | **Secret** (`sk_live_…`) |
| --- | --- | --- |
| Dove vive | Incorporata nel widget, **visibile a chiunque** | Solo sul server del cliente |
| Cosa può fare | Solo operazioni di lettura/azioni del widget | Integrazioni server-to-server, scope più ampi |
| Controllo `Origin` | **Sì**, lista di origini consentite per chiave | No (non arriva da un browser) |
| Esposizione accettata | Alta: va pensata come pubblica | Mai nel browser, mai nei log |

Una chiave `pk_` **non è un segreto**: chiunque apra gli strumenti del browser la legge. La sua protezione è
(1) privilegi minimi, (2) vincolo di origine, (3) rate limit, (4) revoca rapida. Per questo non si usa per
nulla di sensibile: operazioni sensibili richiedono `sk_` lato server.

### Formato

```
pk_live_<prefisso 8 car>_<segreto 32 byte base64url>
```

- il **prefisso** non segreto serve a riconoscere la chiave in dashboard e nei log;
- nel database si salva solo `SHA-256(chiave completa)`: la chiave ha 256 bit di entropia, quindi un hash
  veloce è sufficiente (bcrypt qui sarebbe solo un costo per ogni richiesta);
- il prefisso `sk_live_` rende la chiave riconoscibile dai sistemi di *secret scanning* (es. GitHub).

## 4. Dati

Oggi **non esiste** un'entità negozio: va definita (`stores`). Tabelle nuove, con migrazioni in
`database/migrations/` (mai `synchronize`):

```
stores            id uuid PK, name, createdAt, …
api_keys          id uuid PK
                  storeId uuid FK → stores ON DELETE CASCADE
                  name varchar            -- etichetta scelta dallo staff
                  type  'publishable' | 'secret'
                  keyPrefix varchar(8)    -- non segreto
                  keyHash   varchar(64) UNIQUE  -- sha256 della chiave completa
                  scopes text[]           -- es. widget:read, widget:write
                  allowedOrigins text[]   -- solo publishable; origini esatte (https://shop.example.com)
                  rateLimitPerMinute int
                  expiresAt timestamptz NULL
                  lastUsedAt timestamptz NULL
                  revokedAt  timestamptz NULL
                  createdBy uuid FK → users
                  createdAt timestamptz
api_key_events    audit: creata / revocata / usata da IP nuovo / richiesta con Origin non ammessa
```

Una chiave è valida se `revokedAt IS NULL` e `expiresAt` nel futuro o nullo.

## 5. Trasporto e verifica

```
Authorization: Bearer pk_live_ab12cd34_…
Origin: https://shop.example.com          (inviato dal browser)
```

1. Il guard estrae il Bearer, calcola `SHA-256`, cerca `keyHash` (indice univoco) con un confronto a tempo
   costante; chiave inesistente, revocata o scaduta → **sempre lo stesso 401**, senza dire quale caso.
2. Per le `pk_`: l'header `Origin` **deve** essere in `allowedOrigins` della chiave (confronto esatto, niente
   wildcard sui sottodomini); altrimenti 403 e un evento di audit. Richiesta senza `Origin` con `pk_` → 403.
3. Si controllano gli **scope** richiesti dalla rotta.
4. Si applica il rate limit **per chiave** (non solo per IP) e si aggiorna `lastUsedAt` in modo asincrono.
5. Si valorizzano `request.apiKey = { id, storeId, scopes }`: da qui in poi il codice ragiona **per negozio**.

Le chiavi **non** viaggiano mai in query string (finirebbero nei log e nel `Referer`) e non si accettano
cookie su queste rotte.

## 6. CORS

La *preflight* (`OPTIONS`) **non porta l'`Authorization`**, quindi non si può risolvere la chiave per decidere
l'origine. Soluzione in due livelli:

- livello CORS: lista globale = **unione delle `allowedOrigins` delle chiavi attive** (cache con TTL 30–60 s),
  solo per le rotte `/public/v1/*`; risposta con `Access-Control-Allow-Origin: <origine>` (mai `*` con
  credenziali), `Access-Control-Allow-Headers: Authorization, Content-Type`, `Vary: Origin`;
- livello chiave: il controllo puntuale del punto 5.2 sulla richiesta vera.

**Niente `Access-Control-Allow-Credentials`** su queste rotte: non ci sono cookie. Il CORS dello staff
(`CORS_ORIGIN`, con `credentials: true`) resta separato e invariato.

## 7. Separazione dal login utente

- Namespace distinto: **`/api/public/v1/*`** per il widget, `/api/*` come oggi per lo staff.
- Un **guard dedicato** (`ApiKeyGuard`, decoratore `@ApiKeyAuth('scope')`) accanto all'`AuthGuard` esistente.
  Una rotta è *o* staff *o* pubblica, mai entrambe; l'`AuthGuard` globale salta le rotte `@ApiKeyAuth`.
- Un JWT staff **non** è accettato su `/public/v1` e una chiave API **non** autentica rotte staff
  (claim/prefisso diversi: non si possono confondere).
- La gestione delle chiavi è **una funzione dello staff**, quindi usa il flusso a cookie esistente e i
  permessi (`@Permissions('ADMIN')` o un permesso `STORE_ADMIN` dedicato).

## 8. Gestione delle chiavi (staff)

| Endpoint | Cosa fa |
| --- | --- |
| `POST /api/stores/:id/api-keys` | Crea la chiave. La mostra **una sola volta** in chiaro |
| `GET /api/stores/:id/api-keys` | Elenco: prefisso, tipo, scope, origini, `lastUsedAt`. Mai la chiave |
| `PATCH /api/stores/:id/api-keys/:keyId` | Cambia nome, scope, origini, limite |
| `DELETE /api/stores/:id/api-keys/:keyId` | Revoca (`revokedAt`), effetto entro il TTL della cache (≤ 60 s) |

**Rotazione senza interruzioni:** un negozio può avere due chiavi attive per tipo; si crea la nuova, si
aggiorna il widget, si revoca la vecchia. Scadenza (`expiresAt`) opzionale, consigliata per le `sk_`.

## 9. Sessioni brevi per il widget (consigliato, fase 2)

Una `pk_` fissa e pubblica è facile da copiare e riusare. Per ridurre l'esposizione:

1. il widget chiama `POST /api/public/v1/sessions` con la `pk_` (e `Origin` valida);
2. riceve un **token Bearer a vita breve** (5–15 min), firmato, con `storeId`, scope e id chiave;
3. le chiamate successive usano quel token; alla scadenza ne chiede uno nuovo.

Così la `pk_` si usa pochissimo, la revoca della chiave ferma anche i token già emessi (si controlla l'id chiave
a ogni richiesta, come oggi `tokenVersion`) e si può aggiungere una verifica anti-bot proprio su questo
endpoint (CAPTCHA/Turnstile) senza toccare il resto.

## 10. Sicurezza: riepilogo

- hash `SHA-256` della chiave, confronto a tempo costante, nessuna chiave in chiaro nei log o nel database;
- risposte uniformi (stesso 401) e nessun indizio su chiavi esistenti;
- rate limit per chiave + per IP; quote e allarmi su picchi anomali;
- `Cache-Control: no-store` sulle risposte che contengono una chiave appena creata;
- solo HTTPS; `Referrer-Policy` e CSP già gestiti da Helmet;
- revoca rapida (cache breve) e audit di creazione, revoca e usi sospetti;
- limite onesto: il controllo `Origin` ferma l'uso da **altri siti nel browser**, non da uno script server-side
  (può mandare l'header che vuole). Per questo la `pk_` ha privilegi minimi e rate limit, e le azioni
  sensibili stanno dietro a `sk_`.

## 11. Piano di implementazione (fasi)

1. **Dati**: `stores`, `api_keys`, `api_key_events` + migrazioni + entità.
2. **Servizio chiavi**: generazione, hash, creazione/revoca/rotazione, cache di validazione.
3. **Guard e decoratore**: `ApiKeyGuard`, `@ApiKeyAuth()`, rate limit per chiave (tracker personalizzato del throttler).
4. **CORS dinamico** per `/public/v1/*` e verifica dell'`Origin` per chiave.
5. **Endpoint di gestione** per lo staff (+ Swagger).
6. **Sessioni brevi** del widget (+ anti-bot).
7. **Osservabilità**: metriche per chiave, allarmi, retention dell'audit.

## 12. Test previsti

- unitari: formato/hash delle chiavi, confronto, scope, `Origin` esatto (niente `evil.com`, niente
  `shop.example.com.evil.com`), cache e revoca;
- e2e su PostgreSQL vero: chiave valida/scaduta/revocata (stesso 401), `Origin` non ammessa, scope mancante,
  rate limit per chiave, preflight CORS, un JWT staff **non** passa su `/public/v1` e viceversa, rotazione con
  due chiavi attive, chiave mostrata una volta sola;
- sicurezza: nessuna chiave nei log, nessun cookie accettato sulle rotte pubbliche.

## 13. Alternative scartate

| Alternativa | Perché no |
| --- | --- |
| Cookie `SameSite=None; Secure` | Cookie di terze parti sempre più bloccati; espone a CSRF; non ha senso per un visitatore non utente |
| OAuth2 *client credentials* | Adatto a server-to-server, ma il widget gira nel browser: servirebbe comunque una credenziale pubblica |
| Un solo JWT firmato per negozio | Non revocabile senza stato lato server e lungo da ruotare |
| mTLS | Impossibile da usare da un widget nel browser |

## 14. Domande aperte

1. Quali sono le operazioni del widget (scope reali)? Servono solo letture o anche scritture (es. invio messaggi)?
2. Un negozio può avere più domini (staging, produzione)? Se sì, `allowedOrigins` multiple per chiave.
3. Serve distinguere i **visitatori** del sito del cliente (es. conversazioni) o basta il negozio?
4. Quote/piani per negozio (rate limit diversi per tariffa)?
5. Chi può creare chiavi: solo `ADMIN` o anche il titolare del negozio (permesso dedicato)?
