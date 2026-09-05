# ShareText

Share a piece of text that can only be read a set number of times, then destroys itself.

Text is encrypted **in the browser**. The server stores ciphertext it has no way to read, counts down the remaining reads, and deletes the record when the budget runs out. Google sign-in is required to create and to read.

Runs at `smartlydone.ai/sharetext`.

---

## How it works

```
CREATE                                          READ
------                                          ----
browser: key = 32 random bytes                  browser: split key, verify checksum
browser: ct = AES-256-GCM(key, text)               |  (a mistyped key stops here — no request)
    |                                              v
    |  POST { ct, iv, maxViews, ttl }           POST /api/paste/:id/reveal
    v      ^^^ no key, ever                         |
server:  store, return id                       server: atomic decrement, return ct
    |                                              |  deletes the record at zero
    v                                              v
share key = <id>.<secret>.<checksum>            browser: decrypt locally with secret
            ^^^^ server knows                   plaintext never leaves the browser
                 ^^^^^^ server never sees
```

The **share key** is one string, around 70 characters:

| Part | Bytes | Goes to the server? |
|---|---|---|
| `id` | 16 random | Yes — it is the Redis lookup key |
| `secret` | 32 random | **Never.** This is the AES key |
| `checksum` | 2 | No — a client-side typo guard |

Because the secret half never reaches the server, a full dump of Redis — or of a backup, or of the host — yields nothing but opaque bytes. Losing the key means the text is unrecoverable by anyone, including the operator. That is the point.

### Two decisions worth knowing about

**A read is spent when the ciphertext is released, not when the browser reports a successful decrypt.** Decryption happens client-side, so a "I decrypted it" confirmation from the client is unenforceable — a malicious reader would simply never send one and read forever. Once the bytes leave the server, the read is counted.

That would ordinarily make a typo expensive, so the share key carries a 2-byte checksum. The browser validates it *before* any network call: a mistyped key is rejected locally and costs nothing.

**Reveal is a single Lua script.** Read-then-decrement over two round trips is a race — two concurrent reveals of a one-read paste would both see `views = 1` and both succeed. Redis runs scripts to completion on one thread, so bundling read + decrement + delete makes over-reading impossible under any amount of concurrency. `tests/pasteStore.test.ts` fires 50 simultaneous reveals at a one-read paste and asserts exactly one wins.

---

## Running it locally

```bash
docker compose up -d          # Redis on :6380
bun install
cp .env.example .env          # then fill in the values below
bun run build
bun run start                 # http://localhost:3000/sharetext/
```

For hot reload, run the API and the Vite dev server side by side:

```bash
bun run dev:server            # API on :3000
bun run dev                   # UI on :5173/sharetext/, proxying to :3000
```

### Before you have Google credentials

```bash
ALLOW_DEV_LOGIN=true bun run start
```

adds a local sign-in box that mints a session for any address you type. It is double-gated — it needs the explicit opt-in *and* a non-production build — so it cannot be switched on in production by environment alone.

### Redis is on 6380, not 6379

`docker-compose.yml` publishes on **6380** because 6379 is so often already taken by another project's Redis. The app defaults to 6380 to match, so `docker compose up -d && bun test` works with no `.env` at all. Override with `REDIS_PORT` if you prefer.

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `3000` | |
| `BASE_PATH` | `/sharetext` | Sub-path the app is mounted at |
| `PUBLIC_ORIGIN` | `http://localhost:$PORT` | Public origin; also decides whether cookies are `Secure` |
| `SESSION_SECRET` | — | **Required in production**, min 32 chars. `openssl rand -hex 32` |
| `GOOGLE_CLIENT_ID` | — | |
| `GOOGLE_CLIENT_SECRET` | — | |
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6380` | |
| `ALLOW_DEV_LOGIN` | unset | `true` enables the local bypass; ignored in production |
| `NODE_ENV` | — | `production` enforces `SESSION_SECRET` and disables dev login |

### Google OAuth setup

1. Google Cloud Console → **APIs & Services** → **Credentials** → **Create credentials** → **OAuth client ID** → **Web application**.
2. Under *Authorized redirect URIs* add exactly `<PUBLIC_ORIGIN><BASE_PATH>/auth/google/callback`:
   - production — `https://smartlydone.ai/sharetext/auth/google/callback`
   - local — `http://localhost:3000/sharetext/auth/google/callback`
3. Copy the client ID and secret into `.env`.

The redirect URI must match character for character, trailing slash included, or Google returns `redirect_uri_mismatch`.

---

## Deploying to smartlydone.ai/sharetext

```bash
NODE_ENV=production \
PUBLIC_ORIGIN=https://smartlydone.ai \
BASE_PATH=/sharetext \
SESSION_SECRET=$(openssl rand -hex 32) \
bun run build && bun run start
```

Behind a reverse proxy, forward `/sharetext/*` to the app **without stripping the prefix** — the app owns its own mount point. For Caddy:

```
smartlydone.ai {
  handle /sharetext/* {
    reverse_proxy localhost:3000
  }
}
```

**HTTPS is not optional.** `crypto.subtle` only exists in a secure context; over plain HTTP on a real hostname the browser does not expose it and no encryption is possible. The app detects this and refuses to run rather than pretending to work.

---

## API

All routes sit under `BASE_PATH` and require a session.

| Method | Path | |
|---|---|---|
| `POST` | `/api/paste` | `{ ct, iv, maxViews, ttlSeconds }` → `{ id, expiresAt, maxViews }` |
| `POST` | `/api/paste/:id/reveal` | → `{ ct, iv, viewsRemaining }`, or `404` |
| `GET` | `/api/paste/mine` | Your shares: status and who read them |
| `GET` | `/api/me` | Current session |
| `GET` | `/up` | Health check (unauthenticated) |

`POST /api/paste/:id/reveal` answers **identically** for "never existed", "expired" and "already used up". Distinguishing them would confirm to a prober that a given id was once real.

---

## Storage

| Key | Type | Contents | TTL |
|---|---|---|---|
| `paste:<id>` | hash | `ct`, `iv`, `views`, `createdBy`, `createdAt` | chosen expiry |
| `paste:<id>:log` | list | who read it, capped at 20 — outlives the paste | chosen expiry |
| `user:<email>:pastes` | list | ids created, capped at 50 | 7 days |
| `rl:<email>:<minute>` | string | reveal rate limiting | 120s |

Everything expires on its own; there is no cleanup job. There is no SQL database — the session cookie *is* the user record.

---

## Security notes

- **Server is blind.** No code path can decrypt a paste. `crypto.ts` lives under `frontend/` deliberately: if the backend ever imports it, the end-to-end property is being broken.
- **Ids are 128 bits** of CSPRNG randomness. Reveals are additionally rate limited to 30/minute/user.
- **Sessions** are HMAC-signed, `HttpOnly`, `SameSite=Lax`, scoped to `BASE_PATH`, and `Secure` whenever the origin is HTTPS.
- **OAuth CSRF**: the handshake carries a `state` nonce matched against a short-lived cookie. Unverified Google addresses are rejected.
- **Headers**: strict CSP, `Referrer-Policy: no-referrer` (so decrypted text can never ride along in a `Referer`), `X-Frame-Options: DENY`.
- **Size cap** of 64 KB, enforced on the client as plaintext and on the server as encoded length.

### What this does not defend against

- A compromised **server** could serve modified JavaScript that exfiltrates keys. End-to-end encryption in a web app rests on trusting the code delivery; the CSP narrows this but does not remove it.
- Anyone holding the share key **and** a Google account can read the text. The key is the only credential that matters — send it through a channel you trust.
- A reader can screenshot, copy, or retype what they were shown. Self-destruction limits *retrieval*, not what a reader does afterwards.

---

## Tests

```bash
bun test          # needs `docker compose up -d`
```

- `tests/crypto.test.ts` — round trips, unicode, 64 KB, wrong key, tampered ciphertext, checksum guard.
- `tests/pasteStore.test.ts` — view counting, deletion at zero, TTLs, audit log, and the concurrency tests.
- `tests/backend.test.ts` — auth, session tampering, payload validation, indistinguishable 404s, rate limiting, per-user scoping.
