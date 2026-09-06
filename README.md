# ShareText

Share a piece of text that can only be read a set number of times, then destroys itself.

Text is encrypted **in the browser**. The server stores ciphertext it has no way to read, counts down the remaining reads, and deletes the record when the budget runs out. Google sign-in is required to create and to read.

Runs at **[share.tnkrhaus.dev](https://share.tnkrhaus.dev)**, deployed by Ansible from [`GetThrive/infra`](https://github.com/GetThrive/infra) onto the Thrive primary DNS box.

**Go · HTML + Tailwind · Redis** — the [Thrive standard stack](https://github.com/GetThrive/thrive-wiki/blob/main/wiki/tech-stack.md). No Postgres: paste data is deliberately short-lived and self-deleting.

---

## Tech stack

| Layer | What | Why |
|---|---|---|
| Crypto | Web Crypto `crypto.subtle`, AES-256-GCM | Native, audited primitives; encryption happens client-side so the server never holds a key |
| Frontend | Server-rendered HTML + Tailwind | No framework and no bundler — the only JavaScript is the ~130-line crypto module and the form wiring that drives it |
| Backend | Go | One self-contained binary; templates, stylesheet and scripts are embedded, so a deploy copies one file |
| Storage | Redis (dedicated instance, loopback-only) | Ciphertext with a native TTL and an atomic read counter — no separate GC |
| Auth | Google OAuth 2.0 | Every create and read is attributable; no passwords stored |
| Edge | Caddy + Let's Encrypt | Automatic TLS; a secure context is mandatory for `crypto.subtle` |

Everything security-relevant lives in a few files: [`web/static/js/crypto.mjs`](web/static/js/crypto.mjs) (browser encryption), [`internal/store`](internal/store) (the paste store and its atomic reveal), [`internal/web`](internal/web) (the HTTP surface). See [How it works](#how-it-works) for the data flow and [Security notes](#security-notes) for the threat model.


## How it works

```
CREATE                                          READ
------                                          ----
browser: key = 32 random bytes                  browser: split key, verify checksum
browser: ct = AES-256-GCM(key, text)               |  (a mistyped key stops here — no request)
    |                                              v
    |  POST { ct, iv, max_views, ttl }          POST /api/paste/{uuid}/reveal
    v      ^^^ no key, ever                         |
server:  store, return UUIDv4                   server: atomic decrement, return ct
    |                                              |  deletes the record at zero
    v                                              v
share key = <uuid>.<secret>.<checksum>          browser: decrypt locally with secret
            ^^^^ server knows                   plaintext never leaves the browser
                   ^^^^^^ server never sees
```

After creating a paste the creator is shown a **ready-to-send message**, not a
bare key — pasted into WhatsApp or email, a lone hundred-character string tells
the recipient nothing:

```
Go to https://share.tnkrhaus.dev, sign in with Google, and enter this key:

<key>

Readable 2 times · expires 6 Sep 2026, 19:30
Once the reads run out it is deleted, and the key is the only way to open it.
```

The URL is derived from `PUBLIC_ORIGIN` + `BASE_PATH`, never hardcoded, so a
self-hosted or sub-path instance advertises its own address. The key sits alone
on its own line and unquoted: quotes and trailing punctuation get copied with
it and then fail to parse, and a dedicated line survives the wrapping messaging
apps apply.

The **share key** itself is one string:

| Part | | Goes to the server? |
|---|---|---|
| `uuid` | UUIDv4 | Yes — it is the Redis lookup key |
| `secret` | 32 random bytes | **Never.** This is the AES key |
| `checksum` | 2 bytes | No — a client-side typo guard |

Because the secret half never reaches the server, a full dump of Redis — or of a backup, or of the host — yields nothing but opaque bytes. Losing the key means the text is unrecoverable by anyone, including the operator. That is the point.

### The one piece that cannot be Go

`web/static/js/crypto.mjs` is JavaScript and has to stay that way. The product's whole value is that the key is generated and used on the user's device; moving encryption to the server would hand it exactly what it is designed not to have.

That is not a client-side app. There is no framework and no bundler — Go renders the HTML, and the browser loads ~130 lines of hand-written WebCrypto plus the form wiring that drives it.

### Why UUIDv4 and not v7

The [standard](https://github.com/GetThrive/thrive-wiki/blob/main/wiki/tech-stack.md) prefers **v7** for its Postgres index locality. Here it would be actively wrong: v7 embeds a creation timestamp, and *when a given secret was created* is exactly the metadata a secret-sharing tool must not publish. Pastes are Redis keys, not B-tree rows, so v7 buys nothing to offset it.

### Three decisions worth knowing about

**A read is spent when the ciphertext is released**, not when the browser reports a successful decrypt. Decryption happens client-side, so a confirmation from the client is unenforceable — a reader could simply never send one and read forever.

That would make a typo expensive, so the share key carries a 2-byte checksum the browser validates *before* any network call. A mistyped key is rejected locally and costs nothing.

**Reveal is a single Lua script.** Read-then-decrement over two round trips races: two concurrent reveals of a one-read paste would both see `views = 1` and both succeed. Redis runs scripts to completion on one thread, so bundling read + decrement + delete makes over-reading impossible. `internal/store` fires 50 simultaneous reveals at a one-read paste and asserts exactly one wins — and that test is verified to fail against a deliberately non-atomic implementation.

---

## Running it locally

```sh
docker compose up -d     # Redis on :6380
make dev                 # http://localhost:3000
```

`make build` produces a single self-contained binary — templates, stylesheet and scripts are embedded, so deploying copies one file.

### Before you have Google credentials

```sh
ALLOW_DEV_LOGIN=true make dev
```

adds a local sign-in box that mints a session for any address you type. Double-gated — it needs the explicit opt-in *and* a non-production build — so it cannot be switched on in production by environment alone.

### Redis is on 6380, not 6379

`docker-compose.yml` publishes on **6380** because 6379 is so often already taken by another project's Redis. The app defaults to match, so `docker compose up -d && make test` works with no `.env`. In production it gets its own instance on 6381.

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `3000` | |
| `BASE_PATH` | empty | Empty means the app owns the domain root, the normal case. Set it (e.g. `/sharetext`) to mount under a path on a shared domain. |
| `PUBLIC_ORIGIN` | `http://localhost:$PORT` | Also decides whether cookies are `Secure` |
| `SESSION_SECRET` | — | **Required in production**, min 32 chars. `openssl rand -hex 32` |
| `GOOGLE_CLIENT_ID` / `_SECRET` | — | |
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6380` | Or `REDIS_ADDR` as `host:port` |
| `APP_ENV` | — | `production` enforces `SESSION_SECRET` and disables dev login |
| `ALLOW_DEV_LOGIN` | unset | `true` enables the local bypass; ignored in production |

### Google OAuth setup

1. Cloud Console → **APIs & Services** → **Credentials** → **OAuth client ID** → **Web application**.
2. Authorized redirect URI, character for character: `<PUBLIC_ORIGIN><BASE_PATH>/auth/google/callback`
   - production — `https://share.tnkrhaus.dev/auth/google/callback`
   - local — `http://localhost:3000/auth/google/callback`

`/up` reporting `google:true` only means the credentials are **present**. It cannot tell you whether the redirect URI is registered — only a sign-in attempt can.

---

## Deployment

Runs on `thrive-dns01` (`dm.tnkrhaus.dev`) beside `coredns_ui`. They share the box and Caddy and nothing else.

```
                    Caddy :443
       ┌─────────────┴──────────────┐
   dm.tnkrhaus.dev            share.tnkrhaus.dev
   coredns_ui :3000           sharetext :3001
       │                            │
   Redis :6379                 Redis :6381
   (authoritative DNS,         (paste ciphertext,
    replicates to ns02)         loopback only, never replicated)
```

```sh
make sharetext      # from GetThrive/infra
```

The DNS Redis on 6379 is the authoritative zone store and replicates to `ns02`. Paste ciphertext has no business on that link, and a stray `FLUSHDB` from an app sharing the instance would take `tnkrhaus.dev` down with it.

**HTTPS is not optional.** `crypto.subtle` exists only in a secure context; over plain HTTP on a real hostname the browser does not expose it and no encryption is possible. The app detects this and refuses rather than pretending to work.

---

## API

All routes sit under `BASE_PATH` and require a session.

| Method | Path | |
|---|---|---|
| `POST` | `/api/paste` | `{ct, iv, max_views, ttl_seconds}` → `{id, expires_at, max_views}` |
| `POST` | `/api/paste/{uuid}/reveal` | → `{ct, iv, views_remaining}`, or `404` |
| `GET` | `/api/paste/mine` | Your shares: status and who read them |
| `GET` | `/api/me` | Current session |
| `GET` | `/up` | Health check (unauthenticated) |

Reveal answers **identically** for "never existed", "expired", "already used up" and "not even a valid UUID". Distinguishing them would confirm to a prober that an id was once real.

---

## Storage

| Key | Type | Contents | TTL |
|---|---|---|---|
| `paste:<uuid>` | hash | `ct`, `iv`, `views`, `created_by`, `created_at` | chosen expiry |
| `paste:<uuid>:log` | list | who read it, capped at 20 — outlives the paste | chosen expiry |
| `user:<email>:pastes` | list | ids created, capped at 50 | 7 days |
| `rl:<email>:<minute>` | string | reveal rate limiting | 120s |

Everything expires on its own; there is no cleanup job and no relational database. The session cookie *is* the user record.

---

## Security notes

- **The server is blind.** No code path can decrypt a paste. `crypto.mjs` lives under `web/static/` for a reason: if Go ever imports that logic, the end-to-end property is being broken.
- **Ids are UUIDv4** — 122 bits of CSPRNG randomness. Reveals are additionally rate limited to 30/minute/user.
- **Sessions** are HMAC-signed and compared in constant time, `HttpOnly`, `SameSite=Lax`, scoped to `BASE_PATH`, `Secure` on HTTPS origins.
- **OAuth CSRF**: a `state` nonce matched against a short-lived cookie, compared in constant time. Unverified Google addresses are rejected.
- **Headers**: strict CSP, `Referrer-Policy: no-referrer` (decrypted text must never ride along in a `Referer`), `X-Frame-Options: DENY`, `nosniff`.
- **Size cap** of 64 KB, enforced on the client as plaintext and on the server as encoded length.

### What this does not defend against

- A compromised **server** could serve modified JavaScript that exfiltrates keys. End-to-end encryption in a web app rests on trusting code delivery; the CSP narrows this but does not remove it.
- Anyone holding the share key **and** a Google account can read the text. Send it through a channel you trust.
- A reader can screenshot or retype what they were shown. Self-destruction limits *retrieval*, not what a reader does afterwards.

---

## Tests

```sh
docker compose up -d
make test          # Go + browser crypto
```

- `internal/store` — UUIDv4 generation, view counting, deletion at zero, TTLs, the audit log, and the concurrency tests.
- `internal/web` — auth, session tampering, payload validation, indistinguishable 404s, rate limiting, per-user scoping, both mount modes, OAuth state, and that the pages actually render.
- `internal/session` — round-trip, cookie hardening, forged and truncated cookies, wrong secret.
- `internal/config` — secure-cookie and redirect-URI derivation, production secret enforcement.
- `test/crypto.test.mjs` — round-trips, unicode, 64 KB, wrong key, tampered ciphertext, the checksum guard. Run by `node --test` with **zero dependencies** — `node:test` plus the WebCrypto globals, no `package.json`, no `node_modules`.

---

## Open source

ShareText is open source precisely because "the server can't read your text" is a claim you should be able to verify rather than take on faith. Read the encryption for yourself in [`web/static/js/crypto.mjs`](web/static/js/crypto.mjs), run your own instance, or send a change.

- **Run your own** — [Running it locally](#running-it-locally) gets you going with `docker compose up -d` and `make dev`; [Deployment](#deployment) covers a real host. Self-hosting means you also control the JavaScript that gets served, which closes the one gap end-to-end encryption in the browser cannot close on its own (see [What this does not defend against](#what-this-does-not-defend-against)).
- **Contribute** — issues and pull requests are welcome. Keep the [tests](#tests) green (`make test`), and treat anything touching `crypto.mjs` or the paste store as security-sensitive: explain the reasoning in the PR and add a test that would fail without your change.

## License

[MIT](LICENSE) © 2026 Ajey Gore. Use it, fork it, run your own — just keep the copyright and licence notice.
