/**
 * All cryptography for ShareText. This module runs ONLY in the browser.
 *
 * It deliberately lives under `frontend/` rather than `shared/`: the server must
 * never import it, because the server is never in possession of a key. If you
 * ever find yourself reaching for this from `backend/`, the end-to-end property
 * is about to be broken.
 *
 * Scheme: AES-256-GCM with a 96-bit IV. The key is 32 CSPRNG bytes generated in
 * the browser and transmitted to the server never — it lives only inside the
 * share key string that the creator copies out by hand.
 */

const KEY_BYTES = 32;
const IV_BYTES = 12;
const CHECKSUM_BYTES = 2;

// ---------- base64url ----------

export function toB64u(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- secure context ----------

/**
 * `crypto.subtle` is only exposed in a secure context (HTTPS, or localhost).
 * Over plain HTTP on a real hostname it is `undefined` and every call here
 * would throw. Callers check this up front and refuse to run rather than
 * silently offering a broken app.
 */
export function isCryptoAvailable(): boolean {
  return typeof crypto !== "undefined" && typeof crypto.subtle !== "undefined";
}

// ---------- keys ----------

export function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

async function importKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (raw.length !== KEY_BYTES) throw new Error("Invalid key length");
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, usages);
}

// ---------- encrypt / decrypt ----------

export async function encrypt(
  key: Uint8Array,
  plaintext: string
): Promise<{ ct: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ck = await importKey(key, ["encrypt"]);
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    ck,
    new TextEncoder().encode(plaintext) as BufferSource
  );
  return { ct: toB64u(new Uint8Array(buf)), iv: toB64u(iv) };
}

export async function decrypt(key: Uint8Array, ct: string, iv: string): Promise<string> {
  const ck = await importKey(key, ["decrypt"]);
  // Throws OperationError if the GCM tag does not verify — i.e. wrong key or
  // tampered ciphertext. Callers translate that into a user-facing message.
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64u(iv) as BufferSource },
    ck,
    fromB64u(ct) as BufferSource
  );
  return new TextDecoder().decode(buf);
}

// ---------- share key ----------

async function checksum(id: string, secretB64: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${id}.${secretB64}`) as BufferSource
  );
  return toB64u(new Uint8Array(digest).slice(0, CHECKSUM_BYTES));
}

/**
 * Builds the string the creator copies: `<id>.<secret>.<checksum>`.
 *
 * The checksum is not a security control — it is a typo guard. A view is spent
 * the instant the server releases the ciphertext, so a mistyped secret would
 * otherwise burn a view and then fail to decrypt with no way back. Validating
 * locally means a corrupted key costs nothing.
 */
export async function encodeShareKey(id: string, key: Uint8Array): Promise<string> {
  const secret = toB64u(key);
  return `${id}.${secret}.${await checksum(id, secret)}`;
}

export class ShareKeyError extends Error {}

export async function parseShareKey(input: string): Promise<{ id: string; key: Uint8Array }> {
  const parts = input.trim().split(".");
  if (parts.length !== 3) {
    throw new ShareKeyError("That does not look like a ShareText key.");
  }
  const [id, secret, sum] = parts;
  if (!id || !secret || !sum) {
    throw new ShareKeyError("That does not look like a ShareText key.");
  }
  if ((await checksum(id, secret)) !== sum) {
    throw new ShareKeyError("This key looks mistyped — check it and try again.");
  }
  let key: Uint8Array;
  try {
    key = fromB64u(secret);
  } catch {
    throw new ShareKeyError("This key looks mistyped — check it and try again.");
  }
  if (key.length !== KEY_BYTES) {
    throw new ShareKeyError("This key looks mistyped — check it and try again.");
  }
  return { id, key };
}
