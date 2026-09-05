/**
 * All cryptography for ShareText. This module runs ONLY in the browser.
 *
 * It is the one piece that cannot be Go. The product's whole value is that the
 * server never holds a key or a plaintext, which means key generation and
 * encryption must happen on the user's device. If you ever find yourself
 * wanting this logic on the server, the end-to-end property is about to break.
 *
 * Scheme: AES-256-GCM with a 96-bit IV. The key is 32 CSPRNG bytes generated in
 * the browser and transmitted to the server never — it lives only inside the
 * share key string the creator copies out by hand.
 *
 * .mjs rather than .js so `node --test` treats it as a module without the
 * repository needing a package.json.
 */

const KEY_BYTES = 32;
const IV_BYTES = 12;
const CHECKSUM_BYTES = 2;

// ---------- base64url ----------

export function toB64u(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- secure context ----------

/**
 * `crypto.subtle` exists only in a secure context (HTTPS, or localhost). Over
 * plain HTTP on a real hostname it is undefined and every call here throws, so
 * callers check this up front and refuse to run rather than offering a page
 * that looks like it encrypts and does not.
 */
export function isCryptoAvailable() {
  return typeof crypto !== "undefined" && typeof crypto.subtle !== "undefined";
}

// ---------- keys ----------

export function generateKey() {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

function importKey(raw, usages) {
  if (raw.length !== KEY_BYTES) throw new Error("Invalid key length");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, usages);
}

// ---------- encrypt / decrypt ----------

export async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ck = await importKey(key, ["encrypt"]);
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    ck,
    new TextEncoder().encode(plaintext)
  );
  return { ct: toB64u(new Uint8Array(buf)), iv: toB64u(iv) };
}

export async function decrypt(key, ct, iv) {
  const ck = await importKey(key, ["decrypt"]);
  // Throws if the GCM tag does not verify — wrong key, or tampered ciphertext.
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64u(iv) },
    ck,
    fromB64u(ct)
  );
  return new TextDecoder().decode(buf);
}

// ---------- share key ----------

async function checksum(id, secretB64) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${id}.${secretB64}`)
  );
  return toB64u(new Uint8Array(digest).slice(0, CHECKSUM_BYTES));
}

/**
 * Builds the string the creator copies: `<uuid>.<secret>.<checksum>`.
 *
 * The checksum is not a security control — it is a typo guard. A view is spent
 * the instant the server releases the ciphertext, so a mistyped secret would
 * otherwise burn a read and then fail to decrypt with no way back. Validating
 * locally means a corrupted key costs nothing.
 */
export async function encodeShareKey(id, key) {
  const secret = toB64u(key);
  return `${id}.${secret}.${await checksum(id, secret)}`;
}

export class ShareKeyError extends Error {}

export async function parseShareKey(input) {
  const parts = String(input).trim().split(".");
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
  let key;
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
