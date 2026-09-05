// Browser crypto tests.
//
// This is the one piece that cannot move to Go: ShareText's whole value is that
// the key is generated and used in the browser, so this module ships as
// JavaScript and has to be tested as JavaScript.
//
// Run: node --test test/
//
// Deliberately zero-dependency — node:test, and WebCrypto/btoa/atob from the
// Node globals, which are the same APIs the browser provides. No package.json,
// no node_modules, nothing to install.
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  generateKey,
  encrypt,
  decrypt,
  encodeShareKey,
  parseShareKey,
  toB64u,
  fromB64u,
  ShareKeyError,
} from "../web/static/js/crypto.mjs";

const ID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"; // UUIDv4 shape

describe("base64url", () => {
  test("round-trips arbitrary bytes", () => {
    for (const len of [0, 1, 2, 3, 16, 31, 32, 255]) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      assert.deepEqual([...fromB64u(toB64u(bytes))], [...bytes]);
    }
  });

  test("emits url-safe output with no padding", () => {
    assert.doesNotMatch(toB64u(new Uint8Array([251, 255, 190, 239, 0, 1])), /[+/=]/);
  });
});

describe("encrypt / decrypt", () => {
  test("round-trips a string", async () => {
    const key = generateKey();
    const { ct, iv } = await encrypt(key, "correct horse battery staple");
    assert.equal(await decrypt(key, ct, iv), "correct horse battery staple");
  });

  test("round-trips unicode and newlines", async () => {
    const key = generateKey();
    const secret = "héllo\n世界\n🔐 line three\ttabbed";
    const { ct, iv } = await encrypt(key, secret);
    assert.equal(await decrypt(key, ct, iv), secret);
  });

  test("round-trips a 64 KB payload", async () => {
    const key = generateKey();
    const secret = "x".repeat(64 * 1024);
    const { ct, iv } = await encrypt(key, secret);
    assert.equal(await decrypt(key, ct, iv), secret);
  });

  test("never emits the plaintext in the ciphertext", async () => {
    const { ct } = await encrypt(generateKey(), "SUPERSECRETVALUE");
    assert.ok(!ct.includes("SUPERSECRET"));
    assert.ok(!new TextDecoder().decode(fromB64u(ct)).includes("SUPERSECRET"));
  });

  test("produces a different ciphertext each time (fresh IV)", async () => {
    const key = generateKey();
    const a = await encrypt(key, "same input");
    const b = await encrypt(key, "same input");
    assert.notEqual(a.ct, b.ct);
    assert.notEqual(a.iv, b.iv);
  });

  test("fails with the wrong key", async () => {
    const { ct, iv } = await encrypt(generateKey(), "secret");
    await assert.rejects(() => decrypt(generateKey(), ct, iv));
  });

  test("fails when the ciphertext is tampered with", async () => {
    const key = generateKey();
    const { ct, iv } = await encrypt(key, "secret");
    const bytes = fromB64u(ct);
    bytes[0] ^= 0xff;
    await assert.rejects(() => decrypt(key, toB64u(bytes), iv));
  });

  test("fails when the IV is wrong", async () => {
    const key = generateKey();
    const { ct } = await encrypt(key, "secret");
    const wrongIv = toB64u(crypto.getRandomValues(new Uint8Array(12)));
    await assert.rejects(() => decrypt(key, ct, wrongIv));
  });
});

describe("share key", () => {
  test("round-trips a UUID id and key", async () => {
    const key = generateKey();
    const parsed = await parseShareKey(await encodeShareKey(ID, key));
    assert.equal(parsed.id, ID);
    assert.deepEqual([...parsed.key], [...key]);
  });

  test("tolerates whitespace from a sloppy paste", async () => {
    const share = await encodeShareKey(ID, generateKey());
    assert.equal((await parseShareKey(`  ${share}\n`)).id, ID);
  });

  // A view is spent the moment the server releases the ciphertext, so a
  // mistyped key must be caught before any request goes out.
  test("rejects a mistyped secret before it can burn a view", async () => {
    const [id, secret, sum] = (await encodeShareKey(ID, generateKey())).split(".");
    const flipped = (secret[0] === "A" ? "B" : "A") + secret.slice(1);
    await assert.rejects(() => parseShareKey(`${id}.${flipped}.${sum}`), ShareKeyError);
  });

  test("rejects a mistyped id", async () => {
    const [id, secret, sum] = (await encodeShareKey(ID, generateKey())).split(".");
    await assert.rejects(() => parseShareKey(`${id.slice(0, -1)}f.${secret}.${sum}`), ShareKeyError);
  });

  test("rejects malformed shapes", async () => {
    for (const bad of ["", "nodots", "only.two", "a.b.c.d", " . . "]) {
      await assert.rejects(() => parseShareKey(bad), ShareKeyError);
    }
  });

  test("rejects a key of the wrong length", async () => {
    const short = toB64u(crypto.getRandomValues(new Uint8Array(16)));
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${ID}.${short}`));
    await assert.rejects(
      () => parseShareKey(`${ID}.${short}.${toB64u(new Uint8Array(digest).slice(0, 2))}`),
      ShareKeyError
    );
  });
});
