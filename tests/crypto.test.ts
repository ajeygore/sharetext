import { describe, it, expect } from "bun:test";
import {
  generateKey,
  encrypt,
  decrypt,
  encodeShareKey,
  parseShareKey,
  toB64u,
  fromB64u,
  ShareKeyError,
} from "../src/frontend/crypto";

const ID = "aBcD1234aBcD1234aBcD12";

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    for (const len of [0, 1, 2, 3, 16, 31, 32, 255]) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      expect(Array.from(fromB64u(toB64u(bytes)))).toEqual(Array.from(bytes));
    }
  });

  it("emits url-safe output with no padding", () => {
    const encoded = toB64u(new Uint8Array([251, 255, 190, 239, 0, 1]));
    expect(encoded).not.toMatch(/[+/=]/);
  });
});

describe("encrypt / decrypt", () => {
  it("round-trips a string", async () => {
    const key = generateKey();
    const { ct, iv } = await encrypt(key, "correct horse battery staple");
    expect(await decrypt(key, ct, iv)).toBe("correct horse battery staple");
  });

  it("round-trips unicode and newlines", async () => {
    const key = generateKey();
    const secret = "héllo\n世界\n🔐 line three\ttabbed";
    const { ct, iv } = await encrypt(key, secret);
    expect(await decrypt(key, ct, iv)).toBe(secret);
  });

  it("round-trips a 64 KB payload", async () => {
    const key = generateKey();
    const secret = "x".repeat(64 * 1024);
    const { ct, iv } = await encrypt(key, secret);
    expect(await decrypt(key, ct, iv)).toBe(secret);
  });

  it("never emits the plaintext in the ciphertext", async () => {
    const key = generateKey();
    const { ct } = await encrypt(key, "SUPERSECRETVALUE");
    expect(ct.includes("SUPERSECRET")).toBe(false);
    expect(new TextDecoder().decode(fromB64u(ct)).includes("SUPERSECRET")).toBe(false);
  });

  it("produces a different ciphertext each time (fresh IV)", async () => {
    const key = generateKey();
    const a = await encrypt(key, "same input");
    const b = await encrypt(key, "same input");
    expect(a.ct).not.toBe(b.ct);
    expect(a.iv).not.toBe(b.iv);
  });

  it("fails with the wrong key", async () => {
    const { ct, iv } = await encrypt(generateKey(), "secret");
    await expect(decrypt(generateKey(), ct, iv)).rejects.toThrow();
  });

  it("fails when the ciphertext is tampered with", async () => {
    const key = generateKey();
    const { ct, iv } = await encrypt(key, "secret");
    const bytes = fromB64u(ct);
    bytes[0] ^= 0xff;
    await expect(decrypt(key, toB64u(bytes), iv)).rejects.toThrow();
  });

  it("fails when the IV is wrong", async () => {
    const key = generateKey();
    const { ct } = await encrypt(key, "secret");
    const wrongIv = toB64u(crypto.getRandomValues(new Uint8Array(12)));
    await expect(decrypt(key, ct, wrongIv)).rejects.toThrow();
  });
});

describe("share key", () => {
  it("round-trips id and key", async () => {
    const key = generateKey();
    const { id, key: parsed } = await parseShareKey(await encodeShareKey(ID, key));
    expect(id).toBe(ID);
    expect(Array.from(parsed)).toEqual(Array.from(key));
  });

  it("tolerates surrounding whitespace from a sloppy paste", async () => {
    const key = generateKey();
    const share = await encodeShareKey(ID, key);
    expect((await parseShareKey(`  ${share}\n`)).id).toBe(ID);
  });

  it("rejects a mistyped secret before it can burn a view", async () => {
    const share = await encodeShareKey(ID, generateKey());
    const [id, secret, sum] = share.split(".");
    const flipped = secret[0] === "A" ? `B${secret.slice(1)}` : `A${secret.slice(1)}`;
    await expect(parseShareKey(`${id}.${flipped}.${sum}`)).rejects.toThrow(ShareKeyError);
  });

  it("rejects a mistyped id", async () => {
    const share = await encodeShareKey(ID, generateKey());
    const [id, secret, sum] = share.split(".");
    await expect(parseShareKey(`${id}z.${secret}.${sum}`)).rejects.toThrow(ShareKeyError);
  });

  it("rejects malformed shapes", async () => {
    for (const bad of ["", "nodots", "only.two", "a.b.c.d", " . . "]) {
      await expect(parseShareKey(bad)).rejects.toThrow(ShareKeyError);
    }
  });

  it("rejects a key of the wrong length", async () => {
    const short = toB64u(crypto.getRandomValues(new Uint8Array(16)));
    // Recompute a valid checksum so length is the only thing wrong.
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${ID}.${short}`));
    const sum = toB64u(new Uint8Array(digest).slice(0, 2));
    await expect(parseShareKey(`${ID}.${short}.${sum}`)).rejects.toThrow(ShareKeyError);
  });
});
