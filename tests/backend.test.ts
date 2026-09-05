import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { Hono } from "hono";
import { app } from "../src/backend/index";
import { BASE_PATH } from "../src/backend/config";
import { setSession } from "../src/backend/middleware/auth";
import { redis, disconnectRedis, redisHealthy } from "../src/backend/services/redis";
import { _flushForTests } from "../src/backend/services/pasteStore";
import { MAX_CIPHERTEXT_CHARS, TTL_OPTIONS } from "../src/shared/types";

const ORIGIN = "http://localhost:3000";
const url = (p: string) => `${ORIGIN}${BASE_PATH}${p}`;

/**
 * Mints a real session cookie by driving the app's own `setSession`, rather
 * than reimplementing Hono's cookie signing in the test. If signing changes,
 * these tests follow it automatically.
 */
async function sessionCookie(email: string): Promise<string> {
  const minter = new Hono();
  minter.get("/", async (c) => {
    await setSession(c, { email, name: email, picture: "" });
    return c.body(null, 204);
  });
  const res = await minter.request("/");
  return res.headers.get("set-cookie")!.split(";")[0];
}

const json = (cookie: string | null, body?: unknown) => ({
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    ...(cookie ? { Cookie: cookie } : {}),
  },
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});

const validPayload = {
  ct: "Y2lwaGVydGV4dGN0",
  iv: "aXZpdml2aXZpdg",
  maxViews: 1,
  ttlSeconds: TTL_OPTIONS[1].seconds,
};

let cookie: string;

beforeAll(async () => {
  if (!(await redisHealthy())) {
    throw new Error("Redis is not reachable. Run `docker compose up -d` first.");
  }
  cookie = await sessionCookie("creator@example.com");
});

afterAll(async () => {
  await _flushForTests();
  await disconnectRedis();
});

beforeEach(async () => {
  await _flushForTests();
});

describe("mounting", () => {
  it("serves the health check under the base path", async () => {
    const res = await app.request(url("/up"));
    expect(res.status).toBe(200);
    expect((await res.json()).redis).toBe(true);
  });

  it("redirects the bare root to the app", async () => {
    const res = await app.request(`${ORIGIN}/`);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${BASE_PATH}/`);
  });

  it("sets a restrictive CSP and no-referrer policy", async () => {
    const res = await app.request(url("/up"));
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
  });
});

describe("authentication", () => {
  it("rejects anonymous creates", async () => {
    const res = await app.request(url("/api/paste"), json(null, validPayload));
    expect(res.status).toBe(401);
  });

  it("rejects anonymous reveals", async () => {
    const res = await app.request(url("/api/paste/abc/reveal"), json(null));
    expect(res.status).toBe(401);
  });

  it("rejects anonymous history", async () => {
    expect((await app.request(url("/api/paste/mine"))).status).toBe(401);
  });

  it("rejects a tampered session cookie", async () => {
    const tampered = cookie.slice(0, -3) + "aaa";
    const res = await app.request(url("/api/paste"), json(tampered, validPayload));
    expect(res.status).toBe(401);
  });

  it("reports the session on /api/me", async () => {
    const res = await app.request(url("/api/me"), { headers: { Cookie: cookie } });
    expect(res.status).toBe(200);
    expect((await res.json()).user.email).toBe("creator@example.com");
  });
});

describe("POST /api/paste validation", () => {
  const bad: [string, unknown][] = [
    ["non-base64url ciphertext", { ...validPayload, ct: "not base64!!" }],
    ["empty ciphertext", { ...validPayload, ct: "" }],
    ["missing iv", { ...validPayload, iv: undefined }],
    ["overlong iv", { ...validPayload, iv: "a".repeat(64) }],
    ["zero views", { ...validPayload, maxViews: 0 }],
    ["excessive views", { ...validPayload, maxViews: 999 }],
    ["fractional views", { ...validPayload, maxViews: 1.5 }],
    ["arbitrary ttl", { ...validPayload, ttlSeconds: 12345 }],
  ];

  for (const [name, payload] of bad) {
    it(`rejects ${name}`, async () => {
      const res = await app.request(url("/api/paste"), json(cookie, payload));
      expect(res.status).toBe(400);
    });
  }

  it("rejects a malformed body", async () => {
    const res = await app.request(url("/api/paste"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: "{not json",
    });
    expect(res.status).toBe(400);
  });

  it("rejects an oversized ciphertext with 413", async () => {
    const res = await app.request(
      url("/api/paste"),
      json(cookie, { ...validPayload, ct: "A".repeat(MAX_CIPHERTEXT_CHARS + 1) })
    );
    expect(res.status).toBe(413);
  });

  it("accepts a valid payload and stores only ciphertext", async () => {
    const res = await app.request(url("/api/paste"), json(cookie, validPayload));
    expect(res.status).toBe(201);
    const { id } = await res.json();

    const stored = await redis().hgetall(`paste:${id}`);
    expect(stored.ct).toBe(validPayload.ct);
    expect(JSON.stringify(stored)).not.toContain("plaintext");
  });
});

describe("POST /api/paste/:id/reveal", () => {
  async function create(overrides = {}) {
    const res = await app.request(url("/api/paste"), json(cookie, { ...validPayload, ...overrides }));
    return (await res.json()).id as string;
  }

  it("returns the ciphertext and counts down", async () => {
    const id = await create({ maxViews: 2 });
    const first = await app.request(url(`/api/paste/${id}/reveal`), json(cookie));
    expect(first.status).toBe(200);
    const body = await first.json();
    expect(body.ct).toBe(validPayload.ct);
    expect(body.viewsRemaining).toBe(1);
  });

  it("is gone after the last read", async () => {
    const id = await create({ maxViews: 1 });
    expect((await app.request(url(`/api/paste/${id}/reveal`), json(cookie))).status).toBe(200);
    expect((await app.request(url(`/api/paste/${id}/reveal`), json(cookie))).status).toBe(404);
  });

  // A prober must not be able to tell "this id was real and is used up" from
  // "this id never existed" — that would confirm the existence of a paste.
  it("answers identically for consumed, unknown and malformed ids", async () => {
    const id = await create({ maxViews: 1 });
    await app.request(url(`/api/paste/${id}/reveal`), json(cookie));

    const bodies = await Promise.all(
      [id, "TotallyMadeUpIdentifier", "!!!not-valid!!!"].map(async (candidate) => {
        const res = await app.request(url(`/api/paste/${candidate}/reveal`), json(cookie));
        expect(res.status).toBe(404);
        return await res.text();
      })
    );
    expect(new Set(bodies).size).toBe(1);
  });

  it("lets a different signed-in user read, and records them", async () => {
    const id = await create({ maxViews: 1 });
    const other = await sessionCookie("reader@example.com");

    const res = await app.request(url(`/api/paste/${id}/reveal`), json(other));
    expect(res.status).toBe(200);

    const history = await app.request(url("/api/paste/mine"), { headers: { Cookie: cookie } });
    const { pastes } = await history.json();
    expect(pastes[0].revealedBy[0]).toContain("reader@example.com");
    expect(pastes[0].viewsRemaining).toBeNull();
  });

  it("rate limits a burst of reveal attempts", async () => {
    const spammer = await sessionCookie("spammer@example.com");
    const statuses: number[] = [];
    for (let i = 0; i < 40; i++) {
      const res = await app.request(url("/api/paste/NoSuchPasteId/reveal"), json(spammer));
      statuses.push(res.status);
    }
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
    expect(statuses.slice(0, 30).every((s) => s === 404)).toBe(true);
  });
});

describe("GET /api/paste/mine", () => {
  it("scopes history to the signed-in user", async () => {
    await app.request(url("/api/paste"), json(cookie, validPayload));
    const other = await sessionCookie("stranger@example.com");

    const res = await app.request(url("/api/paste/mine"), { headers: { Cookie: other } });
    expect((await res.json()).pastes).toEqual([]);
  });
});
