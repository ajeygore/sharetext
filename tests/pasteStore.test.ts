import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { redis, disconnectRedis, redisHealthy } from "../src/backend/services/redis";
import {
  createPaste,
  revealPaste,
  listUserPastes,
  _flushForTests,
} from "../src/backend/services/pasteStore";

const OWNER = "owner@example.com";
const VIEWER = "viewer@example.com";

const make = (overrides: Partial<Parameters<typeof createPaste>[0]> = {}) =>
  createPaste({
    ct: "Y2lwaGVydGV4dA",
    iv: "aXZpdml2aXZpdg",
    maxViews: 1,
    ttlSeconds: 300,
    createdBy: OWNER,
    ...overrides,
  });

beforeAll(async () => {
  if (!(await redisHealthy())) {
    throw new Error("Redis is not reachable. Run `docker compose up -d` first.");
  }
});

afterAll(async () => {
  await _flushForTests();
  await disconnectRedis();
});

beforeEach(async () => {
  await _flushForTests();
});

describe("createPaste", () => {
  it("mints distinct, high-entropy ids", async () => {
    const ids = new Set<string>();
    for (let i = 0; i < 25; i++) ids.add((await make()).id);
    expect(ids.size).toBe(25);
    for (const id of ids) expect(id.length).toBeGreaterThanOrEqual(22);
  });

  it("stores only ciphertext — never plaintext or key material", async () => {
    const { id } = await make({ ct: "OPAQUEBYTES" });
    const stored = await redis().hgetall(`paste:${id}`);
    expect(Object.keys(stored).sort()).toEqual(["createdAt", "createdBy", "ct", "iv", "views"]);
    expect(stored.ct).toBe("OPAQUEBYTES");
  });

  it("sets a TTL so pastes expire on their own", async () => {
    const { id } = await make({ ttlSeconds: 300 });
    const ttl = await redis().ttl(`paste:${id}`);
    expect(ttl).toBeGreaterThan(290);
    expect(ttl).toBeLessThanOrEqual(300);
  });
});

describe("revealPaste", () => {
  it("returns the ciphertext and counts down", async () => {
    const { id } = await make({ maxViews: 3 });
    expect((await revealPaste(id, VIEWER))?.viewsRemaining).toBe(2);
    expect((await revealPaste(id, VIEWER))?.viewsRemaining).toBe(1);
    expect((await revealPaste(id, VIEWER))?.viewsRemaining).toBe(0);
  });

  it("returns the same ciphertext on every allowed view", async () => {
    const { id } = await make({ ct: "SAME", maxViews: 2 });
    expect((await revealPaste(id, VIEWER))?.ct).toBe("SAME");
    expect((await revealPaste(id, VIEWER))?.ct).toBe("SAME");
  });

  it("deletes the paste once exhausted", async () => {
    const { id } = await make({ maxViews: 1 });
    await revealPaste(id, VIEWER);
    expect(await redis().exists(`paste:${id}`)).toBe(0);
    expect(await revealPaste(id, VIEWER)).toBeNull();
  });

  it("is null for an unknown id", async () => {
    expect(await revealPaste("nosuchidatall", VIEWER)).toBeNull();
  });

  it("records who revealed it, and keeps that after the paste is gone", async () => {
    const { id } = await make({ maxViews: 1 });
    await revealPaste(id, VIEWER);
    const log = await redis().lrange(`paste:${id}:log`, 0, -1);
    expect(log).toHaveLength(1);
    expect(log[0]).toContain(VIEWER);
    expect(await redis().exists(`paste:${id}`)).toBe(0);
    expect(await redis().ttl(`paste:${id}:log`)).toBeGreaterThan(0);
  });

  // The reason reveal is a Lua script. Two concurrent reveals of a one-view
  // paste must not both succeed.
  it("never over-releases under concurrency", async () => {
    for (const concurrency of [2, 10, 50]) {
      await _flushForTests();
      const { id } = await make({ maxViews: 1 });
      const results = await Promise.all(
        Array.from({ length: concurrency }, () => revealPaste(id, VIEWER))
      );
      expect(results.filter((r) => r !== null)).toHaveLength(1);
    }
  });

  it("releases exactly maxViews times under a concurrent stampede", async () => {
    const { id } = await make({ maxViews: 4 });
    const results = await Promise.all(
      Array.from({ length: 40 }, () => revealPaste(id, VIEWER))
    );
    const ok = results.filter((r) => r !== null);
    expect(ok).toHaveLength(4);
    // Each successful reveal reports a distinct remaining count: 3, 2, 1, 0.
    expect(ok.map((r) => r!.viewsRemaining).sort()).toEqual([0, 1, 2, 3]);
  });
});

describe("listUserPastes", () => {
  it("is empty for an unknown user", async () => {
    expect(await listUserPastes("nobody@example.com")).toEqual([]);
  });

  it("reports live and consumed pastes distinctly, newest first", async () => {
    const first = await make({ maxViews: 1 });
    const second = await make({ maxViews: 5 });
    await revealPaste(first.id, VIEWER);

    const list = await listUserPastes(OWNER);
    expect(list.map((p) => p.id)).toEqual([second.id, first.id]);

    const consumed = list.find((p) => p.id === first.id)!;
    expect(consumed.viewsRemaining).toBeNull(); // gone
    expect(consumed.revealedBy[0]).toContain(VIEWER);

    const live = list.find((p) => p.id === second.id)!;
    expect(live.viewsRemaining).toBe(5);
    expect(live.revealedBy).toEqual([]);
  });

  it("does not leak one user's pastes to another", async () => {
    await make({ createdBy: OWNER });
    expect(await listUserPastes(VIEWER)).toEqual([]);
  });
});
