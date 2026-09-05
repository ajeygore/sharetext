import { randomBytes } from "node:crypto";
import { redis } from "./redis";
import type { PasteSummary } from "../../shared/types";

const ID_BYTES = 16; // 128 bits of CSPRNG — enumeration is infeasible
const LOG_CAP = 20;
const USER_LIST_CAP = 50;
const USER_LIST_TTL = 7 * 24 * 60 * 60;

const pasteKey = (id: string) => `paste:${id}`;
const logKey = (id: string) => `paste:${id}:log`;
const userKey = (email: string) => `user:${email.toLowerCase()}:pastes`;

function newId(): string {
  return randomBytes(ID_BYTES).toString("base64url");
}

/**
 * Reveal is a single Lua script, and it has to stay that way.
 *
 * Read-then-decrement across two round trips is a race: two concurrent reveals
 * of a one-view paste would both read `views = 1`, both return the ciphertext,
 * and the paste would be read twice. Redis runs scripts single-threaded to
 * completion, so bundling read + decrement + delete here makes over-reading
 * impossible regardless of how many requests arrive at once.
 *
 * The view is spent when the ciphertext is *released*, not when the browser
 * reports a successful decrypt — a client-sent confirmation is unenforceable,
 * since a malicious reader could simply never send it and read forever.
 */
const REVEAL_LUA = `
local pkey, lkey = KEYS[1], KEYS[2]
local viewer, ts = ARGV[1], ARGV[2]

local views = redis.call('HGET', pkey, 'views')
if not views then return nil end

local ct = redis.call('HGET', pkey, 'ct')
local iv = redis.call('HGET', pkey, 'iv')
local remaining = tonumber(views) - 1
local ttl = redis.call('TTL', pkey)

-- Audit trail outlives the paste itself so the creator can still see who read it.
redis.call('RPUSH', lkey, ts .. ' ' .. viewer)
redis.call('LTRIM', lkey, -${LOG_CAP}, -1)
if ttl > 0 then redis.call('EXPIRE', lkey, ttl) end

if remaining <= 0 then
  redis.call('DEL', pkey)
else
  redis.call('HSET', pkey, 'views', remaining)
end

return { ct, iv, tostring(remaining) }
`;

export interface CreateArgs {
  ct: string;
  iv: string;
  maxViews: number;
  ttlSeconds: number;
  createdBy: string;
}

export async function createPaste(args: CreateArgs): Promise<{ id: string; expiresAt: Date }> {
  const id = newId();
  const createdAt = new Date();
  const client = redis();

  await client
    .multi()
    .hset(pasteKey(id), {
      ct: args.ct,
      iv: args.iv,
      views: String(args.maxViews),
      createdBy: args.createdBy,
      createdAt: createdAt.toISOString(),
    })
    .expire(pasteKey(id), args.ttlSeconds)
    .lpush(
      userKey(args.createdBy),
      JSON.stringify({
        id,
        createdAt: createdAt.toISOString(),
        maxViews: args.maxViews,
        expiresAt: new Date(createdAt.getTime() + args.ttlSeconds * 1000).toISOString(),
      })
    )
    .ltrim(userKey(args.createdBy), 0, USER_LIST_CAP - 1)
    .expire(userKey(args.createdBy), USER_LIST_TTL)
    .exec();

  return { id, expiresAt: new Date(createdAt.getTime() + args.ttlSeconds * 1000) };
}

export interface RevealResult {
  ct: string;
  iv: string;
  viewsRemaining: number;
}

/** Returns null when the paste does not exist or has already been consumed. */
export async function revealPaste(id: string, viewer: string): Promise<RevealResult | null> {
  const raw = (await redis().eval(
    REVEAL_LUA,
    2,
    pasteKey(id),
    logKey(id),
    viewer,
    new Date().toISOString()
  )) as [string, string, string] | null;

  if (!raw) return null;
  const [ct, iv, remaining] = raw;
  return { ct, iv, viewsRemaining: Math.max(0, parseInt(remaining, 10)) };
}

export async function listUserPastes(email: string): Promise<PasteSummary[]> {
  const client = redis();
  const entries = await client.lrange(userKey(email), 0, USER_LIST_CAP - 1);

  const parsed = entries.flatMap((raw) => {
    try {
      return [JSON.parse(raw) as Omit<PasteSummary, "viewsRemaining" | "revealedBy">];
    } catch {
      return [];
    }
  });
  if (parsed.length === 0) return [];

  // One pipeline for all of them rather than 2N sequential round trips.
  const pipeline = client.pipeline();
  for (const p of parsed) {
    pipeline.hget(pasteKey(p.id), "views");
    pipeline.lrange(logKey(p.id), 0, -1);
  }
  const results = (await pipeline.exec()) ?? [];

  return parsed.map((p, i) => {
    const views = results[i * 2]?.[1] as string | null;
    const log = (results[i * 2 + 1]?.[1] as string[] | null) ?? [];
    return {
      ...p,
      viewsRemaining: views == null ? null : parseInt(views, 10),
      revealedBy: log,
    };
  });
}

/** Test helper: wipes every key this module owns. */
export async function _flushForTests(): Promise<void> {
  const client = redis();
  const keys = [
    ...(await client.keys("paste:*")),
    ...(await client.keys("user:*:pastes")),
    ...(await client.keys("rl:*")),
  ];
  if (keys.length) await client.del(...keys);
}
