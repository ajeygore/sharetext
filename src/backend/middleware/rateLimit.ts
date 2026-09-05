import type { Context, Next } from "hono";
import { redis } from "../services/redis";
import { REVEAL_RATE_LIMIT } from "../config";
import type { AppEnv } from "./auth";

/**
 * Per-user, per-minute cap on reveal attempts.
 *
 * Paste ids are 128 random bits, so guessing one is already infeasible; this is
 * a second layer that also blunts automated hammering by a compromised account.
 * Fails open — Redis being down should not lock out legitimate users, and the
 * reveal itself will fail loudly anyway if Redis is unreachable.
 */
export async function rateLimitReveals(c: Context<AppEnv>, next: Next) {
  const user = c.get("user");
  const bucket = Math.floor(Date.now() / 60_000);
  const key = `rl:${user.email.toLowerCase()}:${bucket}`;

  try {
    const count = await redis().incr(key);
    if (count === 1) await redis().expire(key, 120);
    if (count > REVEAL_RATE_LIMIT) {
      return c.json({ error: "Too many attempts. Wait a minute and try again." }, 429);
    }
  } catch {
    // Fail open.
  }
  return next();
}
