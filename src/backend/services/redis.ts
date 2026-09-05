import Redis from "ioredis";

/**
 * Defaults match docker-compose.yml, which publishes on 6380 rather than the
 * conventional 6379 — that port is frequently already claimed by another
 * project's Redis. `docker compose up -d` then `bun test` works with no .env.
 */
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 6380;

/**
 * Connects on first use rather than at import time, so the process (and the
 * test suite) can start without Redis present, and so environment overrides
 * applied after import are still honoured. Retries are bounded: a missing Redis
 * degrades into visible request errors instead of hanging the server.
 */
class LazyRedis {
  private client: Redis | null = null;

  getClient(): Redis {
    if (!this.client) {
      this.client = new Redis({
        host: process.env.REDIS_HOST || DEFAULT_HOST,
        port: parseInt(process.env.REDIS_PORT || String(DEFAULT_PORT), 10),
        maxRetriesPerRequest: 3,
        retryStrategy(times) {
          if (times > 3) {
            console.warn(`Redis unreachable after ${times} retries; continuing degraded.`);
            return null;
          }
          return Math.min(times * 100, 2000);
        },
      });
      this.client.on("error", (err) => console.warn("Redis error:", err.message));
    }
    return this.client;
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.quit().catch(() => {});
      this.client = null;
    }
  }
}

const lazy = new LazyRedis();
export const redis = () => lazy.getClient();
export const disconnectRedis = () => lazy.disconnect();

export async function redisHealthy(): Promise<boolean> {
  try {
    return (await redis().ping()) === "PONG";
  } catch {
    return false;
  }
}
