import { Hono } from "hono";
import { logger } from "hono/logger";
import { secureHeaders } from "hono/secure-headers";
import { serveStatic } from "hono/bun";
import { BASE_PATH, GOOGLE_CONFIGURED } from "./config";
import { authRouter } from "./routes/auth";
import { pasteRouter } from "./routes/paste";
import { redisHealthy } from "./services/redis";
import type { AppEnv } from "./middleware/auth";

/**
 * Builds the server.
 *
 * `basePath` is a parameter rather than a module-level constant so both mount
 * modes are testable in one process:
 *   ""            — its own domain, e.g. https://share.tnkrhaus.dev
 *   "/sharetext"  — a sub-path of a shared domain
 * Nothing inside the app knows its own mount point; it is applied once here.
 */
export function buildApp(basePath: string = BASE_PATH) {
  const root = new Hono<AppEnv>();

  // Request logs are noise under `bun test`, which drives the app in-process.
  if (process.env.NODE_ENV !== "test") root.use("*", logger());

  root.use(
    "*",
    secureHeaders({
      contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        // Google serves avatars from lh3-lh6 and rotates between them, so
        // pinning a single host silently breaks profile pictures for some
        // accounts and not others.
        imgSrc: ["'self'", "data:", "https://*.googleusercontent.com"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
      },
      // Decrypted text must never ride along in a Referer header to anywhere.
      referrerPolicy: "no-referrer",
      xFrameOptions: "DENY",
    })
  );

  const app = new Hono<AppEnv>();

  app.route("/", authRouter);
  app.route("/api/paste", pasteRouter);

  app.get("/up", async (c) => {
    const redisOk = await redisHealthy();
    return c.json(
      { status: redisOk ? "ok" : "degraded", redis: redisOk, google: GOOGLE_CONFIGURED },
      redisOk ? 200 : 503
    );
  });

  // Built SPA. Assets are content-hashed by Vite, so they can be cached hard;
  // index.html must not be, or clients pin themselves to a stale bundle.
  app.use(
    "/assets/*",
    serveStatic({
      root: "./dist",
      rewriteRequestPath: (path) => (basePath ? path.replace(basePath, "") : path),
      onFound: (_path, c) => c.header("Cache-Control", "public, max-age=31536000, immutable"),
    })
  );

  app.get("*", serveStatic({ path: "./dist/index.html" }));

  root.route(basePath || "/", app);

  // Sub-path deployments get a convenience redirect from the bare domain root.
  // At a dedicated domain there is nothing to redirect to.
  if (basePath) root.get("/", (c) => c.redirect(`${basePath}/`));

  return root;
}
