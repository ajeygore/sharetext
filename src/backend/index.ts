import { Hono } from "hono";
import { logger } from "hono/logger";
import { secureHeaders } from "hono/secure-headers";
import { serveStatic } from "hono/bun";
import { BASE_PATH, PORT, PUBLIC_ORIGIN, GOOGLE_CONFIGURED } from "./config";
import { authRouter } from "./routes/auth";
import { pasteRouter } from "./routes/paste";
import { redisHealthy } from "./services/redis";
import type { AppEnv } from "./middleware/auth";

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
      imgSrc: ["'self'", "data:", "https://lh3.googleusercontent.com"],
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

// Everything hangs off BASE_PATH so the app can live at smartlydone.ai/sharetext
// without any component needing to know its own mount point.
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
    rewriteRequestPath: (path) => path.replace(BASE_PATH, ""),
    onFound: (_path, c) => c.header("Cache-Control", "public, max-age=31536000, immutable"),
  })
);

app.get("*", serveStatic({ path: "./dist/index.html" }));

root.route(BASE_PATH || "/", app);

// Bare-domain convenience: /  ->  /sharetext
if (BASE_PATH) {
  root.get("/", (c) => c.redirect(`${BASE_PATH}/`));
}

console.log(`ShareText listening on :${PORT}  ->  ${PUBLIC_ORIGIN}${BASE_PATH}/`);
if (!GOOGLE_CONFIGURED) {
  console.warn("Google OAuth is not configured — sign-in will be unavailable.");
}

export default { port: PORT, fetch: root.fetch };
export { root as app };
