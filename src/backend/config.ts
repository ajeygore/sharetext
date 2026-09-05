import { randomBytes } from "node:crypto";

export const PORT = parseInt(process.env.PORT || "3000", 10);

/** Sub-path the app is mounted at. Production: smartlydone.ai/sharetext */
export const BASE_PATH = (process.env.BASE_PATH ?? "/sharetext").replace(/\/$/, "");

export const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`).replace(
  /\/$/,
  ""
);

export const IS_PRODUCTION = process.env.NODE_ENV === "production";

/**
 * Cookies are only marked Secure when the app is actually served over TLS.
 * Setting Secure on plain-HTTP localhost would make the browser drop the
 * session cookie entirely and the login loop would never close.
 */
export const USE_SECURE_COOKIES = PUBLIC_ORIGIN.startsWith("https://");

function resolveSessionSecret(): string {
  const secret = process.env.SESSION_SECRET;
  if (secret && secret.length >= 32) return secret;
  if (IS_PRODUCTION) {
    throw new Error(
      "SESSION_SECRET must be set to at least 32 characters in production. " +
        "Generate one with: openssl rand -hex 32"
    );
  }
  // Ephemeral dev secret: sessions do not survive a restart, which is fine
  // locally and strictly better than shipping a hardcoded default.
  console.warn("SESSION_SECRET unset — using an ephemeral dev secret; sessions reset on restart.");
  return randomBytes(32).toString("hex");
}

export const SESSION_SECRET = resolveSessionSecret();
export const SESSION_COOKIE = "sharetext_session";
export const STATE_COOKIE = "sharetext_oauth_state";
export const SESSION_MAX_AGE = 7 * 24 * 60 * 60;

export const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
export const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
export const GOOGLE_REDIRECT_URI = `${PUBLIC_ORIGIN}${BASE_PATH}/auth/google/callback`;
export const GOOGLE_CONFIGURED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

/**
 * Local-only sign-in bypass so the app can be exercised before Google
 * credentials exist. Double-gated: it requires an explicit opt-in AND a
 * non-production build, so it cannot be switched on by env alone in prod.
 */
export const ALLOW_DEV_LOGIN = process.env.ALLOW_DEV_LOGIN === "true" && !IS_PRODUCTION;

/** Reveal attempts allowed per user per minute. */
export const REVEAL_RATE_LIMIT = 30;
