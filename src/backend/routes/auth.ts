import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { randomBytes } from "node:crypto";
import {
  ALLOW_DEV_LOGIN,
  BASE_PATH,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CONFIGURED,
  GOOGLE_REDIRECT_URI,
  STATE_COOKIE,
  USE_SECURE_COOKIES,
} from "../config";
import { clearSession, getSessionUser, setSession, type AppEnv } from "../middleware/auth";

export const authRouter = new Hono<AppEnv>();

const appUrl = (query = "") => `${BASE_PATH || ""}/${query}`;

authRouter.get("/api/me", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.json({ authenticated: false }, 401);
  return c.json({ authenticated: true, user });
});

authRouter.get("/api/auth/config", (c) =>
  c.json({ googleConfigured: GOOGLE_CONFIGURED, devLogin: ALLOW_DEV_LOGIN })
);

// Development only. See ALLOW_DEV_LOGIN in config.ts.
authRouter.post("/auth/dev-login", async (c) => {
  if (!ALLOW_DEV_LOGIN) return c.json({ error: "Not available." }, 404);

  const body = (await c.req.json().catch(() => ({}))) as { email?: string };
  const email = (body.email || "dev@localhost").toLowerCase();
  await setSession(c, { email, name: email, picture: "" });
  return c.json({ ok: true });
});

authRouter.get("/auth/google", (c) => {
  if (!GOOGLE_CONFIGURED) {
    return c.text(
      "Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.",
      503
    );
  }

  // CSRF defence for the handshake: a random state echoed back by Google and
  // matched against a short-lived cookie, so a third party cannot walk a victim
  // through a login they did not start.
  const state = randomBytes(16).toString("base64url");
  setCookie(c, STATE_COOKIE, state, {
    path: BASE_PATH || "/",
    httpOnly: true,
    secure: USE_SECURE_COOKIES,
    sameSite: "Lax",
    maxAge: 600,
  });

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    prompt: "select_account",
    state,
  });
  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

authRouter.get("/auth/google/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const error = c.req.query("error");

  const expectedState = getCookie(c, STATE_COOKIE);
  deleteCookie(c, STATE_COOKIE, { path: BASE_PATH || "/" });

  if (error || !code) {
    return c.redirect(appUrl(`?error=${encodeURIComponent(error || "authorization_failed")}`));
  }
  if (!state || !expectedState || state !== expectedState) {
    return c.redirect(appUrl("?error=state_mismatch"));
  }

  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: GOOGLE_REDIRECT_URI,
      }),
    });
    if (!tokenRes.ok) {
      console.error("Google token exchange failed:", await tokenRes.text());
      return c.redirect(appUrl("?error=token_exchange_failed"));
    }

    const { access_token } = (await tokenRes.json()) as { access_token?: string };
    if (!access_token) return c.redirect(appUrl("?error=token_exchange_failed"));

    const profileRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    if (!profileRes.ok) return c.redirect(appUrl("?error=profile_fetch_failed"));

    const profile = (await profileRes.json()) as {
      email?: string;
      email_verified?: boolean;
      name?: string;
      picture?: string;
    };

    // An unverified Google address is not proof of control of that mailbox, and
    // pastes are attributed by email — so refuse it.
    if (!profile.email || profile.email_verified === false) {
      return c.redirect(appUrl("?error=unverified_email"));
    }

    await setSession(c, {
      email: profile.email.toLowerCase(),
      name: profile.name || profile.email,
      picture: profile.picture || "",
    });
    return c.redirect(appUrl());
  } catch (err) {
    console.error("OAuth callback error:", err);
    return c.redirect(appUrl("?error=oauth_failed"));
  }
});

authRouter.post("/auth/logout", (c) => {
  clearSession(c);
  return c.json({ ok: true });
});
