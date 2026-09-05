import type { Context, Next } from "hono";
import { getSignedCookie, setSignedCookie, deleteCookie } from "hono/cookie";
import {
  BASE_PATH,
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  SESSION_SECRET,
  USE_SECURE_COOKIES,
} from "../config";
import type { SessionUser } from "../../shared/types";

export type AppEnv = { Variables: { user: SessionUser } };

/**
 * The session is the user record. There is no user table: everything the app
 * needs about a signed-in person (email, name, avatar) fits in the signed
 * cookie, and pastes are keyed by email. One less datastore to run and secure.
 */
export async function setSession(c: Context, user: SessionUser): Promise<void> {
  await setSignedCookie(c, SESSION_COOKIE, JSON.stringify(user), SESSION_SECRET, {
    path: BASE_PATH || "/",
    httpOnly: true,
    secure: USE_SECURE_COOKIES,
    sameSite: "Lax",
    maxAge: SESSION_MAX_AGE,
  });
}

export function clearSession(c: Context): void {
  deleteCookie(c, SESSION_COOKIE, { path: BASE_PATH || "/" });
}

export async function getSessionUser(c: Context): Promise<SessionUser | null> {
  try {
    const raw = await getSignedCookie(c, SESSION_SECRET, SESSION_COOKIE);
    if (!raw) return null;
    const user = JSON.parse(raw) as SessionUser;
    return user?.email ? user : null;
  } catch {
    // Bad signature, tampered payload, or unparseable JSON — all mean no session.
    return null;
  }
}

export async function requireLogin(c: Context<AppEnv>, next: Next) {
  const user = await getSessionUser(c);
  if (!user) return c.json({ error: "Sign in with Google to continue." }, 401);
  c.set("user", user);
  return next();
}
