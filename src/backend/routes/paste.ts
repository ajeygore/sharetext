import { Hono } from "hono";
import { requireLogin, type AppEnv } from "../middleware/auth";
import { rateLimitReveals } from "../middleware/rateLimit";
import { createPaste, revealPaste, listUserPastes } from "../services/pasteStore";
import {
  MAX_CIPHERTEXT_CHARS,
  MAX_VIEWS_LIMIT,
  VALID_TTLS,
  type CreatePasteRequest,
} from "../../shared/types";

export const pasteRouter = new Hono<AppEnv>();

pasteRouter.use("*", requireLogin);

const B64U = /^[A-Za-z0-9_-]+$/;

pasteRouter.post("/", async (c) => {
  let body: Partial<CreatePasteRequest>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed request body." }, 400);
  }

  const { ct, iv, maxViews, ttlSeconds } = body;

  // The server cannot inspect the plaintext, so it validates the envelope:
  // shape, encoding and size are the only things it is in a position to check.
  if (typeof ct !== "string" || !ct || !B64U.test(ct)) {
    return c.json({ error: "Invalid ciphertext." }, 400);
  }
  if (typeof iv !== "string" || !iv || !B64U.test(iv) || iv.length > 32) {
    return c.json({ error: "Invalid IV." }, 400);
  }
  if (ct.length > MAX_CIPHERTEXT_CHARS) {
    return c.json({ error: "Text is too large (64 KB maximum)." }, 413);
  }
  if (!Number.isInteger(maxViews) || maxViews! < 1 || maxViews! > MAX_VIEWS_LIMIT) {
    return c.json({ error: `Views must be between 1 and ${MAX_VIEWS_LIMIT}.` }, 400);
  }
  if (!Number.isInteger(ttlSeconds) || !VALID_TTLS.has(ttlSeconds!)) {
    return c.json({ error: "Invalid expiry." }, 400);
  }

  try {
    const { id, expiresAt } = await createPaste({
      ct,
      iv,
      maxViews: maxViews!,
      ttlSeconds: ttlSeconds!,
      createdBy: c.get("user").email,
    });
    return c.json({ id, expiresAt: expiresAt.toISOString(), maxViews }, 201);
  } catch (err) {
    console.error("createPaste failed:", err);
    return c.json({ error: "Could not store the text. Try again." }, 503);
  }
});

pasteRouter.post("/:id/reveal", rateLimitReveals, async (c) => {
  const id = c.req.param("id");
  if (!id || id.length > 64 || !B64U.test(id)) {
    // Same response as a genuine miss — see below.
    return c.json({ error: "This text is no longer available." }, 404);
  }

  try {
    const result = await revealPaste(id, c.get("user").email);

    // "Never existed", "expired" and "already used up" all answer identically.
    // Distinguishing them would confirm to a prober that a given id was once
    // real, and leak the timing of other people's reads.
    if (!result) return c.json({ error: "This text is no longer available." }, 404);

    return c.json(result);
  } catch (err) {
    console.error("revealPaste failed:", err);
    return c.json({ error: "Could not retrieve the text. Try again." }, 503);
  }
});

pasteRouter.get("/mine", async (c) => {
  try {
    return c.json({ pastes: await listUserPastes(c.get("user").email) });
  } catch (err) {
    console.error("listUserPastes failed:", err);
    return c.json({ error: "Could not load your history." }, 503);
  }
});
