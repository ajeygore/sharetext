// Wire types shared by the browser and the server.
//
// Note what is absent: no field here ever carries plaintext or key material.
// The server only ever handles `ct` (ciphertext) and `iv`, both base64url.

export interface CreatePasteRequest {
  ct: string;
  iv: string;
  maxViews: number;
  ttlSeconds: number;
}

export interface CreatePasteResponse {
  id: string;
  expiresAt: string;
  maxViews: number;
}

export interface RevealPasteResponse {
  ct: string;
  iv: string;
  viewsRemaining: number;
}

export interface SessionUser {
  email: string;
  name: string;
  picture: string;
}

export interface MeResponse {
  authenticated: boolean;
  user?: SessionUser;
}

export interface PasteSummary {
  id: string;
  createdAt: string;
  maxViews: number;
  viewsRemaining: number | null; // null once the paste is gone
  expiresAt: string | null;
  revealedBy: string[];
}

export interface ApiError {
  error: string;
}

/** Plaintext ceiling, enforced client-side. */
export const MAX_PLAINTEXT_BYTES = 64 * 1024;

/**
 * Ciphertext ceiling, enforced server-side. The server cannot see the plaintext
 * length, so it bounds the encoded payload instead: 64 KB + a 16-byte GCM tag,
 * base64-expanded by 4/3, plus slack.
 */
export const MAX_CIPHERTEXT_CHARS = Math.ceil((MAX_PLAINTEXT_BYTES + 16) * 1.34) + 256;

export const TTL_OPTIONS = [
  { label: "5 minutes", seconds: 5 * 60 },
  { label: "1 hour", seconds: 60 * 60 },
  { label: "24 hours", seconds: 24 * 60 * 60 },
  { label: "7 days", seconds: 7 * 24 * 60 * 60 },
] as const;

export const MAX_VIEWS_LIMIT = 10;
export const VALID_TTLS = new Set<number>(TTL_OPTIONS.map((t) => t.seconds));
