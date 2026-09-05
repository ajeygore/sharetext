import type {
  CreatePasteRequest,
  CreatePasteResponse,
  MeResponse,
  PasteSummary,
  RevealPasteResponse,
} from "../shared/types";

// Vite injects the mount point at build time, so the client never hardcodes
// /sharetext and the app can be remounted by changing one env var.
const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...init,
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch {
    throw new ApiError("Could not reach the server. Check your connection.", 0);
  }

  if (res.status === 204) return undefined as T;

  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError((body as { error?: string }).error || "Something went wrong.", res.status);
  }
  return body as T;
}

export const loginUrl = () => `${BASE}/auth/google`;

export const fetchMe = () => request<MeResponse>("/api/me");

export const fetchAuthConfig = () =>
  request<{ googleConfigured: boolean; devLogin: boolean }>("/api/auth/config");

export const devLogin = (email: string) =>
  request<{ ok: boolean }>("/auth/dev-login", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
export const logout = () => request<{ ok: boolean }>("/auth/logout", { method: "POST" });

export const createPaste = (body: CreatePasteRequest) =>
  request<CreatePasteResponse>("/api/paste", { method: "POST", body: JSON.stringify(body) });

export const revealPaste = (id: string) =>
  request<RevealPasteResponse>(`/api/paste/${encodeURIComponent(id)}/reveal`, { method: "POST" });

export const fetchMyPastes = () => request<{ pastes: PasteSummary[] }>("/api/paste/mine");
