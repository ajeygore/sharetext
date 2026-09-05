import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { fetchMe, logout as apiLogout } from "../api";
import type { SessionUser } from "../../shared/types";

interface AuthState {
  user: SessionUser | null;
  loading: boolean;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  signOut: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // A 401 here is the normal signed-out state, not an error worth surfacing.
    fetchMe()
      .then((me) => setUser(me.user ?? null))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  async function signOut() {
    await apiLogout().catch(() => {});
    setUser(null);
  }

  return <AuthContext.Provider value={{ user, loading, signOut }}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
