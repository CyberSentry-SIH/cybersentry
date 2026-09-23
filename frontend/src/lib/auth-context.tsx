"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import { api } from "@/lib/api";
import type { CurrentUser, UserRole } from "@/types";
import type { User as ApiUser } from "@/types/api";

function toCurrentUser(u: ApiUser): CurrentUser {
  const initials = (u.full_name || u.email || "?")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase())
    .join("") || "?";

  const role: UserRole = u.role === "ADMINISTRATOR" ? "administrator" : "analyst";

  return {
    id: u.id,
    name: u.full_name || u.email,
    initials,
    role,
    organization: "CyberSentry Workspace",
  };
}

interface AuthContextValue {
  user: CurrentUser | null;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  loading: true,
  refresh: async () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const me = await api.getMe();
      setUser(toCurrentUser(me));
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Ignore — we still clear local state below and force a redirect.
    } finally {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <AuthContext.Provider value={{ user, loading, refresh, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

/** Real, session-backed replacement for the old lib/mock/current-user adapter. */
export function useCurrentUser(): CurrentUser | null {
  return useContext(AuthContext).user;
}

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}
