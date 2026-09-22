import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { AdminApi, setCsrfToken, type AdminUser } from "./api";

type AuthState = {
  user: AdminUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AdminUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await AdminApi.me();
      setUser(me.user);
      setCsrfToken(me.csrf_token);
    } catch {
      setUser(null);
      setCsrfToken(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    const result = await AdminApi.login(username, password);
    setUser(result.user);
    setCsrfToken(result.csrf_token);
  }, []);

  const logout = useCallback(async () => {
    try {
      await AdminApi.logout();
    } finally {
      setUser(null);
      setCsrfToken(null);
    }
  }, []);

  const value = useMemo(
    () => ({ user, loading, login, logout, refresh }),
    [user, loading, login, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth requires AuthProvider");
  return ctx;
}
