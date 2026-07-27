import { createContext, useContext, useEffect, useState } from "react";
import { api, setToken, getToken } from "./api";

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then(setUser)
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
  }, []);

  async function login(email, password) {
    const res = await api.login(email, password);
    setToken(res.access_token);
    setUser(res.user);
    return res.user;
  }
  async function register(name, email, password) {
    const res = await api.register(name, email, password);
    setToken(res.access_token);
    setUser(res.user);
    return res.user;
  }
  async function loginWithToken(token) {
    setToken(token);
    const u = await api.me();
    setUser(u);
    return u;
  }
  function logout() {
    setToken(null);
    setUser(null);
  }
  function updateUser(patch) {
    setUser((u) => (u ? { ...u, ...patch } : u));
  }

  return (
    <AuthCtx.Provider value={{ user, loading, login, register, logout, loginWithToken, updateUser }}>
      {children}
    </AuthCtx.Provider>
  );
}

export function useAuth() {
  return useContext(AuthCtx);
}
