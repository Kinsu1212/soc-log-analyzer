import { apiFetch, setToken, clearToken } from "./api";

export type User = {
  id: number;
  email: string;
};

export type AuthResponse = {
  message: string;
  user: User;
  access_token: string;
};

export type MeResponse = {
  id: number;
  email: string;
  created_at: string;
};

export async function signup(email: string, password: string) {
  const data = await apiFetch<AuthResponse>("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setToken(data.access_token);
  return data.user;
}

export async function login(email: string, password: string) {
  const data = await apiFetch<AuthResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setToken(data.access_token);
  return data.user;
}

export async function me() {
  return apiFetch<MeResponse>("/api/me", { auth: true });
}

export function logout() {
  clearToken();
}