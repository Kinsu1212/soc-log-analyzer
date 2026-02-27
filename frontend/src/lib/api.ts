const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL;

if (!API_BASE) {
  throw new Error("Missing NEXT_PUBLIC_API_BASE_URL in .env.local");
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("access_token");
}

export function setToken(token: string) {
  localStorage.setItem("access_token", token);
}

export function clearToken() {
  localStorage.removeItem("access_token");
}

async function parseError(res: Response): Promise<string> {
  try {
    const data = await res.json();
    return data?.error || data?.message || "Request failed";
  } catch {
    return "Request failed";
  }
}

export async function apiFetch<T>(
  path: string,
  opts: RequestInit & { auth?: boolean } = {}
): Promise<T> {
  const url = `${API_BASE}${path}`;
  const headers = new Headers(opts.headers);

  // Do not force Content-Type for FormData
  const isForm = typeof FormData !== "undefined" && opts.body instanceof FormData;

  if (!isForm && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (opts.auth) {
    const token = getToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(url, { ...opts, headers });

  if (!res.ok) {
    throw new Error(await parseError(res));
  }

  return (await res.json()) as T;
}