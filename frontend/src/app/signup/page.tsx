"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { getToken } from "@/lib/api";
import { signup } from "@/lib/auth";

export default function SignupPage() {
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    // if already logged in, go to upload
    const token = getToken();
    if (token) router.replace("/upload");
  }, [router]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setLoading(true);

    try {
      await signup(email, password);
      router.replace("/upload");
    } catch (e: any) {
      setErr(e?.message ?? "Signup failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen p-6 bg-linear-to-b from-slate-950 via-slate-900 to-slate-950 text-slate-100 flex items-center justify-center">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/70 shadow-lg shadow-black/30 backdrop-blur p-6">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold">Sign up</h1>
          <p className="mt-1 text-sm text-slate-400">SOC Log Analyzer</p>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-slate-300 mb-1">Email</label>
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              type="email"
              placeholder="you@example.com"
              className="w-full rounded-xl border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
              autoComplete="email"
              required
            />
          </div>

          <div>
            <label className="block text-sm text-slate-300 mb-1">Password</label>
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              placeholder="Create a strong password"
              className="w-full rounded-xl border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
              autoComplete="new-password"
              required
            />
          </div>

          {err && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200 shadow-lg shadow-black/20 backdrop-blur">
              {err}
            </div>
          )}

          <button
            disabled={loading}
            className="w-full rounded-xl border border-slate-700 bg-slate-950/30 px-4 py-2 text-sm text-slate-100 hover:bg-slate-800/50 disabled:opacity-60 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
          >
            {loading ? "Creating account..." : "Create account"}
          </button>
        </form>

        <div className="mt-4 text-sm text-slate-400">
          Already have an account?{" "}
          <Link
            href="/login"
            className="text-slate-100 underline underline-offset-4 hover:text-cyan-200"
          >
            Log in
          </Link>
        </div>
      </div>
    </div>
  );
}