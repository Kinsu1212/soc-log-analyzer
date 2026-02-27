"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getToken } from "@/lib/api";
import { me, logout } from "@/lib/auth";
import {
  uploadLogFile,
  listUploads,
  type UploadListItem,
} from "@/lib/uploads";

function SeverityBadge({ sev }: { sev: string }) {
  const base =
    "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border";

  if (sev === "high")
    return (
      <span className={`${base} border-red-300 bg-red-50 text-red-700`}>
        high
      </span>
    );

  if (sev === "medium")
    return (
      <span className={`${base} border-yellow-300 bg-yellow-50 text-yellow-800`}>
        medium
      </span>
    );

  return (
    <span className={`${base} border-gray-300 bg-gray-50 text-gray-700`}>
      low
    </span>
  );
}

function Chip({ text }: { text: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-gray-200 bg-white px-2 py-0.5 text-xs text-gray-700">
      {text}
    </span>
  );
}

function ConfidenceChip({ value }: { value?: number }) {
  if (value === undefined || value === null) return null;

  return (
    <span className="inline-flex items-center rounded-full border border-gray-200 bg-white px-2 py-0.5 text-xs text-gray-700">
      Conf {value}
    </span>
  );
}

export default function UploadPage() {
  const router = useRouter();

  const [authChecking, setAuthChecking] = useState(true);

  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);


  const [recent, setRecent] = useState<UploadListItem[]>([]);
  const [loadingRecent, setLoadingRecent] = useState(false);

  const [ipQuery, setIpQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<
    "all" | "high" | "medium" | "low"
  >("all");

  useEffect(() => {
    async function checkAuth() {
      const token = getToken();

      if (!token) {
        router.replace("/login");
        return;
      }

      try {
        await me();
        setAuthChecking(false);
      } catch {
        logout();
        router.replace("/login");
      }
    }

    checkAuth();
  }, [router]);

  useEffect(() => {
    async function loadRecent() {
      setLoadingRecent(true);
      try {
        const items = await listUploads();
        setRecent(items);
      } catch {
        // ignore silently
      } finally {
        setLoadingRecent(false);
      }
    }

    loadRecent();
  }, []);

    async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);

    if (!file) {
        setErr("Please select a .log or .txt file");
        return;
    }

    setLoading(true);

    try {
        const res = await uploadLogFile(file);

        // refresh recent list (optional)
        const items = await listUploads();
        setRecent(items);

        // IMPORTANT: go to report page, do not show results here
        router.push(`/upload/${res.id}`);
    } catch (e: any) {
        setErr(e?.message ?? "Upload failed");
    } finally {
        setLoading(false);
    }
    }

  if (authChecking) {
    return (
      <div className="min-h-screen flex items-center justify-center text-sm text-gray-600">
        Checking session...
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 bg-linear-to-b from-slate-950 via-slate-900 to-slate-950 text-slate-100">
      <div className="mx-auto max-w-5xl space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-semibold">Upload</h1>
            <p className="mt-1 text-sm text-gray-600">
              Upload an Apache or Nginx access log (.log or .txt).
            </p>
          </div>

          <button
            className="rounded-xl border border-slate-700 bg-slate-950/30 px-4 py-2 text-sm text-slate-100 hover:bg-slate-800/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
            onClick={() => {
              logout();
              router.replace("/login");
            }}
          >
            Logout
          </button>
        </div>

        {/* Upload Form */}
        <form
          onSubmit={onSubmit}
          className="rounded-xl border border-slate-800 bg-slate-900 p-4 shadow-sm space-y-3"
        >
          <div className="space-y-3">
            <label className="block cursor-pointer rounded-xl border-2 border-dashed border-slate-600 bg-slate-950/40 p-6 text-center transition hover:border-cyan-500/60 hover:bg-slate-950/60">
                <span className="block text-sm font-medium text-slate-200">
                Click to select a log file
                </span>
                <span className="block mt-1 text-xs text-slate-400">
                .log or .txt files only
                </span>

                <input
                type="file"
                accept=".log,.txt"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                className="hidden"
                />
            </label>

            {file && (
                <div className="text-sm text-slate-300">
                Selected: <span className="font-mono">{file.name}</span>
                </div>
            )}

            <button
                disabled={loading}
                className="w-full rounded-xl border border-slate-700 bg-slate-950/30 px-4 py-2 text-sm text-slate-100 hover:bg-slate-800/50 disabled:opacity-60"
            >
                {loading ? "Analyzing..." : "Upload"}
            </button>
            </div>

          {err && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200 shadow-lg shadow-black/20 backdrop-blur">
                {err}
            </div>
            )}
        </form>
        {/* Recent Uploads */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-900">
              Recent uploads
            </h2>
            {loadingRecent && (
              <span className="text-xs text-gray-500">Loading...</span>
            )}
          </div>

          {recent.length === 0 ? (
            <div className="mt-2 text-sm text-gray-700">No uploads yet.</div>
          ) : (
            <div className="mt-3 space-y-2">
              {recent.slice(0, 10).map((u) => (
                <button
                  key={u.id}
                  className="w-full rounded-md border border-slate-800 bg-slate-950/20 px-3 py-2 text-left text-sm text-slate-100 hover:bg-slate-800/40 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                  onClick={() => router.push(`/upload/${u.id}`)}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium">{u.filename}</span>
                    <span className="text-xs text-gray-500">
                      {new Date(u.uploaded_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="text-xs text-gray-600">ID: {u.id}</div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}