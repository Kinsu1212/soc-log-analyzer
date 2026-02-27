"use client";

import { useEffect, useState } from "react";
import { useRouter, useParams } from "next/navigation";
import { getToken } from "@/lib/api";
import { me, logout } from "@/lib/auth";
import { getUpload, type UploadResponse } from "@/lib/uploads";

function SeverityBadge({ sev }: { sev: string }) {
  const base =
    "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border";

  if (sev === "high")
    return (
      <span className={`${base} border-red-500/30 bg-red-500/10 text-red-200`}>
        high
      </span>
    );

  if (sev === "medium")
    return (
      <span
        className={`${base} border-amber-500/30 bg-amber-500/10 text-amber-200`}
      >
        medium
      </span>
    );

  return (
    <span className={`${base} border-slate-500/30 bg-slate-500/10 text-slate-200`}>
      low
    </span>
  );
}

function Chip({ text }: { text: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-700 bg-slate-950/30 px-2 py-0.5 text-xs text-slate-200">
      {text}
    </span>
  );
}

function ConfidenceChip({ value }: { value?: number }) {
  if (value === undefined || value === null) return null;

  return (
    <span className="inline-flex items-center rounded-full border border-cyan-500/25 bg-cyan-500/10 px-2 py-0.5 text-xs text-cyan-200">
      Conf {value}
    </span>
  );
}

export default function UploadReportPage() {
  const router = useRouter();
  const params = useParams();
  const uploadId = Number(params?.id);

  const [authChecking, setAuthChecking] = useState(true);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [data, setData] = useState<UploadResponse | null>(null);

  useEffect(() => {
    async function checkAuthAndLoad() {
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
        return;
      }

      if (!uploadId || Number.isNaN(uploadId)) {
        setErr("Invalid upload id");
        setLoading(false);
        return;
      }

      setLoading(true);
      setErr(null);
      try {
        const full = await getUpload(uploadId);
        setData(full);
      } catch (e: any) {
        setErr(e?.message ?? "Failed to load upload");
      } finally {
        setLoading(false);
      }
    }

    checkAuthAndLoad();
  }, [router, uploadId]);

  if (authChecking) {
    return (
      <div className="min-h-screen flex items-center justify-center text-sm text-slate-300">
        Checking session...
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 bg-linear-to-b from-slate-950 via-slate-900 to-slate-950 text-slate-100">
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3">
              <button
                className="rounded-xl border border-slate-700 bg-slate-950/30 px-4 py-2 text-sm text-slate-100 hover:bg-slate-800/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                onClick={() => router.push("/upload")}
              >
                Back
              </button>
              <div>
                <h1 className="text-2xl font-semibold">Report</h1>
                <p className="mt-1 text-sm text-slate-300">Upload ID: {uploadId}</p>
              </div>
            </div>
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

        {loading && (
          <div className="rounded-xl border border-slate-700 bg-slate-800/60 p-4 shadow-lg shadow-black/20 backdrop-blur text-sm text-slate-200">
            Loading report...
          </div>
        )}

        {err && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {err}
          </div>
        )}

        {data && (
          <div className="space-y-6">
            <div className="rounded-xl border border-slate-700 bg-slate-800/60 px-4 py-3 text-sm text-slate-100 shadow-lg shadow-black/20 backdrop-blur">
              <span className="font-medium">Summary:</span> {data.ai_summary}
            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-800/60 shadow-lg shadow-black/20 backdrop-blur overflow-hidden">
              <div className="border-b border-slate-700 px-4 py-3">
                <h2 className="text-base font-semibold text-slate-100 tracking-wide">
                  Findings by IP
                </h2>
              </div>

              {data.findings_by_ip.length === 0 ? (
                <div className="p-4 text-sm text-slate-300">
                  No IP findings for this upload.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead className="bg-slate-800 text-slate-100">
                      <tr className="text-left">
                        <th className="px-4 py-3 font-medium">IP</th>
                        <th className="px-4 py-3 font-medium">Severity</th>
                        <th className="px-4 py-3 font-medium">Anomaly types</th>
                        <th className="px-4 py-3 font-medium">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/70">
                      {data.findings_by_ip.map((row) => (
                        <tr
                          key={row.ip}
                          className="align-top bg-slate-900/30 hover:bg-slate-900/45"
                        >
                          <td className="px-4 py-3 font-mono text-slate-100">
                            {row.ip}
                          </td>
                          <td className="px-4 py-3">
                            <SeverityBadge sev={row.max_severity} />
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-2">
                              {row.anomaly_types.map((t) => (
                                <Chip key={t} text={t} />
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            {row.anomaly_details &&
                            row.anomaly_details.length > 0 ? (
                              <ul className="list-disc pl-5 space-y-2 text-slate-200">
                                {row.anomaly_details.map((a, idx) => (
                                  <li key={idx} className="space-y-1">
                                    <div>{a.bullet}</div>
                                    <div className="flex items-center gap-2">
                                      <ConfidenceChip value={a.confidence} />
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <ul className="list-disc pl-5 space-y-1 text-slate-200">
                                {row.bullets.map((b, idx) => (
                                  <li key={idx}>{b}</li>
                                ))}
                              </ul>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {data.global_findings.length > 0 && (
              <div className="rounded-xl border border-slate-700 bg-slate-800/60 p-4 shadow-lg shadow-black/20 backdrop-blur">
                <h2 className="text-sm font-semibold text-slate-100">
                  Global findings
                </h2>
                <div className="mt-3 space-y-3">
                  {data.global_findings.map((g, idx) => (
                    <div
                      key={idx}
                      className="rounded-xl border border-slate-700 bg-slate-900/60 p-4"
                    >
                      <div className="flex items-center gap-2">
                        <SeverityBadge sev={g.severity} />
                        <span className="text-xs text-slate-300">{g.type}</span>
                        <ConfidenceChip value={g.confidence} />
                      </div>
                      <div className="mt-2 text-sm text-slate-100">
                        {g.bullet}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}