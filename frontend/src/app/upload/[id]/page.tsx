"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter, useParams } from "next/navigation";
import { getToken } from "@/lib/api";
import { me, logout } from "@/lib/auth";
import { getUpload, type UploadResponse } from "@/lib/uploads";

type Severity = "all" | "high" | "medium" | "low";

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
    <span
      className={`${base} border-slate-500/30 bg-slate-500/10 text-slate-200`}
    >
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

function StatPill({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-2 text-xs text-slate-300">
      <span className="text-slate-100 font-medium">{value}</span>{" "}
      <span>{label}</span>
    </div>
  );
}

export default function UploadReportPage() {
  const router = useRouter();
  const params = useParams();
  const uploadId = Number(params?.id);

  const [expandedIps, setExpandedIps] = useState<Record<string, boolean>>({});
  const [authChecking, setAuthChecking] = useState(true);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [data, setData] = useState<UploadResponse | null>(null);

  const [ipQuery, setIpQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity>("all");
  const [anomalyFilter, setAnomalyFilter] = useState("all");

  // pagination
  const PAGE_SIZE = 10;
  const [page, setPage] = useState(1);

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

  const rows = data?.findings_by_ip ?? [];
  const globalCount = data?.global_findings?.length ?? 0;

  const totalIpsObserved = data?.total_ips_observed ?? 0;
  const flaggedIps = data?.flagged_ips ?? rows.length;

  const anomalyOptions = useMemo(() => {
    return Array.from(new Set(rows.flatMap((r) => r.anomaly_types ?? []))).sort();
  }, [rows]);

  const filteredRows = useMemo(() => {
    return rows.filter((r) => {
      const ipOk = ipQuery.trim()
        ? r.ip.toLowerCase().includes(ipQuery.trim().toLowerCase())
        : true;

      const sevOk =
        severityFilter === "all" ? true : r.max_severity === severityFilter;

      const anomalyOk =
        anomalyFilter === "all"
          ? true
          : (r.anomaly_types ?? []).includes(anomalyFilter);

      return ipOk && sevOk && anomalyOk;
    });
  }, [rows, ipQuery, severityFilter, anomalyFilter]);

  // Reset pagination when filters change
  useEffect(() => {
    setPage(1);
  }, [ipQuery, severityFilter, anomalyFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const startIdx = (safePage - 1) * PAGE_SIZE;
  const endIdx = startIdx + PAGE_SIZE;
  const pagedRows = filteredRows.slice(startIdx, endIdx);

  function clearFilters() {
    setIpQuery("");
    setSeverityFilter("all");
    setAnomalyFilter("all");
  }

  function bulletMatchesSelectedAnomaly(bullet: string) {
    if (anomalyFilter === "all") return true;
    return bullet.includes(`(${anomalyFilter})`);
  }

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
                <p className="mt-1 text-sm text-slate-300">
                  Upload ID: {uploadId}
                </p>
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

            {/* Small stats row */}
            <div className="flex flex-wrap gap-2">
              <StatPill label="total IPs observed" value={totalIpsObserved} />
              <StatPill label="flagged IPs" value={flaggedIps} />
              <StatPill label="global findings" value={globalCount} />
            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-800/60 shadow-lg shadow-black/20 backdrop-blur overflow-hidden">
              <div className="border-b border-slate-700 px-4 py-3">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <h2 className="text-base font-semibold text-slate-100 tracking-wide">
                    Findings by IP
                  </h2>

                  <div className="flex flex-col gap-2 md:flex-row md:items-center">
                    <div className="relative">
                      <input
                        value={ipQuery}
                        onChange={(e) => setIpQuery(e.target.value)}
                        placeholder="Search IP..."
                        className="w-full md:w-56 rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                      />
                    </div>

                    <select
                      value={severityFilter}
                      onChange={(e) =>
                        setSeverityFilter(e.target.value as Severity)
                      }
                      className="w-full md:w-40 rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                    >
                      <option value="all">Severity: all</option>
                      <option value="high">Severity: high</option>
                      <option value="medium">Severity: medium</option>
                      <option value="low">Severity: low</option>
                    </select>

                    <select
                      value={anomalyFilter}
                      onChange={(e) => setAnomalyFilter(e.target.value)}
                      className="w-full md:w-56 rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                    >
                      <option value="all">Anomaly: all</option>
                      {anomalyOptions.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>

                    <button
                      onClick={clearFilters}
                      className="rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-2 text-sm text-slate-100 hover:bg-slate-800/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                    >
                      Clear
                    </button>
                  </div>
                </div>

                <div className="mt-3 flex flex-col gap-2 md:flex-row md:items-center md:justify-between text-xs text-slate-300">
                  <div>
                    Showing{" "}
                    <span className="text-slate-100 font-medium">
                      {filteredRows.length === 0 ? 0 : startIdx + 1}
                    </span>{" "}
                    to{" "}
                    <span className="text-slate-100 font-medium">
                      {Math.min(endIdx, filteredRows.length)}
                    </span>{" "}
                    of{" "}
                    <span className="text-slate-100 font-medium">
                      {filteredRows.length}
                    </span>{" "}
                    filtered IPs
                  </div>

                  {/* Pagination controls */}
                  <div className="flex items-center gap-2">
                    <button
                      className="rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-1.5 text-xs text-slate-100 hover:bg-slate-800/50 disabled:opacity-50 disabled:hover:bg-slate-950/30"
                      disabled={safePage <= 1}
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                    >
                      Prev
                    </button>

                    <div className="rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-1.5 text-xs text-slate-200">
                      Page <span className="text-slate-100">{safePage}</span> of{" "}
                      <span className="text-slate-100">{totalPages}</span>
                    </div>

                    <button
                      className="rounded-xl border border-slate-700 bg-slate-950/30 px-3 py-1.5 text-xs text-slate-100 hover:bg-slate-800/50 disabled:opacity-50 disabled:hover:bg-slate-950/30"
                      disabled={safePage >= totalPages}
                      onClick={() =>
                        setPage((p) => Math.min(totalPages, p + 1))
                      }
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>

              {filteredRows.length === 0 ? (
                <div className="p-4 text-sm text-slate-300">
                  No IP findings match the current filters.
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
                      {pagedRows.map((row) => {
                        const allDetails =
                          row.anomaly_details && row.anomaly_details.length > 0
                            ? row.anomaly_details.map((a) => ({
                                bullet: a.bullet,
                                confidence: a.confidence,
                              }))
                            : (row.bullets ?? []).map((b) => ({
                                bullet: b,
                                confidence: undefined as number | undefined,
                              }));

                        const visibleDetails =
                          anomalyFilter === "all"
                            ? allDetails
                            : allDetails.filter((d) =>
                                bulletMatchesSelectedAnomaly(d.bullet)
                              );
                        const isExpanded = !!expandedIps[row.ip];
                        const PREVIEW_COUNT = 3;

                        const shownDetails = isExpanded
                          ? visibleDetails
                          : visibleDetails.slice(0, PREVIEW_COUNT);

                        const hiddenCount = Math.max(0, visibleDetails.length - shownDetails.length);

                        return (
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
                            {visibleDetails.length === 0 ? (
                              <div className="text-sm text-slate-300">No details for selected anomaly.</div>
                            ) : (
                              <div className="space-y-2">
                                <ul className="list-disc pl-5 space-y-2 text-slate-200">
                                  {shownDetails.map((d, idx) => (
                                    <li key={idx} className="space-y-1">
                                      <div>{d.bullet}</div>
                                      <div className="flex items-center gap-2">
                                        <ConfidenceChip value={d.confidence} />
                                      </div>
                                    </li>
                                  ))}
                                </ul>

                                {hiddenCount > 0 ? (
                                  <button
                                    type="button"
                                    className="rounded-lg border border-slate-700 bg-slate-950/30 px-3 py-1.5 text-xs text-slate-100 hover:bg-slate-800/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                                    onClick={() => setExpandedIps((prev) => ({ ...prev, [row.ip]: true }))}
                                  >
                                    See more ({hiddenCount})
                                  </button>
                                ) : (
                                  isExpanded &&
                                  visibleDetails.length > PREVIEW_COUNT && (
                                    <button
                                      type="button"
                                      className="rounded-lg border border-slate-700 bg-slate-950/30 px-3 py-1.5 text-xs text-slate-100 hover:bg-slate-800/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                                      onClick={() =>
                                        setExpandedIps((prev) => ({ ...prev, [row.ip]: false }))
                                      }
                                    >
                                      See less
                                    </button>
                                  )
                                )}
                              </div>
                            )}
                          </td>
                          </tr>
                        );
                      })}
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