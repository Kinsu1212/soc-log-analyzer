import { apiFetch } from "./api";

export type AnomalyDetail = {
  type: string;
  severity: "low" | "medium" | "high";
  confidence: number;
  bullet: string;
};

export type FindingRow = {
  ip: string;
  max_severity: "low" | "medium" | "high";
  anomaly_types: string[];
  bullets: string[];
  anomaly_details?: AnomalyDetail[];
};

export type GlobalFinding = {
  type: string;
  severity: "low" | "medium" | "high";
  bullet: string;
  confidence?: number;
  supporting_stats?: Record<string, any>;
};

export type UploadResponse = {
  id: number;
  filename: string;
  uploaded_at: string;
  ai_summary: string;

  // new fields from backend
  total_ips_observed: number;
  flagged_ips: number;

  findings_by_ip: FindingRow[];
  global_findings: GlobalFinding[];
};

export async function uploadLogFile(file: File) {
  const form = new FormData();
  form.append("file", file);

  return apiFetch<UploadResponse>("/api/uploads", {
    method: "POST",
    body: form,
    auth: true,
  });
}

export type UploadListItem = {
  id: number;
  filename: string;
  uploaded_at: string;
};

export async function listUploads() {
  return apiFetch<UploadListItem[]>("/api/uploads", { auth: true });
}

export async function getUpload(id: number) {
  return apiFetch<UploadResponse>(`/api/uploads/${id}`, { auth: true });
}