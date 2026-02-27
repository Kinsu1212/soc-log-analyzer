# backend/app/routes/uploads.py
import os
import json
import time
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from ..extensions import db
from ..models import Upload

uploads_bp = Blueprint("uploads", __name__, url_prefix="/api/uploads")

ALLOWED_EXTENSIONS = {".log", ".txt"}

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS


def _severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "").lower(), 0)


def _clamp_int(x: float, lo: int = 0, hi: int = 100) -> int:
    try:
        v = int(round(float(x)))
    except Exception:
        v = lo
    return max(lo, min(hi, v))


def compute_confidence(anomaly_type: str, stats: dict) -> int:
    """
    Deterministic confidence score (1-99) based on evidence strength.
    This is not ML probability.
    """
    stats = stats or {}
    threshold = stats.get("threshold")

    observed_key_by_type = {
        "ip_minute_burst": "request_count",
        "ip_request_burst": "request_count",
        "repeated_auth_failures": "auth_fail_count",
        "excessive_404s": "not_found_count",
        "high_unique_paths": "unique_paths_count",
        "server_error_spike": "5xx_count",
        "endpoint_5xx_hotspot": "5xx_count",
        "suspicious_paths_activity": "suspicious_paths_hits",
    }

    observed_key = observed_key_by_type.get(anomaly_type)
    observed = stats.get(observed_key) if observed_key else None

    if threshold is None or observed is None:
        return 70

    try:
        threshold_f = float(threshold)
        observed_f = float(observed)
    except Exception:
        return 70

    if threshold_f <= 0:
        return 70

    ratio = observed_f / threshold_f

    if ratio < 1.0:
        base = 55
    else:
        import math

        k = 1.35
        base = 70 + 29 * (1 - math.exp(-k * (ratio - 1.0)))

    evidence_boost = 0
    if stats.get("minute_bucket_start"):
        evidence_boost += 2
    if isinstance(stats.get("sample_paths"), list) and len(stats["sample_paths"]) >= 5:
        evidence_boost += 2
    if stats.get("total_lines") and int(stats.get("total_lines", 0)) >= 500:
        evidence_boost += 1

    return _clamp_int(base + evidence_boost, 1, 99)


def format_anomaly_bullet(a: dict) -> str:
    """
    Deterministic human bullet. Includes anomaly type at end.
    """
    a_type = a.get("type", "") or ""
    stats = a.get("supporting_stats", {}) or {}
    ip = stats.get("ip")
    bucket = stats.get("minute_bucket_start")
    path = stats.get("path")

    if a_type == "ip_minute_burst":
        return (
            f"Burst in 1 minute at {bucket}: {stats.get('request_count')} requests "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )
    if a_type == "ip_request_burst":
        return (
            f"High volume from IP {ip}: {stats.get('request_count')} requests "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )
    if a_type == "repeated_auth_failures":
        return (
            f"Auth failures from IP {ip}: {stats.get('auth_fail_count')} "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )
    if a_type == "excessive_404s":
        return (
            f"404 enumeration from IP {ip}: {stats.get('not_found_count')} "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )
    if a_type == "high_unique_paths":
        return (
            f"Many unique paths from IP {ip}: {stats.get('unique_paths_count')} "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )
    if a_type == "server_error_spike":
        return (
            f"Service instability: 5xx={stats.get('5xx_count')} "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )
    if a_type == "endpoint_5xx_hotspot":
        return (
            f"5xx hotspot on {path}: {stats.get('5xx_count')} "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )
    if a_type == "suspicious_paths_activity":
        return (
            f"Sensitive path scanning: hits={stats.get('suspicious_paths_hits')} "
            f"(threshold {stats.get('threshold')}). ({a_type})"
        )

    expl = (a.get("explanation") or "").strip()
    if expl and a_type:
        return f"{expl} ({a_type})"
    if expl:
        return expl
    return f"Anomaly detected ({a_type})."


def build_findings_tables(results: dict) -> dict:
    """
    Build:
      - findings_by_ip: rows with anomaly_details per IP
      - global_findings: bullets for non-IP anomalies
    Include only IPs that triggered at least one IP-scoped anomaly.
    Sort by severity desc, anomaly count desc, request volume desc.
    """
    anomalies = results.get("anomalies", []) or []
    top_ips = results.get("top_ips", []) or []

    ip_volume = {x.get("ip"): int(x.get("count", 0)) for x in top_ips if x.get("ip")}

    findings_by_ip_map = {}
    global_findings = []

    for a in anomalies:
        a_type = a.get("type", "") or ""
        sev = a.get("severity", "low") or "low"
        stats = a.get("supporting_stats", {}) or {}
        ip = stats.get("ip")

        if ip:
            row = findings_by_ip_map.get(ip)
            if not row:
                row = {
                    "ip": ip,
                    "max_severity": sev,
                    "anomaly_types": [],
                    "bullets": [],
                    "anomaly_details": [],
                    "_anomalies": [],
                }
                findings_by_ip_map[ip] = row

            if _severity_rank(sev) > _severity_rank(row["max_severity"]):
                row["max_severity"] = sev

            if a_type and a_type not in row["anomaly_types"]:
                row["anomaly_types"].append(a_type)

            bullet = format_anomaly_bullet(a)

            row["bullets"].append(bullet)
            row["anomaly_details"].append(
                {
                    "type": a_type,
                    "severity": sev,
                    "confidence": a.get("confidence"),
                    "bullet": bullet,
                }
            )
            row["_anomalies"].append(a)
        else:
            bullet = format_anomaly_bullet(a)
            global_findings.append(
                {
                    "type": a_type,
                    "severity": sev,
                    "confidence": a.get("confidence"),
                    "bullet": bullet,
                    "supporting_stats": stats,
                }
            )

    rows = list(findings_by_ip_map.values())

    rows.sort(
        key=lambda r: (
            -_severity_rank(r.get("max_severity")),
            -len(r.get("_anomalies", [])),
            -ip_volume.get(r.get("ip"), 0),
        )
    )

    return {"findings_by_ip": rows, "global_findings": global_findings}


def _parse_type_from_bullet(b: str) -> str:
    """
    Extract anomaly type from a bullet suffix like: "... (ip_minute_burst)"
    """
    if not b:
        return ""
    b = str(b).strip()
    if not b.endswith(")"):
        return ""
    i = b.rfind("(")
    if i == -1:
        return ""
    t = b[i + 1 : -1].strip()
    return t


def rewrite_high_severity_bullets_with_groq(findings_by_ip: list) -> list:
    """
    One Groq call per upload (when small enough).
    Rewrites bullets ONLY for high severity anomalies.
    Deterministic bullets remain as fallback and for non-high anomalies.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return findings_by_ip

    try:
        from openai import OpenAI

        high_rows = []
        total_high_anoms = 0

        for row in findings_by_ip:
            high_anoms = [
                a for a in (row.get("_anomalies") or []) if (a.get("severity") == "high")
            ]
            if high_anoms:
                high_rows.append(
                    {
                        "ip": row.get("ip"),
                        "max_severity": row.get("max_severity"),
                        "anomalies": high_anoms,
                    }
                )
                total_high_anoms += len(high_anoms)

        # Safety gates: keep this reliable for a take-home prototype
        # If too many high anomalies, skip AI rewrite to avoid timeouts / token limits.
        MAX_HIGH_ANOMS_FOR_GROQ = 25
        MAX_IPS_FOR_GROQ = 20
        if total_high_anoms == 0:
            return findings_by_ip
        if total_high_anoms > MAX_HIGH_ANOMS_FOR_GROQ or len(high_rows) > MAX_IPS_FOR_GROQ:
            return findings_by_ip

        instructions = (
            "Return ONLY valid JSON. No markdown. No extra text.\n"
            "Input is a list of IP objects with HIGH severity anomalies only.\n"
            "Output schema:\n"
            "{\"by_ip\":[{\"ip\":\"x.x.x.x\",\"bullets\":[\"...\"]}]}\n"
            "Rules:\n"
            "- For each ip, return bullets, exactly one bullet per anomaly.\n"
            "- Each bullet must end with the anomaly type in parentheses.\n"
            "- Use ONLY numbers from supporting_stats.\n"
            "- Keep bullet under 140 characters when possible.\n"
        )

        client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            timeout=4.0,
            max_retries=0,
        )

        t0 = time.perf_counter()
        resp = client.chat.completions.create(
            model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
            messages=[
                {"role": "system", "content": instructions},
                {"role": "user", "content": json.dumps(high_rows)},
            ],
            temperature=0,
            max_tokens=900,
        )
        text = (resp.choices[0].message.content or "").strip()
        groq_json = json.loads(text)

        by_ip = {
            x.get("ip"): x.get("bullets", [])
            for x in (groq_json.get("by_ip") or [])
            if isinstance(x, dict) and x.get("ip")
        }

        # Apply rewrites to anomaly_details for high severity only, matched by type suffix.
        for row in findings_by_ip:
            ip = row.get("ip")
            new_bullets = by_ip.get(ip)
            if not isinstance(new_bullets, list) or not new_bullets:
                continue

            # Map type -> rewritten bullet
            rewrite_map = {}
            for b in new_bullets:
                b = str(b).strip().replace("\n", " ").replace("\r", " ")
                if not b:
                    continue
                t = _parse_type_from_bullet(b)
                if t:
                    rewrite_map[t] = b

            if not rewrite_map:
                continue

            for d in row.get("anomaly_details") or []:
                if d.get("severity") == "high":
                    t = d.get("type")
                    if t in rewrite_map:
                        d["bullet"] = rewrite_map[t]

            # Rebuild row["bullets"] from anomaly_details to keep alignment
            row["bullets"] = [d.get("bullet") for d in (row.get("anomaly_details") or []) if d.get("bullet")]

        return findings_by_ip

    except Exception:
        return findings_by_ip


def analyze_log_file(file_stream) -> dict:
    """
    Apache/Nginx access log parsing + rule-based anomalies + timeline buckets.
    Deterministic detection. AI only rewrites some bullets later.
    """
    import re
    from collections import Counter, defaultdict

    line_re = re.compile(
        r'^(?P<ip>\S+)\s+.*?"(?P<method>[A-Z]+)\s+(?P<path>\S+).*?"\s+(?P<status>\d{3})\b'
    )
    ts_re = re.compile(r"\[(?P<ts>[^\]]+)\]")

    suspicious_prefixes = ("/admin", "/.env", "/wp-login.php")

    content = file_stream.read().decode("utf-8", errors="replace")
    lines = [ln for ln in content.splitlines() if ln.strip()]

    ip_counter = Counter()
    endpoint_5xx_counter = Counter()
    auth_fail_counter = Counter()
    not_found_counter = Counter()

    status_buckets = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    suspicious_hits = 0

    bucket_counts = defaultdict(int)
    ip_minute_counts = defaultdict(int)  # (ip, bucket_iso) -> count
    bucket_status_counts = defaultdict(lambda: {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0})
    unique_paths_per_ip = defaultdict(set)
    bucket_anomalies = defaultdict(list)

    for ln in lines:
        bucket_iso = None
        ts_m = ts_re.search(ln)
        if ts_m:
            ts_str = ts_m.group("ts")
            try:
                dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
                bucket_dt = dt.replace(second=0, microsecond=0)
                bucket_iso = bucket_dt.isoformat()
                bucket_counts[bucket_iso] += 1
            except ValueError:
                pass

        m = line_re.search(ln)
        if not m:
            continue

        ip = m.group("ip")
        path = m.group("path")
        status = int(m.group("status"))

        if bucket_iso is not None:
            if 200 <= status <= 299:
                bucket_status_counts[bucket_iso]["2xx"] += 1
            elif 300 <= status <= 399:
                bucket_status_counts[bucket_iso]["3xx"] += 1
            elif 400 <= status <= 499:
                bucket_status_counts[bucket_iso]["4xx"] += 1
            elif 500 <= status <= 599:
                bucket_status_counts[bucket_iso]["5xx"] += 1

        unique_paths_per_ip[ip].add(path)

        if 500 <= status <= 599:
            endpoint_5xx_counter[path] += 1

        ip_counter[ip] += 1

        if status == 404:
            not_found_counter[ip] += 1

        if bucket_iso is not None:
            ip_minute_counts[(ip, bucket_iso)] += 1

        if status in (401, 403):
            auth_fail_counter[ip] += 1

        if 200 <= status <= 299:
            status_buckets["2xx"] += 1
        elif 300 <= status <= 399:
            status_buckets["3xx"] += 1
        elif 400 <= status <= 499:
            status_buckets["4xx"] += 1
        elif 500 <= status <= 599:
            status_buckets["5xx"] += 1

        if path.startswith(suspicious_prefixes):
            suspicious_hits += 1

    # Sorting helper for UI ordering (not a detection limit)
    top_ips = [{"ip": ip, "count": cnt} for ip, cnt in ip_counter.most_common(20)]
    anomalies = []

    # Cap per rule to keep payload and UI manageable for a prototype
    MAX_FINDINGS_PER_RULE = 50

    # Thresholds tuned for better coverage in typical test logs
    BURST_THRESHOLD = 40
    IP_MINUTE_BURST_THRESHOLD = 25
    AUTH_FAIL_THRESHOLD = 6
    SUSPICIOUS_PATHS_THRESHOLD = 4
    SERVER_ERROR_THRESHOLD = 8
    NOT_FOUND_THRESHOLD = 12
    UNIQUE_PATHS_THRESHOLD = 20
    ENDPOINT_5XX_THRESHOLD = 6

    # Rule 1: File-level high request volume per IP
    if ip_counter:
        hits = [(ip, cnt) for ip, cnt in ip_counter.items() if cnt >= BURST_THRESHOLD]
        hits.sort(key=lambda x: x[1], reverse=True)
        for ip, cnt in hits[:MAX_FINDINGS_PER_RULE]:
            anomaly = {
                "type": "ip_request_burst",
                "severity": "medium",
                "explanation": f"High request volume from a single IP ({ip}) in this upload.",
                "supporting_stats": {
                    "ip": ip,
                    "request_count": cnt,
                    "threshold": BURST_THRESHOLD,
                    "total_lines": len(lines),
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 1b: Per-minute burst per IP
    if ip_minute_counts:
        hits = [
            ((ip, bucket), cnt)
            for (ip, bucket), cnt in ip_minute_counts.items()
            if cnt >= IP_MINUTE_BURST_THRESHOLD
        ]
        hits.sort(key=lambda x: x[1], reverse=True)
        for ((ip, bucket), cnt) in hits[:MAX_FINDINGS_PER_RULE]:
            anomaly = {
                "type": "ip_minute_burst",
                "severity": "high",
                "explanation": f"High request burst from IP ({ip}) within a 1-minute window.",
                "supporting_stats": {
                    "ip": ip,
                    "minute_bucket_start": bucket,
                    "request_count": cnt,
                    "threshold": IP_MINUTE_BURST_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

            bucket_anomalies[bucket].append(
                {
                    "type": "ip_minute_burst",
                    "ip": ip,
                    "request_count": cnt,
                    "threshold": IP_MINUTE_BURST_THRESHOLD,
                }
            )

    # Rule 2: Repeated auth failures per IP
    if auth_fail_counter:
        hits = [(ip, cnt) for ip, cnt in auth_fail_counter.items() if cnt >= AUTH_FAIL_THRESHOLD]
        hits.sort(key=lambda x: x[1], reverse=True)
        for ip, cnt in hits[:MAX_FINDINGS_PER_RULE]:
            anomaly = {
                "type": "repeated_auth_failures",
                "severity": "medium",
                "explanation": f"Repeated 401/403 responses from IP ({ip}). Possible brute force or probing.",
                "supporting_stats": {
                    "ip": ip,
                    "auth_fail_count": cnt,
                    "threshold": AUTH_FAIL_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 3: Suspicious path hits (global)
    if suspicious_hits >= SUSPICIOUS_PATHS_THRESHOLD:
        anomaly = {
            "type": "suspicious_paths_activity",
            "severity": "medium",
            "explanation": "High number of requests to sensitive paths (/admin, /.env, /wp-login.php). Possible scanning.",
            "supporting_stats": {
                "suspicious_paths_hits": suspicious_hits,
                "threshold": SUSPICIOUS_PATHS_THRESHOLD,
            },
        }
        anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
        anomalies.append(anomaly)

    # Rule 4: 5xx spike (global)
    if status_buckets["5xx"] >= SERVER_ERROR_THRESHOLD:
        anomaly = {
            "type": "server_error_spike",
            "severity": "high",
            "explanation": "High number of 5xx responses detected. Possible service instability or outage.",
            "supporting_stats": {
                "5xx_count": status_buckets["5xx"],
                "threshold": SERVER_ERROR_THRESHOLD,
                "total_lines": len(lines),
            },
        }
        anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
        anomalies.append(anomaly)

    # Rule 6: Excessive 404 per IP
    if not_found_counter:
        hits = [(ip, cnt) for ip, cnt in not_found_counter.items() if cnt >= NOT_FOUND_THRESHOLD]
        hits.sort(key=lambda x: x[1], reverse=True)
        for ip, cnt in hits[:MAX_FINDINGS_PER_RULE]:
            anomaly = {
                "type": "excessive_404s",
                "severity": "medium",
                "explanation": f"High number of 404 responses from IP ({ip}). Possible path enumeration/scanning.",
                "supporting_stats": {
                    "ip": ip,
                    "not_found_count": cnt,
                    "threshold": NOT_FOUND_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 7: High unique paths per IP
    if unique_paths_per_ip:
        hits = []
        for ip, paths_set in unique_paths_per_ip.items():
            cnt = len(paths_set)
            if cnt >= UNIQUE_PATHS_THRESHOLD:
                hits.append((ip, cnt, paths_set))
        hits.sort(key=lambda x: x[1], reverse=True)

        for ip, cnt, paths_set in hits[:MAX_FINDINGS_PER_RULE]:
            anomaly = {
                "type": "high_unique_paths",
                "severity": "medium",
                "explanation": f"IP ({ip}) accessed many unique paths. Possible automated scanning/crawling.",
                "supporting_stats": {
                    "ip": ip,
                    "unique_paths_count": cnt,
                    "threshold": UNIQUE_PATHS_THRESHOLD,
                    "sample_paths": sorted(list(paths_set))[:10],
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 8: Endpoint 5xx hotspot (per endpoint)
    if endpoint_5xx_counter:
        hits = [(path, cnt) for path, cnt in endpoint_5xx_counter.items() if cnt >= ENDPOINT_5XX_THRESHOLD]
        hits.sort(key=lambda x: x[1], reverse=True)
        for path, cnt in hits[:MAX_FINDINGS_PER_RULE]:
            anomaly = {
                "type": "endpoint_5xx_hotspot",
                "severity": "high",
                "explanation": f"High number of 5xx responses concentrated on endpoint ({path}).",
                "supporting_stats": {
                    "path": path,
                    "5xx_count": cnt,
                    "threshold": ENDPOINT_5XX_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    timeline = [
        {
            "bucket_start": k,
            "requests": bucket_counts[k],
            "status_counts": bucket_status_counts.get(
                k, {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
            ),
            "bucket_anomalies": bucket_anomalies.get(k, []),
        }
        for k in sorted(bucket_counts.keys())
    ]

    return {
        "summary": {
            "total_requests": len(lines),
            "unique_ips": len(ip_counter),
            "status_counts": status_buckets,
            "anomalies_count": len(anomalies),
        },
        "total_lines": len(lines),
        "status_counts": status_buckets,
        "top_ips": top_ips,
        "suspicious_paths_hits": suspicious_hits,
        "anomalies": anomalies,
        "timeline": timeline,
        "ai_summary": None,
        "findings_by_ip": [],
        "global_findings": [],
    }


@uploads_bp.post("")
@jwt_required()
def upload_and_analyze():
    user_id = int(get_jwt_identity())

    if "file" not in request.files:
        return jsonify({"error": "file is required (multipart field name must be 'file')"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "filename is required"}), 400

    if not allowed_file(f.filename):
        return jsonify({"error": "only .log or .txt files are allowed"}), 400

    results = analyze_log_file(f.stream)

    tables = build_findings_tables(results)
    results["findings_by_ip"] = tables["findings_by_ip"]
    results["global_findings"] = tables["global_findings"]

    # AI polish: rewrite only HIGH severity bullets, only when small enough
    results["findings_by_ip"] = rewrite_high_severity_bullets_with_groq(results["findings_by_ip"])

    # Remove internal anomalies list before saving/returning
    for row in results["findings_by_ip"]:
        row.pop("_anomalies", None)

    total_ips_observed = int(results.get("summary", {}).get("unique_ips", 0))
    flagged_ips = len(results.get("findings_by_ip", []))

    total_requests = int(results.get("summary", {}).get("total_requests", 0))
    anoms_count = int(results.get("summary", {}).get("anomalies_count", 0))

    high_ips = sum(1 for r in results.get("findings_by_ip", []) if r.get("max_severity") == "high")
    med_ips = sum(1 for r in results.get("findings_by_ip", []) if r.get("max_severity") == "medium")
    low_ips = sum(1 for r in results.get("findings_by_ip", []) if r.get("max_severity") == "low")

    ai_lines = [
        f"Processed {total_requests} requests from {total_ips_observed} unique IPs.",
        f"Flagged {flagged_ips} IPs across {anoms_count} anomalies (high: {high_ips}, medium: {med_ips}, low: {low_ips}).",
    ]
    results["ai_summary"] = " ".join(ai_lines)

    upload = Upload(
        user_id=user_id,
        filename=f.filename,
        uploaded_at=datetime.utcnow(),
        results_json=results,
    )

    db.session.add(upload)
    db.session.commit()

    return jsonify(
        {
            "id": upload.id,
            "filename": upload.filename,
            "uploaded_at": upload.uploaded_at.isoformat(),
            "ai_summary": upload.results_json.get("ai_summary"),
            "total_ips_observed": total_ips_observed,
            "flagged_ips": flagged_ips,
            "findings_by_ip": upload.results_json.get("findings_by_ip", []),
            "global_findings": upload.results_json.get("global_findings", []),
        }
    ), 201


@uploads_bp.get("")
@jwt_required()
def list_uploads():
    user_id = int(get_jwt_identity())

    rows = Upload.query.filter_by(user_id=user_id).order_by(Upload.uploaded_at.desc()).all()

    return jsonify(
        [
            {
                "id": r.id,
                "filename": r.filename,
                "uploaded_at": r.uploaded_at.isoformat(),
            }
            for r in rows
        ]
    ), 200


@uploads_bp.get("/<int:upload_id>")
@jwt_required()
def get_upload(upload_id: int):
    user_id = int(get_jwt_identity())

    r = Upload.query.filter_by(id=upload_id, user_id=user_id).first()
    if not r:
        return jsonify({"error": "not found"}), 404

    total_ips_observed = int((r.results_json.get("summary") or {}).get("unique_ips", 0))
    flagged_ips = len(r.results_json.get("findings_by_ip", []))

    return jsonify(
        {
            "id": r.id,
            "filename": r.filename,
            "uploaded_at": r.uploaded_at.isoformat(),
            "ai_summary": r.results_json.get("ai_summary"),
            "total_ips_observed": total_ips_observed,
            "flagged_ips": flagged_ips,
            "findings_by_ip": r.results_json.get("findings_by_ip", []),
            "global_findings": r.results_json.get("global_findings", []),
        }
    ), 200