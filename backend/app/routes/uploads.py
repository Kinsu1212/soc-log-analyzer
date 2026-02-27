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
    Deterministic confidence score (0-100) for each anomaly based on evidence strength.
    This is not ML probability. It is "how strongly the rule evidence supports the anomaly."
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

    # If we cannot compute, return a conservative default.
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

    # ratio=1.0 means just met threshold. Higher ratio means stronger evidence.
    if ratio < 1.0:
        base = 55
    else:
        # Smooth curve that saturates near 99
        import math

        k = 1.35
        base = 70 + 29 * (1 - math.exp(-k * (ratio - 1.0)))

    # Small boost when evidence context is richer
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
    Uses only supporting_stats already produced by rule engine.
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
    Deterministically build:
      - findings_by_ip: rows with bullets per IP
      - global_findings: bullets for non-IP anomalies (endpoint or overall)
    Include only IPs that triggered at least one IP-scoped anomaly.
    Sort by severity desc, anomaly count desc, request volume desc.
    """
    anomalies = results.get("anomalies", []) or []
    top_ips = results.get("top_ips", []) or []

    ip_volume = {x.get("ip"): int(x.get("count", 0)) for x in top_ips if x.get("ip")}

    findings_by_ip_map = {}  # ip -> row
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
                    "anomaly_details": [], # exposed to frontend later
                    "_anomalies": [],  # internal only, removed before returning/storing
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


def rewrite_bullets_with_groq(findings_by_ip: list) -> list:
    """
    One Groq call per upload. Rewrites bullets per IP, grounded in anomaly stats.
    Falls back to deterministic bullets if anything fails.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return findings_by_ip

    try:
        from openai import OpenAI

        compact = []
        for row in findings_by_ip:
            compact.append(
                {
                    "ip": row.get("ip"),
                    "max_severity": row.get("max_severity"),
                    "anomalies": row.get("_anomalies", []),
                }
            )

        instructions = (
            "Return ONLY valid JSON. No markdown. No extra text.\n"
            "Input is a list of IP objects with anomalies (type, severity, supporting_stats).\n"
            "Output schema:\n"
            "{\"by_ip\":[{\"ip\":\"x.x.x.x\",\"bullets\":[\"...\"]}]}\n"
            "Rules:\n"
            "- For each ip, return bullets, exactly one bullet per anomaly.\n"
            "- Each bullet must end with the anomaly type in parentheses.\n"
            "- Use ONLY numbers from supporting_stats.\n"
            "- If supporting_stats has request_count and threshold, include both.\n"
            "- If supporting_stats has minute_bucket_start, include it.\n"
            "- If supporting_stats has ip, include it.\n"
            "- Keep bullet under 140 characters when possible.\n"
            "Example for ip_minute_burst:\n"
            "\"Burst at <minute_bucket_start>: <request_count> requests (threshold <threshold>). (ip_minute_burst)\""
        )

        client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            timeout=3.0,
            max_retries=0,
        )

        t0 = time.perf_counter()
        print("GROQ: rewriting bullets...")
        resp = client.responses.create(
            model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
            instructions=instructions,
            input=json.dumps(compact),
            max_output_tokens=600,
        )
        dt = time.perf_counter() - t0
        print(f"GROQ: rewrite done in {dt:.2f}s")

        text = (resp.output_text or "").strip()
        data = json.loads(text)

        by_ip = {
            x.get("ip"): x.get("bullets", [])
            for x in (data.get("by_ip") or [])
            if isinstance(x, dict) and x.get("ip")
        }

        for row in findings_by_ip:
            ip = row.get("ip")
            bullets = by_ip.get(ip)
            if isinstance(bullets, list) and bullets:
                cleaned = []
                for b in bullets:
                    b = str(b).strip().replace("\n", " ").replace("\r", " ")
                    if b:
                        cleaned.append(b)
                if cleaned:
                    row["bullets"] = cleaned

        return findings_by_ip

    except Exception as e:
        print(f"GROQ: rewrite failed, using deterministic bullets. error={repr(e)}")
        return findings_by_ip


def analyze_log_file(file_stream) -> dict:
    """
    Apache/Nginx access log parsing + rule-based anomalies + timeline buckets.
    Deterministic detection only. AI only rewrites bullets later.
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

    from collections import Counter, defaultdict  # local import to keep scope clear

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

    top_ips = [{"ip": ip, "count": cnt} for ip, cnt in ip_counter.most_common(5)]
    anomalies = []

    # Rule 1: Burst from a single IP (file-level)
    BURST_THRESHOLD = 50
    if ip_counter:
        top_ip, top_count = ip_counter.most_common(1)[0]
        if top_count >= BURST_THRESHOLD:
            anomaly = {
                "type": "ip_request_burst",
                "severity": "medium",
                "explanation": f"High request volume from a single IP ({top_ip}) in this upload.",
                "supporting_stats": {
                    "ip": top_ip,
                    "request_count": top_count,
                    "threshold": BURST_THRESHOLD,
                    "total_lines": len(lines),
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 1b: Burst from a single IP within a single minute bucket
    IP_MINUTE_BURST_THRESHOLD = 30
    if ip_minute_counts:
        (burst_ip, burst_minute), burst_count = max(ip_minute_counts.items(), key=lambda x: x[1])
        if burst_count >= IP_MINUTE_BURST_THRESHOLD:
            anomaly = {
                "type": "ip_minute_burst",
                "severity": "high",
                "explanation": f"High request burst from IP ({burst_ip}) within a 1-minute window.",
                "supporting_stats": {
                    "ip": burst_ip,
                    "minute_bucket_start": burst_minute,
                    "request_count": burst_count,
                    "threshold": IP_MINUTE_BURST_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

            bucket_anomalies[burst_minute].append(
                {
                    "type": "ip_minute_burst",
                    "ip": burst_ip,
                    "request_count": burst_count,
                    "threshold": IP_MINUTE_BURST_THRESHOLD,
                }
            )

    # Rule 2: Repeated 401/403 from a single IP
    AUTH_FAIL_THRESHOLD = 10
    if auth_fail_counter:
        worst_ip, worst_count = auth_fail_counter.most_common(1)[0]
        if worst_count >= AUTH_FAIL_THRESHOLD:
            anomaly = {
                "type": "repeated_auth_failures",
                "severity": "medium",
                "explanation": f"Repeated 401/403 responses from IP ({worst_ip}). Possible brute force or probing.",
                "supporting_stats": {
                    "ip": worst_ip,
                    "auth_fail_count": worst_count,
                    "threshold": AUTH_FAIL_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 3: Excessive hits to suspicious paths
    SUSPICIOUS_PATHS_THRESHOLD = 5
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

    # Rule 4: 5xx spike (service instability)
    SERVER_ERROR_THRESHOLD = 10
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

    # Rule 6: Excessive 404s from a single IP (possible enumeration)
    NOT_FOUND_THRESHOLD = 20
    if not_found_counter:
        nf_ip, nf_count = not_found_counter.most_common(1)[0]
        if nf_count >= NOT_FOUND_THRESHOLD:
            anomaly = {
                "type": "excessive_404s",
                "severity": "medium",
                "explanation": f"High number of 404 responses from IP ({nf_ip}). Possible path enumeration/scanning.",
                "supporting_stats": {
                    "ip": nf_ip,
                    "not_found_count": nf_count,
                    "threshold": NOT_FOUND_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 7: High number of unique paths from a single IP (possible scanning/crawling)
    UNIQUE_PATHS_THRESHOLD = 30
    if unique_paths_per_ip:
        up_ip, paths_set = max(unique_paths_per_ip.items(), key=lambda x: len(x[1]))
        unique_count = len(paths_set)
        if unique_count >= UNIQUE_PATHS_THRESHOLD:
            anomaly = {
                "type": "high_unique_paths",
                "severity": "medium",
                "explanation": f"IP ({up_ip}) accessed many unique paths. Possible automated scanning/crawling.",
                "supporting_stats": {
                    "ip": up_ip,
                    "unique_paths_count": unique_count,
                    "threshold": UNIQUE_PATHS_THRESHOLD,
                    "sample_paths": sorted(list(paths_set))[:10],
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    # Rule 8: 5xx concentrated on a single endpoint
    ENDPOINT_5XX_THRESHOLD = 8
    if endpoint_5xx_counter:
        bad_path, bad_count = endpoint_5xx_counter.most_common(1)[0]
        if bad_count >= ENDPOINT_5XX_THRESHOLD:
            anomaly = {
                "type": "endpoint_5xx_hotspot",
                "severity": "high",
                "explanation": f"High number of 5xx responses concentrated on endpoint ({bad_path}).",
                "supporting_stats": {
                    "path": bad_path,
                    "5xx_count": bad_count,
                    "threshold": ENDPOINT_5XX_THRESHOLD,
                },
            }
            anomaly["confidence"] = compute_confidence(anomaly["type"], anomaly["supporting_stats"])
            anomalies.append(anomaly)

    timeline = [
        {
            "bucket_start": k,
            "requests": bucket_counts[k],
            "status_counts": bucket_status_counts.get(k, {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}),
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

    # Optional: Groq polish for bullets, one call per upload
    results["findings_by_ip"] = rewrite_bullets_with_groq(results["findings_by_ip"])

    # Remove internal anomalies list before saving/returning
    for row in results["findings_by_ip"]:
        row.pop("_anomalies", None)

    # Simple summary for frontend
    results["ai_summary"] = f"{len(results['findings_by_ip'])} IP(s) with anomalies."

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

    return jsonify(
        {
            "id": r.id,
            "filename": r.filename,
            "uploaded_at": r.uploaded_at.isoformat(),
            "ai_summary": r.results_json.get("ai_summary"),
            "findings_by_ip": r.results_json.get("findings_by_ip", []),
            "global_findings": r.results_json.get("global_findings", []),
        }
    ), 200