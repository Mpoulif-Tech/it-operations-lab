"""Small, deterministic tools inspired by common IT support workflows."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable
import re


TICKET_RULES = {
    "security": ("phishing", "ransomware", "malware", "compromised", "unauthorized"),
    "network": ("wifi", "network", "internet", "dns", "vpn", "latency"),
    "access": ("password", "locked", "login", "permission", "mfa", "account"),
    "hardware": ("laptop", "monitor", "printer", "keyboard", "battery", "disk"),
    "software": ("application", "software", "crash", "update", "installation", "license"),
}


def triage_ticket(subject: str, description: str, impact: int = 1, urgency: int = 1) -> dict[str, Any]:
    """Classify a support ticket and calculate an explainable priority.

    Impact and urgency are integers from 1 (low) to 3 (high). Security signals
    automatically raise the priority because they require rapid human review.
    """
    if impact not in {1, 2, 3} or urgency not in {1, 2, 3}:
        raise ValueError("impact and urgency must be between 1 and 3")

    text = f"{subject} {description}".lower()
    scores = {
        category: sum(1 for keyword in keywords if keyword in text)
        for category, keywords in TICKET_RULES.items()
    }
    category = max(scores, key=scores.get) if max(scores.values(), default=0) else "general"
    score = impact + urgency + (2 if category == "security" else 0)
    priority = "P1" if score >= 7 else "P2" if score >= 5 else "P3" if score >= 3 else "P4"
    sla_hours = {"P1": 1, "P2": 4, "P3": 12, "P4": 24}[priority]
    return {
        "category": category,
        "priority": priority,
        "sla_hours": sla_hours,
        "reason": f"impact={impact}, urgency={urgency}, category={category}",
    }


def audit_asset_inventory(assets: Iterable[dict[str, Any]], stale_after_days: int = 90) -> dict[str, Any]:
    """Find duplicate IDs, incomplete assets and overdue inventory checks."""
    rows = list(assets)
    ids = [str(row.get("asset_id", "")).strip() for row in rows]
    duplicate_ids = sorted(asset_id for asset_id, count in Counter(ids).items() if asset_id and count > 1)
    missing_serial = sorted(
        str(row.get("asset_id", "unknown")) for row in rows if not str(row.get("serial", "")).strip()
    )
    now = datetime.now(timezone.utc)
    stale_assets: list[str] = []
    for row in rows:
        checked_at = row.get("checked_at")
        if not checked_at:
            stale_assets.append(str(row.get("asset_id", "unknown")))
            continue
        checked = _parse_iso_datetime(str(checked_at))
        if (now - checked).days > stale_after_days:
            stale_assets.append(str(row.get("asset_id", "unknown")))
    return {
        "asset_count": len(rows),
        "duplicate_ids": duplicate_ids,
        "missing_serial": missing_serial,
        "stale_assets": sorted(stale_assets),
        "is_clean": not (duplicate_ids or missing_serial or stale_assets),
    }


def scan_log_anomalies(lines: Iterable[str]) -> dict[str, Any]:
    """Detect operational and security signals in plain-text logs."""
    patterns = {
        "error": re.compile(r"\b(error|exception|fatal|panic)\b", re.I),
        "auth_failure": re.compile(r"\b(failed login|invalid password|unauthorized|403)\b", re.I),
        "timeout": re.compile(r"\b(timeout|timed out|504)\b", re.I),
        "resource_pressure": re.compile(r"\b(out of memory|disk full|cpu 9\d%)\b", re.I),
    }
    findings: list[dict[str, Any]] = []
    counts = Counter()
    for number, line in enumerate(lines, start=1):
        tags = [name for name, pattern in patterns.items() if pattern.search(line)]
        if tags:
            findings.append({"line": number, "tags": tags, "text": line.rstrip()})
            counts.update(tags)
    risk = "high" if counts["resource_pressure"] or counts["auth_failure"] >= 3 else "medium" if findings else "low"
    return {"risk": risk, "counts": dict(counts), "findings": findings}


def verify_backup_manifest(
    manifest: Iterable[dict[str, Any]],
    *,
    now: datetime | None = None,
    max_age_hours: int = 26,
) -> dict[str, Any]:
    """Check backup recency, completion state, size and checksum presence."""
    reference = now or datetime.now(timezone.utc)
    failures: list[dict[str, str]] = []
    checked = 0
    for item in manifest:
        checked += 1
        name = str(item.get("name", f"backup-{checked}"))
        reasons: list[str] = []
        if item.get("status") != "completed":
            reasons.append("status_not_completed")
        if int(item.get("size_bytes", 0) or 0) <= 0:
            reasons.append("empty_backup")
        if not str(item.get("sha256", "")).strip():
            reasons.append("missing_checksum")
        created = _parse_iso_datetime(str(item.get("created_at", "")))
        age_hours = (reference - created).total_seconds() / 3600
        if age_hours > max_age_hours:
            reasons.append("backup_too_old")
        if age_hours < 0:
            reasons.append("future_timestamp")
        if reasons:
            failures.append({"name": name, "reasons": ",".join(reasons)})
    return {"checked": checked, "healthy": checked > 0 and not failures, "failures": failures}


def generate_network_checklist(issue_type: str, environment: str = "office") -> list[dict[str, str]]:
    """Create a repeatable diagnostic checklist without changing any device."""
    issue = issue_type.strip().lower()
    common = [
        ("Confirm scope", "Identify affected users, devices and locations."),
        ("Capture symptoms", "Record exact error messages and timestamps."),
        ("Check physical layer", "Inspect power, cabling and link indicators."),
    ]
    specialized = {
        "wifi": [
            ("Validate association", "Confirm SSID, signal strength and authentication."),
            ("Compare zones", "Test from a known-good access point area."),
        ],
        "dns": [
            ("Compare resolution", "Test hostname and direct IP connectivity."),
            ("Inspect resolver", "Confirm the assigned DNS server and cache state."),
        ],
        "vpn": [
            ("Verify prerequisites", "Confirm internet access, time sync and MFA."),
            ("Review client status", "Capture client version and connection log."),
        ],
        "latency": [
            ("Establish baseline", "Measure local gateway and remote target latency."),
            ("Trace path", "Locate the hop where delay or loss starts."),
        ],
    }
    steps = common + specialized.get(issue, [("Run baseline tests", "Test gateway, DNS and one external service.")])
    steps += [
        ("Document result", f"Record findings for the {environment} environment."),
        ("Escalate safely", "Attach evidence and avoid disruptive changes without approval."),
    ]
    return [{"step": str(index), "title": title, "details": details} for index, (title, details) in enumerate(steps, 1)]


def _parse_iso_datetime(value: str) -> datetime:
    if not value:
        raise ValueError("timestamp is required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
