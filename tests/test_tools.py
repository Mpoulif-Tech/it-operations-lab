from datetime import datetime, timedelta, timezone

import pytest

from it_operations_lab import (
    audit_asset_inventory,
    generate_network_checklist,
    scan_log_anomalies,
    triage_ticket,
    verify_backup_manifest,
)


def test_ticket_triage_explains_priority():
    result = triage_ticket("Possible phishing", "Compromised account", impact=3, urgency=2)
    assert result["category"] == "security"
    assert result["priority"] == "P1"
    assert result["sla_hours"] == 1


def test_ticket_triage_validates_inputs():
    with pytest.raises(ValueError):
        triage_ticket("Printer", "Offline", impact=4)


def test_asset_inventory_flags_data_quality_issues():
    now = datetime.now(timezone.utc)
    result = audit_asset_inventory(
        [
            {"asset_id": "LT-001", "serial": "ABC", "checked_at": now.isoformat()},
            {"asset_id": "LT-001", "serial": "", "checked_at": (now - timedelta(days=120)).isoformat()},
        ]
    )
    assert result["duplicate_ids"] == ["LT-001"]
    assert result["missing_serial"] == ["LT-001"]
    assert result["stale_assets"] == ["LT-001"]


def test_log_scanner_groups_anomalies():
    result = scan_log_anomalies(["INFO started", "ERROR timeout contacting DNS", "403 unauthorized"])
    assert result["risk"] == "medium"
    assert result["counts"] == {"error": 1, "timeout": 1, "auth_failure": 1}
    assert [item["line"] for item in result["findings"]] == [2, 3]


def test_backup_verifier_requires_fresh_complete_artifacts():
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = verify_backup_manifest(
        [
            {
                "name": "database",
                "status": "completed",
                "size_bytes": 1024,
                "sha256": "abc123",
                "created_at": (now - timedelta(hours=2)).isoformat(),
            },
            {
                "name": "files",
                "status": "failed",
                "size_bytes": 0,
                "sha256": "",
                "created_at": (now - timedelta(hours=40)).isoformat(),
            },
        ],
        now=now,
    )
    assert result["healthy"] is False
    assert result["failures"][0]["name"] == "files"
    assert set(result["failures"][0]["reasons"].split(",")) == {
        "status_not_completed",
        "empty_backup",
        "missing_checksum",
        "backup_too_old",
    }


def test_network_checklist_is_repeatable_and_safe():
    checklist = generate_network_checklist("vpn", "hybrid office")
    assert checklist[0]["title"] == "Confirm scope"
    assert checklist[-1]["title"] == "Escalate safely"
    assert any(item["title"] == "Verify prerequisites" for item in checklist)
