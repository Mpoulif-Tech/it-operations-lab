import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from ops_toolkit.audits import inventory_diff, disk_capacity, subnet_plan, sla_audit
from ops_toolkit.__main__ import main


class AuditTests(unittest.TestCase):
    def test_inventory_add_remove_change(self):
        result = inventory_diff([{"asset_id": "A", "os": "old"}, {"asset_id": "B"}],
                                [{"asset_id": "A", "os": "new"}, {"asset_id": "C"}])
        self.assertEqual(result["added"], ["C"])
        self.assertEqual(result["removed"], ["B"])
        self.assertEqual(result["changed"][0]["fields"]["os"], {"before": "old", "after": "new"})

    def test_duplicate_asset_rejected(self):
        with self.assertRaises(ValueError):
            inventory_diff([], [{"asset_id": "A"}, {"asset_id": "A"}])

    def test_null_and_absent_are_different(self):
        self.assertEqual(len(inventory_diff([{"asset_id": "A"}], [{"asset_id": "A", "os": None}])["changed"]), 1)

    def test_capacity_thresholds(self):
        rows = [{"volume": str(n), "total_bytes": 100, "used_bytes": n} for n in [79, 80, 95]]
        self.assertEqual([x["status"] for x in disk_capacity(rows)], ["ok", "warning", "critical"])

    def test_invalid_capacities(self):
        for total, used in [(0, 0), (10, 11), (10, -1), (10, float("nan")), (True, 0)]:
            with self.subTest(total=total, used=used), self.assertRaises(ValueError):
                disk_capacity([{"volume": "/", "total_bytes": total, "used_bytes": used}])

    def test_invalid_thresholds(self):
        with self.assertRaises(ValueError):
            disk_capacity([], 95, 80)

    def test_ipv4(self):
        result = subnet_plan("192.0.2.0/24")
        self.assertEqual(result["usable_addresses"], 254)
        self.assertEqual(result["last_host"], "192.0.2.254")

    def test_small_subnets(self):
        self.assertEqual(subnet_plan("192.0.2.0/31")["usable_addresses"], 2)
        self.assertEqual(subnet_plan("192.0.2.1/32")["usable_addresses"], 1)
        self.assertEqual(subnet_plan("2001:db8::/127")["usable_addresses"], 2)

    def test_large_ipv6(self):
        self.assertEqual(subnet_plan("2001:db8::/32")["total_addresses"], 2 ** 96)

    def test_host_bits_rejected(self):
        with self.assertRaises(ValueError):
            subnet_plan("192.0.2.1/24")

    def ticket(self, **changes):
        return dict({"id": "T1", "opened_at": "2026-01-01T00:00:00Z", "target_hours": 4}, **changes)

    def test_sla_boundary(self):
        self.assertFalse(sla_audit([self.ticket()], "2026-01-01T04:00:00Z")[0]["breached"])
        self.assertTrue(sla_audit([self.ticket()], "2026-01-01T04:00:01Z")[0]["breached"])

    def test_closed_ticket_stops_clock(self):
        row = self.ticket(closed_at="2026-01-01T03:00:00Z")
        self.assertEqual(sla_audit([row], "2026-01-02T00:00:00Z")[0]["elapsed_hours"], 3)

    def test_timezone_equivalence(self):
        self.assertEqual(sla_audit([self.ticket()], "2025-12-31T23:00:00-05:00")[0]["elapsed_hours"], 4)

    def test_invalid_dates(self):
        for now in ["2026-01-01T04:00:00", "2025-01-01T00:00:00Z"]:
            with self.assertRaises(ValueError):
                sla_audit([self.ticket()], now)

    def test_cli_success_and_bad_json(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            path.write_text('{"cidr":"192.0.2.0/24"}')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["subnet", str(path)]), 0)
            self.assertEqual(json.loads(output.getvalue())["usable_addresses"], 254)
            path.write_text("{")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["subnet", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
