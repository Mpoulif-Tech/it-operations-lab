"""Pure audit functions: no network access or infrastructure changes."""
from datetime import datetime, timezone
import ipaddress
import math


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def inventory_diff(before, after):
    """Compare two asset snapshots by unique asset_id."""
    def index(rows):
        result = {}
        for row in rows:
            key = row.get("asset_id")
            if not isinstance(key, str) or not key.strip() or key in result:
                raise ValueError("asset_id must be a unique nonempty string")
            result[key] = row
        return result
    old, new = index(before), index(after)
    changed = []
    for key in sorted(old.keys() & new.keys()):
        fields = {}
        for field in sorted(old[key].keys() | new[key].keys()):
            if (field in old[key]) != (field in new[key]) or old[key].get(field) != new[key].get(field):
                fields[field] = {"before": old[key].get(field), "after": new[key].get(field)}
        if fields:
            changed.append({"asset_id": key, "fields": fields})
    return {"added": sorted(new.keys() - old.keys()),
            "removed": sorted(old.keys() - new.keys()), "changed": changed}


def disk_capacity(records, warning=80, critical=95):
    """Classify utilization; reject malformed or impossible measurements."""
    if not 0 <= warning < critical <= 100:
        raise ValueError("Require 0 <= warning < critical <= 100")
    result = []
    for record in records:
        total, used = record["total_bytes"], record["used_bytes"]
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
               for v in (total, used)):
            raise ValueError("Capacity values must be finite numbers")
        if total <= 0 or not 0 <= used <= total:
            raise ValueError("Require total > 0 and 0 <= used <= total")
        percent = 100 * used / total
        result.append({"volume": record["volume"], "used_percent": round(percent, 2),
                       "free_bytes": total - used,
                       "status": "critical" if percent >= critical else "warning" if percent >= warning else "ok"})
    return result


def subnet_plan(cidr):
    """Describe an IPv4/IPv6 subnet without enumerating its addresses."""
    network = ipaddress.ip_network(cidr, strict=True)
    if network.version == 4 and network.prefixlen < 31:
        first, last, usable = network.network_address + 1, network.broadcast_address - 1, network.num_addresses - 2
    elif network.version == 6 and network.prefixlen < 127:
        first, last, usable = network.network_address + 1, network.broadcast_address, network.num_addresses - 1
    else:
        first, last, usable = network.network_address, network.broadcast_address, network.num_addresses
    return {"network": str(network), "version": network.version,
            "total_addresses": network.num_addresses, "usable_addresses": usable,
            "first_host": str(first), "last_host": str(last)}


def sla_audit(tickets, now):
    """Evaluate elapsed-time resolution targets, in continuous hours."""
    now = timestamp(now)
    result = []
    seen = set()
    for ticket in tickets:
        key = ticket["id"]
        if not isinstance(key, str) or not key.strip() or key in seen:
            raise ValueError("Ticket IDs must be unique nonempty strings")
        seen.add(key)
        opened = timestamp(ticket["opened_at"])
        closed = timestamp(ticket["closed_at"]) if ticket.get("closed_at") else None
        target = ticket["target_hours"]
        if isinstance(target, bool) or not isinstance(target, (int, float)) or not math.isfinite(target) or target <= 0:
            raise ValueError("target_hours must be a positive finite number")
        if opened > now or (closed and (closed < opened or closed > now)):
            raise ValueError("Invalid ticket chronology")
        elapsed = ((closed or now) - opened).total_seconds() / 3600
        result.append({"id": key, "elapsed_hours": round(elapsed, 2),
                       "target_hours": target, "breached": elapsed > target,
                       "state": "closed" if closed else "open"})
    return result
