"""JSON input/output CLI. Exit 2 means invalid input, not an audit finding."""
import argparse
import json
import sys
from pathlib import Path
from .audits import inventory_diff, disk_capacity, subnet_plan, sla_audit


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", choices=["inventory", "capacity", "subnet", "sla"])
    parser.add_argument("input", type=Path, help="UTF-8 JSON input file")
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        if args.audit == "inventory":
            result = inventory_diff(data["before"], data["after"])
        elif args.audit == "capacity":
            result = disk_capacity(data["volumes"])
        elif args.audit == "subnet":
            result = subnet_plan(data["cidr"])
        else:
            result = sla_audit(data["tickets"], data["now"])
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
