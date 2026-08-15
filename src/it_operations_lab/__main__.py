"""Run a small demonstration with ``python -m it_operations_lab``."""

from __future__ import annotations

import json

from .tools import generate_network_checklist, triage_ticket


def main() -> None:
    demo = {
        "ticket": triage_ticket("VPN access", "User cannot login to the VPN", impact=2, urgency=2),
        "checklist": generate_network_checklist("vpn"),
    }
    print(json.dumps(demo, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
