# IT Operations Lab

Five tested Python tools that model common junior IT support workflows. Every result is deterministic and explainable; the tools analyze supplied data but never modify infrastructure.

## Projects

| # | Project | Practical outcome |
|---|---|---|
| 04 | **Ticket Triage** | Categorizes tickets and assigns an explainable SLA priority. |
| 05 | **Asset Inventory Audit** | Finds duplicate IDs, missing serials and overdue checks. |
| 06 | **Log Anomaly Scanner** | Groups errors, authentication failures, timeouts and resource pressure. |
| 07 | **Backup Verifier** | Validates status, recency, size and checksum presence. |
| 08 | **Network Checklist Generator** | Builds safe, repeatable diagnostics for Wi-Fi, DNS, VPN and latency incidents. |

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
python -m it_operations_lab
```

## Engineering choices

- Python 3.11+ and standard-library business logic
- Type hints, validation and structured dictionary outputs
- Pytest coverage for normal paths and invalid inputs
- GitHub Actions CI with read-only repository permissions
- Privacy-first examples with no real user or infrastructure data

These are personal portfolio projects built to demonstrate support thinking, data quality and automation skills. They are not representations of client work or production deployments.

## License

MIT © Henri Mpouli
