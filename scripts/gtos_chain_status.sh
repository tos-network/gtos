#!/usr/bin/env bash
# gtos_chain_status.sh — authoritative operator status for a GTOS cluster.
set -euo pipefail

BASE_DIR="${BASE_DIR:-/data/gtos}"
NODE_URLS="${NODE_URLS:-http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549}"
RPC_URLS="${RPC_URLS:-http://127.0.0.1:8555}"
GUARD_DIR="${GUARD_DIR:-${BASE_DIR}/ops/validator_guard}"
INCIDENT_DIR="${INCIDENT_DIR:-${BASE_DIR}/ops/incidents}"
FORMAT="${FORMAT:-both}"
ALERT_LIMIT="${ALERT_LIMIT:-10}"

usage() {
	cat <<'USAGE'
Usage: scripts/gtos_chain_status.sh [options]

Render authoritative GTOS cluster status for operators.

Options:
  --base-dir <path>        cluster base directory (default: /data/gtos)
  --nodes <url,url,...>    validator HTTP RPC URLs
  --rpcs <url,url,...>     RPC/fullnode HTTP RPC URLs
  --guard-dir <path>       validator_guard journal directory
  --incident-dir <path>    incident outbox directory
  --format <json|md|both>  output format (default: both)
  --alert-limit <n>        number of recent alerts to include (default: 10)
  -h, --help               show help
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--base-dir) BASE_DIR="$2"; shift 2 ;;
	--nodes) NODE_URLS="$2"; shift 2 ;;
	--rpcs) RPC_URLS="$2"; shift 2 ;;
	--guard-dir) GUARD_DIR="$2"; shift 2 ;;
	--incident-dir) INCIDENT_DIR="$2"; shift 2 ;;
	--format) FORMAT="$2"; shift 2 ;;
	--alert-limit) ALERT_LIMIT="$2"; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

case "${FORMAT}" in
json|md|both) ;;
*) echo "unsupported format: ${FORMAT}" >&2; exit 1 ;;
esac

python3 - <<'PY' "${BASE_DIR}" "${NODE_URLS}" "${RPC_URLS}" "${GUARD_DIR}" "${INCIDENT_DIR}" "${FORMAT}" "${ALERT_LIMIT}"
import collections
import datetime as dt
import json
import pathlib
import sys
import urllib.request

base_dir = pathlib.Path(sys.argv[1])
node_urls = [u for u in sys.argv[2].split(",") if u]
rpc_urls = [u for u in sys.argv[3].split(",") if u]
guard_dir = pathlib.Path(sys.argv[4])
incident_dir = pathlib.Path(sys.argv[5])
fmt = sys.argv[6]
alert_limit = int(sys.argv[7])

def rpc(url, method, params):
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        body = json.loads(r.read())
    if "error" in body:
        raise RuntimeError(body["error"])
    return body["result"]

def dec(value):
    if value is None:
        return 0
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    return int(value)

def load_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None

def tail_jsonl(path, limit):
    if not path.exists():
        return []
    items = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items[-limit:]

def collect_node(url, role, idx):
    item = {
        "role": role,
        "index": idx,
        "url": url,
        "healthy": False,
    }
    try:
        block = rpc(url, "tos_getBlockByNumber", ["latest", False])
        peers = dec(rpc(url, "net_peerCount", []))
        item["healthy"] = True
        item["head"] = dec(block["number"])
        item["hash"] = block["hash"]
        item["miner"] = block["miner"]
        item["peers"] = peers
    except Exception as exc:
        item["error"] = str(exc)
    return item

report = {
    "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
    "baseDir": str(base_dir),
    "validators": [collect_node(url, "validator", i + 1) for i, url in enumerate(node_urls)],
    "rpcs": [collect_node(url, "rpc", i + 1) for i, url in enumerate(rpc_urls)],
    "maintenance": [],
    "guardState": load_json(guard_dir / "state.json"),
    "recentAlerts": tail_jsonl(guard_dir / "alerts.jsonl", alert_limit),
    "incidents": [],
}

for idx in range(1, len(node_urls) + 1):
    row = {"node": idx}
    path = base_dir / "ops" / "maintenance" / f"node{idx}.env"
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            row[k] = v
        if "UPDATED_AT" in row:
            row["ageSec"] = int(dt.datetime.now(dt.timezone.utc).timestamp()) - int(row["UPDATED_AT"])
    report["maintenance"].append(row)

if incident_dir.exists():
    for item in sorted(incident_dir.glob("*.json")):
        body = load_json(item)
        if body is not None:
            body["_file"] = item.name
            report["incidents"].append(body)

healthy_heads = [item["head"] for item in report["validators"] if item.get("healthy")]
report["summary"] = {
    "validatorHealthy": sum(1 for item in report["validators"] if item.get("healthy")),
    "rpcHealthy": sum(1 for item in report["rpcs"] if item.get("healthy")),
    "headMin": min(healthy_heads) if healthy_heads else None,
    "headMax": max(healthy_heads) if healthy_heads else None,
    "headSpread": (max(healthy_heads) - min(healthy_heads)) if healthy_heads else None,
    "recentAlertCount": len(report["recentAlerts"]),
    "incidentCount": len(report["incidents"]),
}
if report["guardState"] and isinstance(report["guardState"], dict):
    analysis = report["guardState"].get("analysis") or {}
    report["summary"]["finalized"] = analysis.get("finalized")
    report["summary"]["finalityLag"] = analysis.get("finalityLag")
    report["summary"]["turnLength"] = analysis.get("turnLength")
    report["summary"]["groupsObserved"] = analysis.get("groupsObserved")

if fmt in ("json", "both"):
    print(json.dumps(report, indent=2, sort_keys=True))
if fmt in ("md", "both"):
    lines = [
        "# GTOS Chain Status",
        "",
        f'- Generated: `{report["generatedAt"]}`',
        f'- Validator healthy: `{report["summary"]["validatorHealthy"]}/{len(report["validators"])}`',
        f'- RPC healthy: `{report["summary"]["rpcHealthy"]}/{len(report["rpcs"])}`',
        f'- Head spread: `{report["summary"]["headSpread"]}`',
        f'- Recent alerts: `{report["summary"]["recentAlertCount"]}`',
        f'- Incidents: `{report["summary"]["incidentCount"]}`',
    ]
    if report["summary"].get("finalityLag") is not None:
        lines.append(f'- Finality lag: `{report["summary"]["finalityLag"]}`')
    if report["summary"].get("turnLength") is not None:
        lines.append(f'- TurnLength: `{report["summary"]["turnLength"]}`')
    lines.extend(["", "## Validators", ""])
    for item in report["validators"]:
        lines.append(f'- node{item["index"]}: healthy `{item.get("healthy")}`, head `{item.get("head")}`, peers `{item.get("peers")}`, miner `{item.get("miner")}`')
    lines.extend(["", "## RPC", ""])
    for item in report["rpcs"]:
        lines.append(f'- rpc{item["index"]}: healthy `{item.get("healthy")}`, head `{item.get("head")}`, peers `{item.get("peers")}`')
    lines.extend(["", "## Maintenance", ""])
    for item in report["maintenance"]:
        lines.append(f'- node{item["node"]}: state `{item.get("STATE","unknown")}`, ageSec `{item.get("ageSec","-")}`, tx `{item.get("TX_HASH","")}`')
    lines.extend(["", "## Recent Alerts", ""])
    if report["recentAlerts"]:
        for item in report["recentAlerts"]:
            lines.append(f'- `{item.get("level","")}/{item.get("kind","")}` {item.get("message","")}')
    else:
        lines.append("- none")
    print("")
    print("\n".join(lines))
PY
