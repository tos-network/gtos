#!/usr/bin/env bash
# validator_guard_report.sh — summarize validator_guard journals into periodic reports.
set -euo pipefail

JOURNAL_DIR="${JOURNAL_DIR:-/data/gtos/ops/validator_guard}"
REPORT_DIR="${REPORT_DIR:-/data/gtos/ops/validator_guard/reports}"
INCIDENT_DIR="${INCIDENT_DIR:-/data/gtos/ops/incidents}"
BASE_DIR="${BASE_DIR:-/data/gtos}"
LOOKBACK_HOURS="${LOOKBACK_HOURS:-24}"
REPORT_FORMAT="${REPORT_FORMAT:-both}"

usage() {
	cat <<'USAGE'
Usage: scripts/validator_guard_report.sh [options]

Generate a periodic validator operations report from validator_guard journals.

Options:
  --journal-dir <path>     directory containing events.jsonl / alerts.jsonl
  --report-dir <path>      destination directory for rendered reports
  --incident-dir <path>    incident outbox directory
  --base-dir <path>        cluster base dir for maintenance state files
  --lookback-hours <n>     summarize the last N hours (default: 24)
  --format <json|md|both>  output format (default: both)
  -h, --help               show help
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--journal-dir) JOURNAL_DIR="$2"; shift 2 ;;
	--report-dir) REPORT_DIR="$2"; shift 2 ;;
	--incident-dir) INCIDENT_DIR="$2"; shift 2 ;;
	--base-dir) BASE_DIR="$2"; shift 2 ;;
	--lookback-hours) LOOKBACK_HOURS="$2"; shift 2 ;;
	--format) REPORT_FORMAT="$2"; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

case "${REPORT_FORMAT}" in
json|md|both) ;;
*) echo "unsupported report format: ${REPORT_FORMAT}" >&2; exit 1 ;;
esac

mkdir -p "${REPORT_DIR}"

python3 - <<'PY' "${JOURNAL_DIR}" "${REPORT_DIR}" "${INCIDENT_DIR}" "${BASE_DIR}" "${LOOKBACK_HOURS}" "${REPORT_FORMAT}"
import collections
import datetime as dt
import json
import pathlib
import statistics
import sys

journal_dir = pathlib.Path(sys.argv[1])
report_dir = pathlib.Path(sys.argv[2])
incident_dir = pathlib.Path(sys.argv[3])
base_dir = pathlib.Path(sys.argv[4])
lookback_hours = int(sys.argv[5])
report_format = sys.argv[6]
now = int(dt.datetime.now(dt.timezone.utc).timestamp())
since = now - lookback_hours * 3600


def load_jsonl(path: pathlib.Path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


events = [e for e in load_jsonl(journal_dir / 'events.jsonl') if int(e.get('ts', 0)) >= since]
alerts = [a for a in load_jsonl(journal_dir / 'alerts.jsonl') if int(a.get('ts', 0)) >= since]
incidents = []
if incident_dir.exists():
    for item in incident_dir.glob("*.json"):
        try:
            body = json.loads(item.read_text())
        except json.JSONDecodeError:
            continue
        if int(body.get("ts", 0)) >= since:
            incidents.append(body)
state = None
state_path = journal_dir / 'state.json'
if state_path.exists():
    try:
        state = json.loads(state_path.read_text())
    except json.JSONDecodeError:
        state = None

peers_by_node = collections.defaultdict(list)
heights_by_node = collections.defaultdict(list)
lag_samples = []
groups_observed = []
out_of_turn_samples = []
turn_length = None
turn_group_duration_ms = None
for event in events:
    for rec in event.get('latest', []):
        node = rec.get('node')
        if node is None:
            continue
        if 'peers' in rec:
            peers_by_node[int(node)].append(int(rec['peers']))
        if 'height' in rec:
            heights_by_node[int(node)].append(int(rec['height']))
    analysis = event.get('analysis') or {}
    if 'finalityLag' in analysis:
        lag_samples.append(int(analysis['finalityLag']))
    if 'groupsObserved' in analysis:
        groups_observed.append(int(analysis['groupsObserved']))
    if 'outOfTurnBlocks' in analysis:
        out_of_turn_samples.append(int(analysis['outOfTurnBlocks']))
    if turn_length is None and 'turnLength' in analysis:
        turn_length = int(analysis['turnLength'])
    if turn_group_duration_ms is None and 'turnGroupDurationMs' in analysis:
        turn_group_duration_ms = int(analysis['turnGroupDurationMs'])

alert_counts = collections.Counter((a.get('level', 'UNKNOWN'), a.get('kind', 'unknown')) for a in alerts)
incident_counts = collections.Counter((a.get('severity', 'unknown'), a.get('kind', 'unknown')) for a in incidents)
maintenance_files = []
maint_dir = base_dir / "ops" / "maintenance"
if maint_dir.exists():
    for item in sorted(maint_dir.glob("node*.env")):
        row = {"node": item.stem.replace("node", "")}
        for line in item.read_text().splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            row[k] = v
        maintenance_files.append(row)
report = {
    'generatedAt': now,
    'generatedAtRFC3339': dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat(),
    'lookbackHours': lookback_hours,
    'journalDir': str(journal_dir),
    'events': len(events),
    'alerts': len(alerts),
    'incidents': len(incidents),
    'turnLength': turn_length,
    'turnGroupDurationMs': turn_group_duration_ms,
    'groupsObservedMax': max(groups_observed) if groups_observed else 0,
    'outOfTurnBlocksMax': max(out_of_turn_samples) if out_of_turn_samples else 0,
    'finalityLag': {
        'latest': (((state or {}).get('analysis') or {}).get('finalityLag')),
        'max': max(lag_samples) if lag_samples else None,
        'avg': round(statistics.mean(lag_samples), 2) if lag_samples else None,
    },
    'perNode': {},
    'alertBreakdown': [
        {'level': level, 'kind': kind, 'count': count}
        for (level, kind), count in sorted(alert_counts.items())
    ],
    'incidentBreakdown': [
        {'severity': level, 'kind': kind, 'count': count}
        for (level, kind), count in sorted(incident_counts.items())
    ],
    'maintenanceFiles': maintenance_files,
    'latestState': state,
}
for node in sorted(set(peers_by_node) | set(heights_by_node)):
    peer_samples = peers_by_node[node]
    height_samples = heights_by_node[node]
    report['perNode'][str(node)] = {
        'peerMin': min(peer_samples) if peer_samples else None,
        'peerMax': max(peer_samples) if peer_samples else None,
        'peerAvg': round(statistics.mean(peer_samples), 2) if peer_samples else None,
        'headMin': min(height_samples) if height_samples else None,
        'headMax': max(height_samples) if height_samples else None,
        'headDelta': (max(height_samples) - min(height_samples)) if len(height_samples) >= 2 else 0,
    }

stamp = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime('%Y-%m-%d')
json_path = report_dir / f'validator-guard-{stamp}.json'
md_path = report_dir / f'validator-guard-{stamp}.md'
if report_format in ('json', 'both'):
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
if report_format in ('md', 'both'):
    lines = [
        '# GTOS Validator Guard Daily Report',
        '',
        f'- Generated: `{report["generatedAtRFC3339"]}`',
        f'- Lookback: `{lookback_hours}h`',
        f'- Events: `{report["events"]}`',
        f'- Alerts: `{report["alerts"]}`',
    ]
    if turn_length is not None:
        lines.append(f'- TurnLength: `{turn_length}`')
    if turn_group_duration_ms is not None:
        lines.append(f'- TurnGroupDurationMs: `{turn_group_duration_ms}`')
    if report['finalityLag']['latest'] is not None:
        lines.append(f'- Latest finality lag: `{report["finalityLag"]["latest"]}`')
    lines.extend(['', '## Per-node Summary', ''])
    if report['perNode']:
        for node, data in sorted(report['perNode'].items(), key=lambda kv: int(kv[0])):
            lines.append(f'- node{node}: peer avg `{data["peerAvg"]}`, peer min `{data["peerMin"]}`, head delta `{data["headDelta"]}`')
    else:
        lines.append('- No per-node samples in the lookback window.')
    lines.extend(['', '## Alert Breakdown', ''])
    if report['alertBreakdown']:
        for item in report['alertBreakdown']:
            lines.append(f'- `{item["level"]}/{item["kind"]}`: `{item["count"]}`')
    else:
        lines.append('- No alerts in the lookback window.')
    lines.extend(['', '## Incident Breakdown', ''])
    if report['incidentBreakdown']:
        for item in report['incidentBreakdown']:
            lines.append(f'- `{item["severity"]}/{item["kind"]}`: `{item["count"]}`')
    else:
        lines.append('- No incidents in the lookback window.')
    lines.extend(['', '## Maintenance Files', ''])
    if report['maintenanceFiles']:
        for item in report['maintenanceFiles']:
            lines.append(f'- node{item.get("node")}: state `{item.get("STATE","")}`, updated `{item.get("UPDATED_AT","")}`, tx `{item.get("TX_HASH","")}`')
    else:
        lines.append('- No maintenance state files found.')
    md_path.write_text('\n'.join(lines) + '\n')

print(json.dumps({
    'json': str(json_path) if report_format in ('json', 'both') else None,
    'md': str(md_path) if report_format in ('md', 'both') else None,
}, sort_keys=True))
PY
