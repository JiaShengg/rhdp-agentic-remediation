#!/usr/bin/env bash
# Run Hermes oneshot triage for every finding in findings.public.json.
# Usage:
#   NS=remediation-pov OUT=/tmp/triage-run ./scripts/run_triage_batch.sh
#
# Writes:
#   $OUT/decisions.jsonl   stub decisions collected after the batch
#   $OUT/oneshot/<id>.txt  per-finding transcript tails
#   $OUT/summary.txt       ids with and without decisions
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NS="${NS:-remediation-pov}"
OUT="${OUT:-/tmp/triage-run}"
CATALOG="${CATALOG:-$ROOT/lab/stub-findings-mcp/findings.public.json}"
MAX_TURNS="${MAX_TURNS:-12}"

mkdir -p "$OUT/oneshot"

HERMES=$(oc get pods -n "$NS" -l app=hermes-agent --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')
test -n "$HERMES"

IDS_FILE=$(mktemp)
python3 - <<PY
import json
from pathlib import Path
data = json.loads(Path(r"""$CATALOG""").read_text())
# Triage scores against Benchmark expectedresults. Skip library and Sonatype cases.
cases = [
    c for c in data["demo_cases"]
    if c.get("category") != "library" and c.get("tool") != "stub-sonatype"
]
Path(r"""$IDS_FILE""").write_text("\n".join(c["id"] for c in cases) + "\n")
print("findings", len(cases), "(excluded library)")
PY

echo "namespace=$NS hermes=$HERMES out=$OUT"

# Fresh decisions volume for this run
oc delete pod -n "$NS" -l app=stub-findings-mcp --force --grace-period=0
oc rollout status deploy/stub-findings-mcp -n "$NS" --timeout=180s

while IFS= read -r id; do
  [ -n "$id" ] || continue
  echo "==== triage $id ===="
  # Prompt file inside the Hermes pod (id expanded locally before oc exec).
  oc exec -n "$NS" "$HERMES" -c hermes -- bash -lc "cat > /tmp/triage-prompt.txt <<EOF
Triage finding ${id}. Read the code, decide true or false positive, and give your reason. Do not change any code. Call record_decision with your decision and reason.
EOF"
  set +e
  oc exec -n "$NS" "$HERMES" -c hermes -- bash -lc "
export HERMES_HOME=/opt/data HOME=/opt/data
hermes chat --oneshot -Q --max-turns ${MAX_TURNS} --in /opt/data/workspace/BenchmarkJava \
  --query-file /tmp/triage-prompt.txt
" >"$OUT/oneshot/${id}.txt" 2>&1
  rc=$?
  set -e
  echo "exit=$rc" | tee -a "$OUT/oneshot/${id}.txt"
  HERMES=$(oc get pods -n "$NS" -l app=hermes-agent --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}')
done <"$IDS_FILE"
rm -f "$IDS_FILE"

STUB=$(oc get pods -n "$NS" -l app=stub-findings-mcp -o jsonpath='{.items[0].metadata.name}')
oc exec -n "$NS" "$STUB" -- sh -c 'cat /decisions/decisions.jsonl 2>/dev/null || true' \
  >"$OUT/decisions.jsonl"

python3 - <<PY
import json
from pathlib import Path
catalog = json.loads(Path(r"""$CATALOG""").read_text())
ids = [c["id"] for c in catalog["demo_cases"]]
dec_path = Path(r"""$OUT/decisions.jsonl""")
recorded = {}
if dec_path.exists() and dec_path.read_text().strip():
    for line in dec_path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        recorded[row["finding_id"]] = row
missing = [i for i in ids if i not in recorded]
Path(r"""$OUT/summary.txt""").write_text(
    f"recorded={len(recorded)} missing={len(missing)}\n"
    f"missing_ids={missing}\n"
    f"recorded_ids={sorted(recorded)}\n"
)
print(Path(r"""$OUT/summary.txt""").read_text())
PY

echo "batch complete -> $OUT"
