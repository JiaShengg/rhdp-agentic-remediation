#!/usr/bin/env python3
"""Run triage twice per finding and keep a decision only when both agree.

Two Hermes sessions are independent: the workspace is reset and each session
gets its own id in the audit log. A disagreement is recorded as
NEEDS_DEVELOPER with both reasons. The answer key is not read here.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "lab/stub-findings-mcp/findings.public.json"
NS = os.environ.get("NS", "remediation-lab")
SEED = "7d94047"
MAX_TURNS = os.environ.get("MAX_TURNS", "12")


def oc(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["oc", *args],
        input=input_text,
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        err = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-800:]
        raise SystemExit(err or "oc failed")
    return proc


def pod(label: str) -> str:
    name = oc(
        "get", "pods", "-n", NS, "-l", label,
        "--field-selector=status.phase=Running",
        "-o", "jsonpath={.items[0].metadata.name}",
    ).stdout.strip()
    if not name:
        raise SystemExit(f"no running pod for {label}")
    return name


def finding_ids(only: list[str]) -> list[str]:
    data = json.loads(CATALOG.read_text())
    ids = [
        c["id"]
        for c in data["demo_cases"]
        if c.get("category") != "library" and c.get("tool") != "stub-sonatype"
    ]
    if only:
        missing = [item for item in only if item not in ids]
        if missing:
            raise SystemExit(f"unknown finding ids: {missing}")
        return only
    return ids


def reset_workspace(hermes: str) -> None:
    script = f"""
set -euo pipefail
cd /opt/data/workspace/BenchmarkJava
git checkout -B main {SEED}
git reset --hard
git clean -fdx
git for-each-ref --format='%(refname:short)' 'refs/heads/fix/*' | xargs -r git branch -D
"""
    oc("exec", "-n", NS, hermes, "-c", "hermes", "--", "bash", "-lc", script)


def run_session(hermes: str, finding_id: str, session_id: str, out_path: Path) -> None:
    prompt = (
        f"Triage finding {finding_id}. Read the code and decide whether it is a "
        "true positive or a false positive. Cite the file and line numbers that "
        "support the decision. State where the input comes from and whether it "
        "reaches the sink unchanged. Do not change any code. Call record_decision "
        "with TP, FP, or NEEDS_DEVELOPER and the reason.\n"
    )
    oc(
        "exec", "-i", "-n", NS, hermes, "-c", "hermes", "--",
        "bash", "-lc", "cat > /tmp/rhdp-session-id",
        input_text=session_id + "\n",
    )
    oc(
        "exec", "-i", "-n", NS, hermes, "-c", "hermes", "--",
        "bash", "-lc", "cat > /tmp/triage-prompt.txt",
        input_text=prompt,
    )
    proc = oc(
        "exec", "-n", NS, hermes, "-c", "hermes", "--",
        "bash", "-lc",
        "export HERMES_HOME=/opt/data HOME=/opt/data; "
        f"hermes chat --oneshot --max-turns {MAX_TURNS} "
        "--in /opt/data/workspace/BenchmarkJava --query-file /tmp/triage-prompt.txt",
        check=False,
    )
    text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    out_path.write_text(text + f"\nexit={proc.returncode}\n")


def decision_for_session(session_id: str) -> dict | None:
    raw = oc(
        "exec", "-n", NS, "deploy/stub-findings-mcp", "--",
        "sh", "-c", "cat /audit/audit.jsonl 2>/dev/null || true",
    ).stdout
    chosen = None
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("session_id") != session_id or row.get("tool") != "record_decision":
            continue
        record = (row.get("result") or {}).get("record") or {}
        if record.get("decision"):
            chosen = record
    return chosen


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ids", nargs="*", default=[])
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    ids = finding_ids(args.ids)
    consolidated = args.out / "decisions.jsonl"
    consolidated.write_text("")
    for finding_id in ids:
        for repeat in range(1, args.repeats + 1):
            pair = []
            for side in ("a", "b"):
                hermes = pod("app=hermes-agent")
                reset_workspace(hermes)
                session_id = str(uuid.uuid4())
                started = time.time()
                transcript = args.out / f"{finding_id}-r{repeat}-{side}.txt"
                print(f"==== {finding_id} repeat {repeat} {side} {session_id} ====", flush=True)
                run_session(hermes, finding_id, session_id, transcript)
                elapsed = round(time.time() - started)
                record = decision_for_session(session_id) or {
                    "finding_id": finding_id,
                    "decision": "",
                    "reason": "no decision recorded",
                }
                record = dict(record)
                record["session_id"] = session_id
                record["seconds"] = elapsed
                pair.append(record)
                (args.out / f"{finding_id}-r{repeat}-{side}.json").write_text(
                    json.dumps(record) + "\n"
                )
            left, right = pair
            same = bool(left.get("decision")) and left.get("decision") == right.get("decision")
            if same:
                merged = {
                    "finding_id": finding_id,
                    "decision": left["decision"],
                    "reason": left.get("reason", ""),
                    "repeat": repeat,
                    "sessions": [left.get("session_id"), right.get("session_id")],
                }
            else:
                merged = {
                    "finding_id": finding_id,
                    "decision": "NEEDS_DEVELOPER",
                    "reason": (
                        f"run A: {left.get('decision') or 'none'}: {left.get('reason', '')} "
                        f"run B: {right.get('decision') or 'none'}: {right.get('reason', '')}"
                    ),
                    "repeat": repeat,
                    "sessions": [left.get("session_id"), right.get("session_id")],
                }
            with consolidated.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(merged) + "\n")
            print(
                json.dumps(
                    {"finding_id": finding_id, "repeat": repeat, "decision": merged["decision"]}
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
