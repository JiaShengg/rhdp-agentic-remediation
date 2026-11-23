#!/usr/bin/env python3
"""Print one audit-log trace in call order.

  python3 scripts/show_trace.py <session-or-finding-id>
  python3 scripts/show_trace.py <id> --file /path/to/audit.jsonl

The log lives on the stub PVC. It is not mounted in the agent pod.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_REDACT = tuple(
    re.compile(part, re.I if part.startswith("opentlc") or part.startswith("password") else 0)
    for part in (
        r"opentlc\.com",
        "sandbox" + "[0-9]",
        "/Use" + "rs/",
        r"https://\S+",
        r"[\w.-]+\.compute\.internal",
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        r"password\s*[:=]\s*\S+",
        "".join(["BEGIN ", ".*", "PRIVATE", " KEY"]),
        "AKIA" + "[0-9A-Z]{16}",
        "hf_" + "[A-Za-z0-9]{20,}",
    )
)


def redact(value):
    if isinstance(value, str):
        for pattern in _REDACT:
            value = pattern.sub("[redacted]", value)
        return value
    if isinstance(value, dict):
        return {str(key): redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def load_remote(namespace: str) -> str:
    proc = subprocess.run(
        [
            "oc",
            "exec",
            "-n",
            namespace,
            "deploy/stub-findings-mcp",
            "--",
            "sh",
            "-c",
            "cat /audit/audit.jsonl 2>/dev/null || true",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(redact(proc.stderr or proc.stdout or "oc exec failed")[-400:] + "\n")
        raise SystemExit(proc.returncode)
    return proc.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("key", help="session id or finding id")
    parser.add_argument("--file", type=Path)
    parser.add_argument("--namespace", default=os.environ.get("NS", "remediation-lab"))
    args = parser.parse_args()
    text = args.file.read_text() if args.file else load_remote(args.namespace)
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        session = str(row.get("session_id") or "")
        finding = str(row.get("finding_id") or "")
        if args.key in (session, finding) or args.key in session:
            rows.append(row)
    for row in rows:
        print(json.dumps(redact(row), default=str))
    if not rows:
        print(f"no calls for {args.key}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
