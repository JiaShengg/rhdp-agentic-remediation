#!/usr/bin/env python3
"""Offline score: agent decisions vs OWASP Benchmark expectedresults-1.2.csv.

The agent must never see the CSV. Run this on a laptop after the demo:

  python3 scripts/score.py \\
    --decisions decisions.jsonl \\
    --expected ~/BenchmarkJava/expectedresults-1.2.csv
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_expected(path: Path) -> dict[str, bool]:
    """test_case -> real_vulnerability"""
    out: dict[str, bool] = {}
    with path.open() as fh:
        next(fh)  # header
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            name, _cat, real = parts[0], parts[1], parts[2].lower() == "true"
            out[name] = real
    return out


def finding_to_test_case(finding_id: str, catalog: dict | None) -> str | None:
    if catalog:
        for raw in catalog.get("demo_cases", []):
            if raw["id"] == finding_id:
                return raw.get("test_case")
    # F-00024 / F-00052 -> BenchmarkTest00024
    parts = finding_id.split("-")
    if len(parts) >= 3 and parts[-1].isdigit():
        return f"BenchmarkTest{parts[-1]}"
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--decisions", required=True, type=Path)
    ap.add_argument("--expected", required=True, type=Path)
    ap.add_argument(
        "--catalog",
        type=Path,
        default=Path("lab/phase3-golden-findings.json"),
        help="optional id→test_case map",
    )
    args = ap.parse_args()

    expected = load_expected(args.expected)
    catalog = json.loads(args.catalog.read_text()) if args.catalog.exists() else None

    rows = []
    for line in args.decisions.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))

    print(f"{'finding':<14} {'decision':<16} {'truth':<8} {'result':<8} build")
    print("-" * 64)
    correct = wrong = abstained = needs = 0
    build_pass = build_total = 0
    for r in rows:
        fid = r["finding_id"]
        decision = str(r["decision"]).upper()
        tc = finding_to_test_case(fid, catalog)
        if tc is None or tc not in expected:
            print(f"{fid:<14} {decision:<16} {'?':<8} {'skip':<8}")
            abstained += 1
            continue
        real = expected[tc]
        truth = "TP" if real else "FP"
        build = "Y" if r.get("build_ok") else ("N" if "build_ok" in r else "-")
        if decision == "NEEDS_DEVELOPER":
            needs += 1
            print(f"{fid:<14} {decision:<16} {truth:<8} {'held':<8} {build}")
            continue
        # TP means the agent says the vulnerability is real. FP means it is not.
        agent_says_real = decision == "TP"
        ok = agent_says_real == real
        if ok:
            correct += 1
            label = "ok"
        else:
            wrong += 1
            label = "WRONG"
        if "build_ok" in r:
            build_total += 1
            if r["build_ok"]:
                build_pass += 1
        print(f"{fid:<14} {decision:<16} {truth:<8} {label:<8} {build}")

    decided = correct + wrong
    print("-" * 64)
    print(
        f"correct={correct} wrong={wrong} needs_developer={needs} "
        f"unresolved={abstained} decided={decided}"
    )
    if decided:
        print(f"accuracy_on_decided={correct}/{decided} ({correct / decided:.3f})")
    if build_total:
        print(f"build_pass_rate={build_pass}/{build_total}")


if __name__ == "__main__":
    main()
