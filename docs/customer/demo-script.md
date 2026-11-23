# Agentic remediation demo script

Customer-facing walkthrough (~15–18 min). Screenshots (if any) live under `docs/customer/screenshots/`.

**Rule:** false positive first, library upgrade second, code fix third. The optional hand-back scene comes after the code fix and can be skipped. Never reverse that order.

## Opening (30s)

> “This is policy-gated remediation on Red Hat OpenShift AI: scanner findings come in over MCP, the agent decides true versus false positive from the code, and only then patches real vulnerabilities - verified by build and a rescan.”

What is stubbed in this rehearsal vs the POV is listed in the repository README (“Lab vs POV”).

## Scene 1 - Platform shape (1 min)

Show the running model and the stub scanner health from the operator console. Say clearly:

- Lab model is Qwen3.6-27B FP8 on one L40S at 128K, the same model and context as the POV.
- Scanner today is a stub over OWASP BenchmarkJava; the POV uses Fortify and Sonatype through the scanner partner MCP servers.
- Nothing is merged. The agent stops at branch + diff.

## Scene 2 - False positive triage (3 min)

**New chat**, paste:

```text
Triage finding F-00063. Read the code, decide true or false positive, and give your reason. Only change code for a true positive. Call record_decision with your decision and reason.
```

Expect: agent reads the file, decides FP, records the decision, **no code change**.

**Honesty:** three self-checking runs agreed FP, both sessions each time, and the transcripts do not show a commit. An earlier single-session run was 2 of 3; the third called it a true positive and edited the file. Play a take that did not change code.

**Say:** the agent judges from the code. The Benchmark answer key is used only afterwards for scoring - never as an agent input.

## Scene 3 - Library upgrade via OpenRewrite (4 min)

**New chat**, paste:

```text
Remediate library finding F-L001.
Work on branch fix/F-L001. Call run_recipe with dry_run true and show the patch, then call it again with dry_run false. Commit the change. Call run_build, then request_rescan with id=F-L001. Call record_decision with decision, reason, changed_files and build_ok.
Show git diff main when done. Do not merge.
```

Expect:

1. `run_recipe` dry-run shows an `UpgradeDependencyVersion` patch on `pom.xml` (api-ldap-model 2.1.7 → 2.1.9 for CVE-2026-103885).
2. Second `run_recipe` applies the change; agent commits on `fix/F-L001`.
3. `run_build` compiles; `request_rescan` returns `still_present: false` with `"stub": true`.
4. Branch + diff only - the agent never merges.

**Say:** this is the Sonatype half of the story - the fix is a pinned OpenRewrite recipe the agent calls, not free-form Java editing. Live Sonatype coverage across the repository is a POV concern.

## Scene 4 - True positive code fix (5 min)

**New chat**, paste:

```text
Triage and remediate finding F-00018.
Work on branch fix/F-00018. Commit your change. Call run_build, then request_rescan with id=F-00018. Call record_decision with decision, reason, changed_files, and build_ok.
Show git diff main when done. Do not merge.
```

Expect: the agent keeps the original `INSERT`, replaces the concatenated value with `?`, switches the plain `Statement` to a `PreparedStatement`, and binds the header value with `setString`. `run_build` passes. `request_rescan` returns `still_present: false` with `"stub": true`.

**Say:** handover is a feature branch. The agent does not merge.

## Scene 5 - Optional hand-back (2 min)

Skip this scene if time is short. **New chat**, paste:

```text
Triage and remediate finding F-00008.
Work on branch fix/F-00008. Commit your change. Call run_build, then request_rescan with id=F-00008. Call record_decision with decision, reason, changed_files, and build_ok.
Show git diff main when done. Do not merge.
```

Expect: no code change. The agent records `NEEDS_DEVELOPER` because the input is the procedure name, and a placeholder cannot stand in for that name. The rescan still reports the finding.

**Honesty:** the saved attempts recorded `NEEDS_DEVELOPER` and did not edit. The checker agrees the finding is still there.

## Close

1. FP-first discipline  
2. Library upgrade via recipe (`run_recipe`)  
3. Agent-authored code fix on `F-00018` keeps the original insert and binds the input  
4. Stub rescan honesty (`stub: true`)  
5. The rehearsal model is the POV model: Qwen3.6-27B FP8, 128K, one L40S  
6. Scanner cutover timeline with the scanner partner  
7. Nothing merged in the lab  

## Timing

| Scene | Minutes |
|---|---|
| Open + platform | 2 |
| FP triage | 3 |
| Library upgrade | 4 |
| Code fix | 5 |
| Optional hand-back | 2 |
| Close | 1 |
