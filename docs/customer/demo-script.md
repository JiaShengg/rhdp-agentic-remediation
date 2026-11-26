# Agentic remediation demo script

Customer-facing walkthrough, about 15 to 18 minutes. Screenshots are in the repository README.

The order is false positive, then the optional library scene, then the code fix, then the optional hand back. Keep that order.

This script is the Path B flow. The agent patch tool is `apply_patch` on the workspace Model Context Protocol (MCP) server. The server returns status `applied` or status `rejected`.

## Opening (30s)

> "This is policy-gated remediation on Red Hat OpenShift AI. Scanner findings come in over MCP. The agent decides true versus false positive from the code, and only then patches a real vulnerability. The workspace server keeps the patch only after the compile and the rescan both pass."

What is stubbed in this rehearsal, and what the proof of value (POV) uses instead, is in the repository README under "Lab and POV".

## Scene 1. Platform shape (1 min)

Show the running model and the stub scanner health from the operator console. Say clearly:

1. The lab model is Qwen3.6-27B FP8 on one L40S at 128K context. That is the same model and context as the POV.
2. The scanner today is a stub over the Open Worldwide Application Security Project (OWASP) BenchmarkJava suite. The POV uses Fortify and Sonatype. The integration method is agreed with the scanner partner.
3. Nothing is merged. The agent stops at the decision and the diff in the developer workspace.

## Scene 2. False positive triage (3 min)

Start a new chat and paste:

```text
Triage finding F-00063. Read the code and decide true or false positive. Give your reason. If it is a false positive, do not change any file. Call record_decision with your decision and reason.
```

Expect the agent to read the file, decide false positive, record the decision, and leave the file unchanged.

Say: the agent judges from the code. The Benchmark answer key is used only afterwards for scoring. It is never an agent input.

## Scene 3. Optional library upgrade on the stock agent (4 min)

Skip this scene on Path B. The workspace MCP server has no `run_recipe` tool, so the library upgrade cannot run there. Run it only on the stock agent, which still calls the stub recipe service.

Start a new chat on the stock agent and paste:

```text
Remediate library finding F-L001.
Call run_recipe with dry_run true and show the patch, then call it again with dry_run false. Call run_build, then request_rescan with id=F-L001. Call record_decision with decision, reason, changed_files and build_ok.
Show the diff when done. Do not merge.
```

Expect:

1. `run_recipe` with dry_run true shows an `UpgradeDependencyVersion` patch on `pom.xml` for api-ldap-model 2.1.7 to 2.1.9. CVE-2026-103885 is a stub identifier from the lab catalogue.
2. The second `run_recipe` applies the change.
3. `run_build` compiles. `request_rescan` returns `still_present: false` with `"stub": true`.
4. The agent does not merge.

Say: this is the Sonatype half of the story. The fix is a pinned OpenRewrite recipe the agent calls. It is not free-form Java editing. Live Sonatype coverage across the repository is a POV concern.

## Scene 4. True positive code fix (5 min)

Start a new chat on Path B and paste:

```text
Triage F-00018. If it is a true positive, give me up to three fix options with a one-line trade-off each. Do not change any file yet.
```

Expect up to three options. Each option keeps the original Structured Query Language (SQL) statement and binds the tainted input with a `PreparedStatement`. The workspace checksum stays the same.

Then paste:

```text
Apply option 2.
```

Expect one `apply_patch` call. Status `applied` means the compile exited 0 and the rescan reported `still_present` false. The diff keeps the original `INSERT`, replaces the concatenated value with an unquoted `?`, and binds that value with `setString`.

Say: the workspace server checked the compile and the rescan before it kept the file. The agent does not merge.

## Scene 5. Optional hand back (2 min)

Skip this scene if time is short. Start a new chat on Path B and paste:

```text
Triage F-00008. If it is a true positive, apply a fix. If it is a false positive, do not change any file.
```

Expect no remaining edit. The tainted value is the stored procedure name. A `?` placeholder cannot stand in for that name. If `apply_patch` returns status `rejected`, the workspace file is restored. After a second rejection the agent hands the finding back with the failed checks.

Say: when the patch is rejected twice, the agent hands the finding back and the file stays as it was.

## Close

1. False positive first, with no file change.
2. The library upgrade is optional and runs on the stock agent, because Path B has no `run_recipe`.
3. The code fix for F-00018 goes through `apply_patch` and is kept only when status is `applied`.
4. The rescan response includes `stub: true`.
5. The rehearsal model is the POV model: Qwen3.6-27B FP8, 128K context, one L40S.
6. Scanner cutover timing is agreed with the scanner partner.
7. Nothing is merged in the lab.

## Timing

| Scene | Minutes |
| --- | --- |
| Open and platform | 2 |
| False positive triage | 3 |
| Optional library upgrade | 4 |
| Code fix | 5 |
| Optional hand back | 2 |
| Close | 1 |
