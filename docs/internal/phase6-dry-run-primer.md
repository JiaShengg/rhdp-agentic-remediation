# Phase 6 - Dry-run primer (agent triage + remediate)

Prove the agent loop on Hermes + stub findings MCP + BenchmarkJava **without** answer-key tools and **without** a pre-written fix script.

## Demo cases (order)

| Order | Id | Category | Expected offline label | Agent task |
|---|---|---|---|---|
| 1 | `F-00063` | pathtraver | FP | Triage only; do not change code |
| 2 | `F-L001` | library | n/a (CVE-2026-103885) | OpenRewrite upgrade via `run_recipe` |
| 3 | `F-00018` | sqli | TP | Remediate a plain `Statement` on a branch, build, rescan |
| 4 | `F-00008` | sqli | TP | Optional. Hand back when the input is an identifier |

### Case selection

Rule: a finding is eligible only if both Qwen3.6-27B triage runs classified it correctly, then the lowest test number wins. False-positive scene: `F-00063`, 3 of 3 under self-checking triage. Code-fix scene: `F-00018`, the lowest eligible true `sqli` whose sink is a plain `Statement`. All 3 saved diffs pass the corrected checker, and a reading of each diff keeps the original insert. Library scene: `F-L001`. Optional scene: `F-00008`, where the agent hands the finding back because the input is the procedure name. `F-00008` is not the code-fix scene.

`F-00052` and `F-00024` were dropped because the model misjudged both of them. The 20-finding scores, including those misses, stay in `docs/internal/triage-batch-results.md` and stay in the video.

Offline SAST labels come from `expectedresults-1.2.csv` via `scripts/score.py` **after** the run. The agent must not read that file (stripped from the workspace).

### Library finding detail (`F-L001`)

| Field | Value |
|---|---|
| Tool | `stub-sonatype` |
| Component | `org.apache.directory.api:api-ldap-model:2.1.7` |
| CVE | [CVE-2026-103885](https://nvd.nist.gov/vuln/detail/CVE-2026-103885) ([GHSA-c2cq-mmh3-7wxh](https://github.com/advisories/GHSA-c2cq-mmh3-7wxh)) |
| Fixed version | `2.1.9` (advisory: 2.1.0 before 2.1.9; verified `mvn -q -DskipTests compile`) |
| Recipe | `org.openrewrite.maven.UpgradeDependencyVersion` only |

## Prompts (paste into Hermes chat)

**1. FP first:**

```text
Triage finding F-00063. Read the code, decide true or false positive, and give your reason. Only change code for a true positive. Call record_decision with your decision and reason.
```

**2. Library upgrade:**

```text
Remediate library finding F-L001.
Work on branch fix/F-L001. Call run_recipe with dry_run true and show the patch, then call it again with dry_run false. Commit the change. Call run_build, then request_rescan with id=F-L001. Call record_decision with decision, reason, changed_files and build_ok.
Show git diff main when done. Do not merge.
```

**3. TP code fix:**

```text
Triage and remediate finding F-00008.
Work on branch fix/F-00008. Commit your change. Call run_build, then request_rescan with id=F-00008. Call record_decision with decision, reason, changed_files, and build_ok.
Show git diff main when done. Do not merge.
```

## Remediation guidance

Hermes concatenates the triage skill and the SQL remediation skill into `SOUL.md` at start, so both texts are in the system prompt. They name no test, file, or expected answer.

```text
# Triage

When deciding whether a finding is a true or false positive:

- Cite the file and line numbers that support the decision.
- State where the input comes from and whether it reaches the sink unchanged.
- When a branch depends on a constant expression, evaluate it explicitly, show the result, and follow only the branch that runs.
- Only change code when the finding is a true positive.
- If the evidence does not support either decision, record NEEDS_DEVELOPER.
- Call record_decision with the decision and the reason.

# SQL injection remediation

When a finding is SQL injection, change the query without changing what the program does.

- Keep the original behaviour and the original inputs.
- Move user input out of the SQL string into `?` placeholders on a PreparedStatement or CallableStatement.
- Bind each former input with the matching setter (`setString`, `setObject`, or the setter for that type).
- Do not delete inputs, hardcode values, or comment out code to make a finding disappear.
- If a safe fix is not clear, record the finding as NEEDS_DEVELOPER instead of guessing.

Before committing a fix, show `git diff` and check it against these rules:

- The SQL text is unchanged except for value placeholders.
- Every former user input is still used and bound to a placeholder.
- No placeholder replaces a procedure, table, or column name.
- No new hardcoded literals.
- No code is deleted or commented out to remove the finding.

If any rule fails, revise the fix once. If the revision still fails, record NEEDS_DEVELOPER and do not commit.
```

## Success criteria

1. FP: agent abstains from edits; `record_decision` says FP with a code-based reason
2. Library: `run_recipe` dry-run then run; `pom.xml` moves to 2.1.9; build ok; rescan `still_present: false` with `"stub": true`
3. TP: agent edits the Java file itself (parameterized SQL); branch `fix/F-00008` exists; the stub SQL checks all pass
4. `run_build` returns `ok: true` from the in-cluster build-runner (`mvn -q -DskipTests compile`)
5. `request_rescan` returns `still_present: false` with `"stub": true`
6. `scripts/score.py` matches SAST decisions to the local CSV

## Model note

Attempt A and Attempt B below used Qwen2.5 on the L4 (16K). Coder emits markdown JSON tool stubs under `tool_choice=auto`. `lab/hermes/patch_coder_tool_json.py` can promote allowlisted names, and it is a no-op unless `HERMES_TEXT_TOOLCALL_FALLBACK=true`. That variable is unset for Qwen3.6.

The lab model for the rest of this log is Qwen3.6-27B FP8 on one L40S at 128K, via a custom vLLM 0.19.1 runtime. The RHOAI `vllm-cuda-runtime` is vLLM 0.10.1.1 and cannot serve this checkpoint. Thinking stays on (`enable_thinking` and `preserve_thinking`). Sampling is the checkpoint `generation_config` for general thinking: temperature 1.0, top_p 0.95, top_k 20. Hermes merges `extra_body` over the typed chat body. Triage leaves `temperature` unset, so the checkpoint default of 1.0 stands. A remediation run can set `extra_body.temperature` and restart Hermes. The retest below did not justify a lower temperature. Leave remediation at the checkpoint default as well. At 0.6, two of the three fixes replaced the original call with a different query and a hardcoded password. At 1.0 the agent either stopped for a developer, bound the procedure name as a placeholder value, or ran out of turns. None of the six kept the original call.

## Dry-run log (2026-11-22, lab namespace)

### Attempt A — Qwen2.5-7B-Instruct

**Verdict: both findings failed. No success commit.**

| Step | Result | Notes |
|---|---|---|
| FP triage F-00052 | FAIL | Recorded **TP**; dirty-edited `BenchmarkTest00052.java`. Session `local-c27f647c…`. |
| TP remediate F-00024 | FAIL | Non-fix `setString` index change; SQL still concatenated. Session `local-84bd3428…`. |
| run_build / request_rescan | FAIL | Narrated only. |
| score.py | SKIP | |

### Attempt B — Qwen2.5-Coder-7B-Instruct (+ tool-JSON promote patch)

**Verdict: FP pass, TP fail. Not demo-ready end-to-end. No success commit.**

| Step | Result | Notes |
|---|---|---|
| FP triage F-00052 | PASS | `record_decision` → **FP**; no file edits; workspace stayed clean. Session `local-3e22a1bb…`. Log: `/tmp/dryrun-fp-coder.txt`. |
| TP remediate F-00024 | FAIL | Created `fix/F-00024` and applied a **broken** patch (`String` decl dropped, missing `;`, no `setString(2, param)`). Collapsed into prose before commit/build/rescan. Session `local-9d3ce9a3…`. Log: `/tmp/dryrun-tp-coder.txt`. |
| run_build | FAIL | Not called. |
| request_rescan | FAIL | Not called. |
| score.py | PARTIAL | Would score F-00052 correct (FP); F-00024 absent. |

Coder note: FP-first story works on this SKU with the promote patch. Free-form TP remediate still needs POV-class model or a tighter multi-shot harness.

### Attempt C — Library upgrade F-L001 (Coder-7B)

Attempts recorded below after `run_recipe` landed (up to 3).

| Attempt | Tools called | Patch | Build | Rescan | Verdict |
|---|---|---|---|---|---|
| C1 | _pending_ | | | | |
| C2 | _pending_ | | | | |
| C3 | _pending_ | | | | |

## Qwen3.6-27B FP8 (vLLM 0.19.1, one L40S)

Custom runtime required. RHOAI `vllm-cuda-runtime` left untouched at 0.10.1.1.

| Attempt | max_model_len | KV result | Kept |
|---|---:|---|---|
| 1 | 65536 | 10.4 GiB available. Maximum concurrency for 65,536 tokens per request: 4.52x. | no |
| 2 | 131072 | 10.4 GiB available. Maximum concurrency for 131,072 tokens per request: 2.41x. Two sessions still fit. | yes |

No `--language-model-only`. Parsers: `reasoning-parser=qwen3`, `tool-call-parser=qwen3_coder`, auto tool choice on. `max_num_seqs=2`, `kv-cache-dtype=fp8`, `gpu-memory-utilization=0.92`, prefix caching on.

### Smoke tests on the kept 131072 server

`/v1/models` listed `qwen36-27b`. A plain chat with thinking off returned content `pong` and finish reason `stop`.

Native tool call (`tool_choice: auto`, one function `get_weather`, thinking on). `finish_reason` is `tool_calls`. The tool call is a `tool_calls` field, not JSON in `content` (`content` is null).

```json
{
  "object": "chat.completion",
  "model": "qwen36-27b",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": null,
        "tool_calls": [
          {
            "id": "chatcmpl-tool-82528867c3de081c",
            "type": "function",
            "function": {
              "name": "get_weather",
              "arguments": "{\"city\": \"Paris\"}"
            }
          }
        ]
      },
      "finish_reason": "tool_calls"
    }
  ]
}
```

The same native `tool_calls` shape was also returned on the 65536 server before the 131072 restart.

### Hermes cutover

Config model `qwen36-27b`, `context_length` 131072, in-cluster base URL. `MINIMUM_CONTEXT_LENGTH` in the image is still 64000. The start script does not patch it. `HERMES_TEXT_TOOLCALL_FALLBACK` is unset. `hermes tools list` reports MCP server `stub-fortify` with all tools enabled. The bridge registers `list_findings`, `get_finding`, `run_build`, `run_recipe`, `request_rescan`, `record_decision`.

### `run_recipe` dry-run (operator, before agent attempts)

Rejected recipe `org.openrewrite.java.RemoveUnusedImports`: HTTP 400, `only org.openrewrite.maven.UpgradeDependencyVersion is supported`.

`dry_run: true` for `org.apache.directory.api:api-ldap-model` 2.1.7 to 2.1.9: `ok: true`, exit 0, `version_before` 2.1.7, `version_after` 2.1.7 (dry-run does not edit the file). Patch from `target/rewrite/rewrite.patch` (regenerated by this call):

```diff
diff --git a/pom.xml b/pom.xml
--- a/pom.xml
+++ b/pom.xml
@@ -670,7 +670,7 @@
         <dependency>
             <groupId>org.apache.directory.api</groupId>
             <artifactId>api-ldap-model</artifactId>
-            <version>2.1.7</version>
+            <version>2.1.9</version>
         </dependency>
```

The build-runner image has no git. The runner reads the OpenRewrite patch file instead of `git diff`.

`run_build` initially failed in the agent because Spotless looks up `origin/master` and the lab seed has no such ref. Attempt D1 renamed `main` to a branch literally named `origin/master` to get past that. After those three attempts, `run_build` was given the same Spotless skip as `run_recipe`. A direct compile then returned `ok: true`, exit 0. Later attempts use that runner. The F-00052 decisions below were already wrong before that change.

### Attempt D — F-00052 on Qwen3.6-27B FP8

Expected label: FP. Native MCP tools were used (`get finding`, and on some attempts `patch` / `run build` / `record decision`). No text-JSON fallback.

| Attempt | Wall clock | Decision | Tree | Verdict |
|---|---:|---|---|---|
| D1 | 143s | TP. Edited `BenchmarkTest00052.java` to `{call procedure( ? )}` plus `setString`. `build_ok: true` only after renaming the branch. Session `local-22a678ad…`. | dirty | FAIL |
| D2 | 73s | TP. `changed_files` listed the Java file, but the worktree had no content diff. `build_ok: false`. | clean tree, branch left as `origin/master` | FAIL |
| D3 | 121s | TP. Allowlist edit of the same Java file. `build_ok: true`. | dirty | FAIL |

0 / 3. The model treats `"{call " + param + "}"` as a real injection. The offline label is false positive. D2 and D3 started after D1 had renamed `main`; the reset used then did not recreate `main`. The source they read was still the seed file.

### Attempt E — F-L001 on Qwen3.6-27B FP8

| Attempt | Wall clock | What happened | Verdict |
|---|---:|---|---|
| E1 | 526s | Native `run recipe` dry-run (219s) returned the 2.1.7 to 2.1.9 pom patch. Second `run recipe` (198s) applied it. Commit `1ebf448` on `fix/F-L001`. `main` stayed at the seed. `run build` passed. `request rescan` was called; the agent reported `still_present: false`. `record_decision` TP, `build_ok: true`, files `pom.xml` and `rewrite.yml`. Not merged. Session `local-0b5221dc…`. | PASS |

Stopped after the first pass. Later attempts were not run.

### Attempt F — F-00024 on Qwen3.6-27B FP8

Expected: parameterized SQL, commit on `fix/F-00024`, build ok, rescan `still_present: false`, not merged. None of the three did that.

| Attempt | Wall clock | What happened | Verdict |
|---|---:|---|---|
| F1 | 147s | Changed `setString(1, "foo")` to `setString(1, param)` and left `PASSWORD='" + param + "'"`. Build passed. Rescan stayed `still_present: true`. Session continued on `fix/F-00024`, not merged. | FAIL |
| F2 | 137s | Deleted `param` and hardcoded `PASSWORD='***'`. Build passed. Rescan went clear because the concat pattern was gone. That is not a parameterized binding of the user value. Commit `d989064`. Not merged. | FAIL |
| F3 | 264s | Same hardcoded password, unused `param` left in the method, plus a comment calling it a Fortify suppression. Build passed. Commit `d5c0bb1`. Not merged. | FAIL |

0 / 3. Native tool calls were used. The text-tool fallback did not fire.

### Triage batches

Two full 20-finding runs are in `docs/internal/triage-batch-results.md` next to the Coder-7B scores. Qwen3.6 run 1: 16 correct, 4 wrong, 0 no decision. Run 2: 17 correct, 3 wrong, 0 no decision. `F-00052` was called TP both times. `F-00024` was called FP both times.

## Retest after the behaviour check (2026-11-23)

Each code-fix attempt started from the seed on `main`. Temperature was set in Hermes `extra_body` and Hermes was restarted. Triage left `temperature` unset (checkpoint 1.0). A pass needs a committed change on the fix branch, a successful build, a rescan whose checks all pass, and the original behaviour kept. The captured transcripts did not include the raw rescan JSON, so the check column is the stub function run on the committed diff. The agent did call `request_rescan` on the attempts that changed code.

### F-00008 at temperature 1.0

| Attempt | Wall clock | Change | Checks that failed | Verdict |
|---|---:|---|---|---|
| 1 | 199s | No edit. Recorded `NEEDS_DEVELOPER` because the input is the procedure name. | `no_tainted_concat` on the unchanged source | FAIL |
| 2 | 125s | Commit on `fix/F-00008`: `{call ?}` and `setString(1, param)`. Build reported ok. Decision TP. | none. The stub clears it. The placeholder stands in for the procedure name, so the original call is not preserved. | FAIL |
| 3 | 296s | Hit the 22-turn cap and stopped without a commit or a new decision. | not run | FAIL |

0 / 3.

### F-00008 at temperature 0.6

| Attempt | Wall clock | Change | Checks that failed | Verdict |
|---|---:|---|---|---|
| 1 | 377s | Replaced the call with a `SELECT` that binds `param` as the username and hardcodes the password. Build reported ok. Decision TP. | none. The stub clears it because the tainted name is still bound, so the hardcoded-literal rule does not fire. | FAIL |
| 2 | 296s | Same `{call ?}` plus `setString(1, param)` as the 1.0 second attempt. Build reported ok. Decision TP. | none. Same stub gap: the procedure name is bound as a value. | FAIL |
| 3 | 242s | Same rewritten `SELECT` and hardcoded password as the first 0.6 attempt, still using `executeQuery`. Build reported ok. Decision TP. | none. Same stub gap as the first 0.6 attempt. | FAIL |

0 / 3. Lowering temperature did not help. Leave fixes at the checkpoint default.

### F-00063 at the triage default

Answer key: false. A pass is `FP` and no edit.

| Attempt | Wall clock | Decision | Tree | Verdict |
|---|---:|---|---|---|
| 1 | 100s | FP. The flagged line sets a cookie flag, not a file path. | clean | PASS |
| 2 | 88s | FP. A constant expression always selects a fixed path segment. | clean | PASS |
| 3 | 167s | TP. Added a canonical-path check in `doPost` and left the file dirty on `main`. | dirty | FAIL |

2 / 3.

### F-L001 once, temperature unset

| Attempt | Wall clock | What happened | Verdict |
|---|---:|---|---|
| 1 | 523s | `run_recipe` dry-run then apply. `pom.xml` 2.1.7 to 2.1.9 for CVE-2026-103885. Commit on `fix/F-L001`. `run_build` passed. `request_rescan` reported `still_present: false`. `record_decision` TP, files `pom.xml` and `rewrite.yml`. Not merged. | PASS |

## Retest after the stricter check and the audit log (2026-11-23)

Temperature stayed unset, so remediation used the checkpoint default of 1.0. The Hermes turn cap was 30. Every code-fix attempt started from the seed on `main`. Scores come from the stub audit log, not from the agent's prose. Turns below are Hermes replies in the transcript. The run did not print an iteration counter.

The audit volume was root-owned and the stub runs as uid 1001, so the first writes failed silently. An init container makes `/audit` writable. The sample trace after that fix is a `get_finding` call whose session id is `audit-smoke-1`.

### Self-checking triage, all 20 findings

Each finding was triaged in two independent sessions. Agreement is the recorded decision. A disagreement is `NEEDS_DEVELOPER`.

`score.py`: correct=14, wrong=3, needs_developer=3, decided=17, accuracy_on_decided=14/17.

Wrong: `F-00024` (FP, truth TP), `F-00052` (TP, truth FP), `F-00051` (TP, truth FP). Handed back: `F-00147`, `F-00063`, `F-00064`.

### F-00018, plain Statement, temperature 1.0

| Attempt | Time | Turns | Failed checks | Change | Verdict |
|---|---:|---:|---|---|---|
| 1 | 167s | 8 | `tainted_input_bound`, `no_hardcoded_replacement`, `sql_text_preserved` | `VALUES ('foo', ?)`, `prepareStatement`, `setString(1, param)`, `executeUpdate()`. Build ok. Decision TP. | FAIL |
| 2 | 174s | 7 | same three | Same shape as attempt 1, with a space before `?`. Build ok. Decision TP. | FAIL |
| 3 | 133s | 6 | same three | `VALUES ('foo',?)`, `prepareStatement`, `setString(1, param)`, `executeUpdate()`. Build ok. Decision TP. | FAIL |

0 / 3. Reading the diffs, the insert and the header value are kept. The stub and that reading disagree. The checker marks `headers` tainted because that assignment calls `getHeaders`, and it does not follow `param = headers.nextElement()`. `setString(param)` therefore does not count as binding the tainted name, the quoted `'foo'` fails the hardcoded-literal rule, and the SQL comparison does not treat `param` as the slot to replace.

### F-00008, CallableStatement, temperature 1.0

| Attempt | Time | Turns | Failed checks | Change | Verdict |
|---|---:|---:|---|---|---|
| 1 | 200s | 4 | `no_tainted_concat`, `uses_placeholder`, `tainted_input_bound`, `sql_text_preserved` | No edit. Recorded `NEEDS_DEVELOPER` because the input is the procedure name. | FAIL |
| 2 | 118s | 5 | same four | No edit. Same `NEEDS_DEVELOPER` reason. | FAIL |
| 3 | 200s | 11 | same four | No edit. Same `NEEDS_DEVELOPER` reason. | FAIL |

0 / 3. The unchanged source still has the finding. The reading agrees with the stub.

### F-00063 through self-checking triage

Answer key: false. A pass is both sessions recording FP.

| Attempt | Sessions | Decision | Verdict |
|---|---|---|---|
| 1 | 102s, 2 turns and 92s, 2 turns | FP, FP | PASS |
| 2 | 119s, 2 turns and 90s, 2 turns | FP, FP | PASS |
| 3 | 114s, 2 turns and 101s, 2 turns | FP, FP | PASS |

3 / 3. The transcripts read the file and do not show a commit.

### F-L001 once, temperature unset

| Attempt | Time | Turns | What happened | Verdict |
|---|---:|---:|---|---|
| 1 | 509s | 5 | `run_recipe` dry-run then apply. `pom.xml` 2.1.7 to 2.1.9. `rewrite.yml` added. `run_build` passed. Audit log `still_present: false`. `record_decision` TP. Not merged. | PASS |

Neither code-fix case passed 2 of 3 under the checker that was live during the run, so that run did not unlock a code-fix scene.

## Offline rescore after the taint fix (no new model run)

The saved diffs and decisions were not edited. The corrected checker was run on those files only.

| Attempt | Old result | New result | Checks that changed | Reading |
|---|---|---|---|---|
| F-00018 1 | FAIL. `tainted_input_bound`, `no_hardcoded_replacement`, `sql_text_preserved` | cleared | those three, false to true | Keeps the insert. Binds the header value with `setString(1, param)`. Space before `?`. |
| F-00018 2 | FAIL. Same three checks | cleared | those three, false to true | Same shape as attempt 1, with its own connection variable. |
| F-00018 3 | FAIL. Same three checks | cleared | those three, false to true | Same shape, with no space before `?`. |
| F-00008 1 | FAIL. No edit. `NEEDS_DEVELOPER` | still present. No check changed | none | No code change. The procedure-name call is still there. |
| F-00008 2 | FAIL. No edit. `NEEDS_DEVELOPER` | still present. No check changed | none | No code change. |
| F-00008 3 | FAIL. No edit. `NEEDS_DEVELOPER` | still present. No check changed | none | No code change. |

The `{call ?}` fix, the rewritten `SELECT` with a hardcoded password, and the earlier password-literal fixes stay `still_present`. None of them pass under the corrected checker.

`F-00018` is the code-fix scene because all 3 rescored attempts pass and the reading agrees. `F-00008` stays the optional hand-back scene.

## Offline score (not in the customer script)

Operator runs `scripts/score.py` against a local Benchmark `expectedresults-1.2.csv` and the recorded decisions. Show the correct count, the wrong count, and the build pass rate. The CSV never enters the agent workspace. The customer script does not include this scene, and it does not repeat the checker rescore above.

## Teach order

1. FP triage (`F-00063`) - proves the agent is not a "fix everything" bot.
2. Library upgrade (`F-L001`) - Sonatype-shaped fix via recipe, not free-form Java.
3. TP code fix (`F-00018`) - the three saved diffs pass the corrected checker and keep the original insert.
4. Optional hand-back (`F-00008`) - the agent records `NEEDS_DEVELOPER` and does not edit. `F-00024` was dropped after the model misjudged it.
