# Triage batch results (Coder-7B)

- Run date: **2026-11-22**
- Model: **Qwen/Qwen2.5-Coder-7B-Instruct** (lab L4, 16K)
- Prompt: triage-only; `record_decision` required; no code changes
- Expected CSV: local `expectedresults-1.2.csv` (never in agent workspace)
- Catalog: 20 SAST findings (library `F-L001` excluded from triage scoring)

## Run 1

- Recorded decisions: 3 / 20
- Correct: **1**
- Wrong: **2**
- No decision: **17**

### Score table

| finding | decision | truth | result | category |
|---|---|---|---|---|
| F-00008 | FP | TP | WRONG | sqli |
| F-00014 | TP | TP | ok | xss |
| F-00006 | FP | TP | WRONG | cmdi |

### Per-category breakdown

| category | correct | wrong | no decision |
|---|---:|---:|---:|
| sqli | 0 | 1 | 4 |
| xss | 1 | 0 | 4 |
| pathtraver | 0 | 0 | 5 |
| cmdi | 0 | 1 | 4 |

### No decision / broken tool calls

- No decision: `['F-00018', 'F-00024', 'F-00052', 'F-00104', 'F-00013', 'F-00030', 'F-00147', 'F-00151', 'F-00001', 'F-00002', 'F-00011', 'F-00063', 'F-00064', 'F-00007', 'F-00015', 'F-00051', 'F-00090']`
- Broke or failed `record_decision` (mentioned / error in transcript): `['F-00090', 'F-00104']`

## Run 2

- Recorded decisions: 1 / 20
- Correct: **0**
- Wrong: **1**
- No decision: **19**

### Score table

| finding | decision | truth | result | category |
|---|---|---|---|---|
| F-00011 | FP | TP | WRONG | pathtraver |

### Per-category breakdown

| category | correct | wrong | no decision |
|---|---:|---:|---:|
| sqli | 0 | 0 | 5 |
| xss | 0 | 0 | 5 |
| pathtraver | 0 | 1 | 4 |
| cmdi | 0 | 0 | 5 |

### No decision / broken tool calls

- No decision: `['F-00008', 'F-00018', 'F-00024', 'F-00052', 'F-00104', 'F-00013', 'F-00014', 'F-00030', 'F-00147', 'F-00151', 'F-00001', 'F-00002', 'F-00063', 'F-00064', 'F-00006', 'F-00007', 'F-00015', 'F-00051', 'F-00090']`
- Broke or failed `record_decision` (mentioned / error in transcript): `['F-00008', 'F-00024']`

## Notes

- Both runs show very low `record_decision` completion under Coder-7B + allowlisted tool-JSON promote (file-read text stubs are dropped; many sessions end without a recorded decision).
- Results are reported as-is for both runs; neither run was discarded.

# Triage batch results (Qwen3.6-27B FP8)

- Run date: **2026-11-23** (decision timestamps are 2026-11-22 UTC)
- Model: **Qwen/Qwen3.6-27B-FP8** (one L40S, 128K, thinking on)
- Prompt: same triage-only prompt as the Coder runs
- Catalog: 20 SAST findings. Library `F-L001` is excluded and shows up as the one missing id.
- Native tool calls. `HERMES_TEXT_TOOLCALL_FALLBACK` was unset.

## Side by side

| Model | Run | Correct | Wrong | No decision |
|---|---:|---:|---:|---:|
| Qwen2.5-Coder-7B | 1 | 1 | 2 | 17 |
| Qwen2.5-Coder-7B | 2 | 0 | 1 | 19 |
| Qwen3.6-27B FP8 | 1 | 16 | 4 | 0 |
| Qwen3.6-27B FP8 | 2 | 17 | 3 | 0 |

Run 2's jsonl has two `F-00024` rows, both FP. Unique findings are 17 correct and 3 wrong. `score.py` counts every line, so it prints `correct=17 wrong=4 n=21`.

## Run 1

- Recorded decisions: 20 / 20
- Correct: **16**
- Wrong: **4**
- No decision: **0**

### Score table

| finding | decision | truth | result | category |
|---|---|---|---|---|
| F-00008 | TP | TP | ok | sqli |
| F-00018 | TP | TP | ok | sqli |
| F-00024 | FP | TP | WRONG | sqli |
| F-00052 | TP | FP | WRONG | sqli |
| F-00104 | FP | FP | ok | sqli |
| F-00013 | TP | TP | ok | xss |
| F-00014 | TP | TP | ok | xss |
| F-00030 | TP | TP | ok | xss |
| F-00147 | FP | FP | ok | xss |
| F-00151 | FP | FP | ok | xss |
| F-00001 | FP | TP | WRONG | pathtraver |
| F-00002 | TP | TP | ok | pathtraver |
| F-00011 | TP | TP | ok | pathtraver |
| F-00063 | FP | FP | ok | pathtraver |
| F-00064 | FP | FP | ok | pathtraver |
| F-00006 | TP | TP | ok | cmdi |
| F-00007 | TP | TP | ok | cmdi |
| F-00015 | TP | TP | ok | cmdi |
| F-00051 | TP | FP | WRONG | cmdi |
| F-00090 | FP | FP | ok | cmdi |

### Per-category breakdown

| category | correct | wrong | no decision |
|---|---:|---:|---:|
| sqli | 3 | 2 | 0 |
| xss | 5 | 0 | 0 |
| pathtraver | 4 | 1 | 0 |
| cmdi | 4 | 1 | 0 |

### No decision

- None. `F-L001` is the library case and is not scored.

## Run 2

- Recorded decisions: 20 / 20 findings (21 jsonl rows; `F-00024` twice)
- Correct: **17** unique
- Wrong: **3** unique (`F-00024`, `F-00052`, `F-00051`)
- No decision: **0**

### Score table

| finding | decision | truth | result | category |
|---|---|---|---|---|
| F-00008 | TP | TP | ok | sqli |
| F-00018 | TP | TP | ok | sqli |
| F-00024 | FP | TP | WRONG | sqli |
| F-00052 | TP | FP | WRONG | sqli |
| F-00104 | FP | FP | ok | sqli |
| F-00013 | TP | TP | ok | xss |
| F-00014 | TP | TP | ok | xss |
| F-00030 | TP | TP | ok | xss |
| F-00147 | FP | FP | ok | xss |
| F-00151 | FP | FP | ok | xss |
| F-00001 | TP | TP | ok | pathtraver |
| F-00002 | TP | TP | ok | pathtraver |
| F-00011 | TP | TP | ok | pathtraver |
| F-00063 | FP | FP | ok | pathtraver |
| F-00064 | FP | FP | ok | pathtraver |
| F-00006 | TP | TP | ok | cmdi |
| F-00007 | TP | TP | ok | cmdi |
| F-00015 | TP | TP | ok | cmdi |
| F-00051 | TP | FP | WRONG | cmdi |
| F-00090 | FP | FP | ok | cmdi |

The second `F-00024` row is also FP / WRONG. Both reasons say `param` is unused and miss `PASSWORD='" + param + "'"`.

### Per-category breakdown

Unique findings:

| category | correct | wrong | no decision |
|---|---:|---:|---:|
| sqli | 3 | 2 | 0 |
| xss | 5 | 0 | 0 |
| pathtraver | 5 | 0 | 0 |
| cmdi | 4 | 1 | 0 |

### No decision

- None.

## Notes

- Both Qwen3.6 runs are kept. Run 2 is not a replacement for run 1.
- `F-00052` is wrong in both runs (called TP). That matches the three phase 6 dry-runs, which also called it TP.
- `F-00024` is wrong in both runs (called FP). The phase 6 remediate attempts did not parameterize the password either.
- Transcripts: `docs/internal/triage-qwen36-run1/` and `docs/internal/triage-qwen36-run2/`.
