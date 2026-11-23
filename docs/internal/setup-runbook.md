# Remediation POV Prep - Setup Runbook

Step-by-step rebuild of the agentic remediation lab on RHDP OpenShift + RHOAI (cluster pattern: `<GUID>` / namespace `remediation-pov`).

**Audience:** you (operator), not the customer.  
**Goal:** Hermes UI + in-cluster vLLM + stub Fortify MCP + BenchmarkJava, ready for TC-04/05.

---

## 0. Prerequisites

| Need | Notes |
|---|---|
| RHDP GPU sandbox (NVIDIA L4-class, ~24GB) | Extend auto-stop before anything else |
| `oc` logged in as cluster-admin | `oc whoami` |
| Local tools | `oc`, `curl`, `jq`, Java 8+/Maven (for offline verify), git |
| Manifests | This repo under `lab/` |
| BenchmarkJava upstream | e.g. `https://github.com/OWASP-Benchmark/BenchmarkJava` |

Architecture you are building:

```text
Browser → Hermes Dashboard
              ├─ model → vLLM InferenceService (qwen25-7b) on GPU
              ├─ MCP   → stub-fortify → stub-findings-mcp (REST)
              └─ files → /opt/data/workspace/BenchmarkJava
```

---

## 1. Keep the cluster alive

1. In RHDP catalog → your service → extend **auto-stop**.
2. Note **auto-destroy** separately (often Sunday) - extending stop does not extend destroy.
3. Confirm GPU node:

```bash
oc get nodes -o custom-columns=NAME:.metadata.name,GPU:.status.allocatable.nvidia\\.com/gpu
```

Expect one worker with `GPU=1`. The L4 pool is the lab default. The L40S pool below is optional and billed separately.

### L40S node (Qwen3.6-27B FP8)

`lab/machineset-l40s.yaml` is gitignored. It is a filled copy of `lab/machineset-l40s.example.yaml` and contains the infrastructure ID, AMI, subnet, security groups, and IAM instance profile.

Fill the template from a live worker MachineSet:

```bash
oc get machineset -n openshift-machine-api -o yaml
```

Copy `providerSpec` from the existing GPU or worker set into `lab/machineset-l40s.yaml`: AMI id, subnet `tag:Name`, both security group `tag:Name` values, IAM instance profile, region, and zone. Set `instanceType: g6e.2xlarge`, `replicas: 1`, the `nvidia.com/gpu=True:NoSchedule` taint, and label `rhdp.redhat.com/gpu: l40s`. Apply that file. The new volume must land in the same zone as the L40S node (`WaitForFirstConsumer` on the model PVC).

Scale the node to zero after each session:

```bash
oc scale machineset <INFRA_ID>-worker-gpu-l40s-<ZONE> --replicas=0 -n openshift-machine-api
```

`g6e.2xlarge` is about US$2.24 an hour on demand in us-east-1. Look up the current us-east-2 on-demand price before quoting it. Do not reuse the us-east-1 figure for us-east-2.

Serve Qwen3.6-27B FP8 from `lab/phase2-qwen36-pvc-job.yaml`, `lab/phase2-qwen36-runtime.yaml`, and `lab/phase2-qwen36-inferenceservice.yaml`. The RHOAI `vllm-cuda-runtime` (vLLM 0.10.1.1) is too old for this checkpoint. The custom runtime is vLLM 0.19.1, one GPU, `--reasoning-parser=qwen3`, `--tool-call-parser=qwen3_coder`, `--enable-auto-tool-choice`, FP8 KV cache. Start at `--max-model-len=65536`. On this node that length reported 4.52x concurrency. `--max-model-len=131072` then reported 2.41x, so two sessions still fit and 131072 is what the manifests keep. Do not add `--language-model-only` unless the GPU OOMs. Schedule the download Job and the predictor with `rhdp.redhat.com/gpu: l40s` so the volume binds in the L40S zone. The download Job sets `HF_HUB_DISABLE_XET=1` so shards come from the LFS hosts. Keep `cas-server.xethub.hf.co` on the EgressFirewall allowlist anyway: the hub client can still redirect to Xet, and the fix is to allow the host, not to delete the firewall.

---

## 2. Namespace + RHOAI sanity

```bash
oc new-project remediation-pov || oc project remediation-pov
oc get datasciencecluster -A
oc get csv -n nvidia-gpu-operator   # or wherever GPU Operator lives
```

Confirm RHOAI / `DataScienceCluster` Ready and a `vllm-cuda-runtime` ServingRuntime exists (from RHOAI templates).

---

## 3. Model weights PVC + download Job

1. Apply the model PVC + download Job:

```bash
oc apply -f lab/phase2-model-pvc-job.yaml
oc logs -f job/download-qwen25-7b -n remediation-pov
```

2. Wait until Job `Completed`. Weights land on PVC `qwen25-7b-model` (~15G for Qwen2.5-7B-Instruct).

**Gotchas we hit:**

- PVC must schedule in the same AZ / on the GPU node as the InferenceService (pin if multi-AZ).
- Prefer `huggingface_hub.snapshot_download` as root in the Job if HF CLI / perms fail.
- If the download Job cannot reach Hugging Face, add the missing host to the `EgressFirewall` allowlist in `lab/networkpolicy.yaml` and re-apply that file. Hugging Face Xet uses `cas-server.xethub.hf.co` (plus `cas-bridge.xethub.hf.co` and `transfer.xethub.hf.co`). Do not delete the `EgressFirewall`. EgressFirewall has no wildcard dnsName, so each host is listed exactly.

---

## 4. Deploy vLLM InferenceService

```bash
oc apply -f lab/phase2-inferenceservice.yaml
# do not apply phase2-route.yaml by default (public model URL)
oc get isvc qwen25-7b -n remediation-pov -w
```

Required predictor args (L4 + Hermes tools):

- `--max-model-len=16384`
- `--gpu-memory-utilization=0.92`
- `--enable-auto-tool-choice`
- `--tool-call-parser=hermes`

Smoke:

```bash
# in-cluster from any pod, or via Route
curl -sS "$OPENAI_BASE/v1/models" | jq .
curl -sS "$OPENAI_BASE/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen25-7b","messages":[{"role":"user","content":"Say OK"}],"max_tokens":8}'
```

In-cluster base URL used by Hermes:

`http://qwen25-7b-openai.remediation-pov.svc.cluster.local/v1`

**Gotcha:** if you change args and an old predictor holds the GPU, force-delete the predictor pod so the new one can schedule.

---

## 5. BenchmarkJava (local + agent workspace)

Local (verifier / golden cases):

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git ~/Projects/BenchmarkJava
cd ~/Projects/BenchmarkJava
mvn -q -DskipTests compile
```

Golden demo cases (see `lab/phase3-golden-findings.json`):

| Role | Finding ID | Test class |
|---|---|---|
| TC-04 true positive | `F-00024` | `BenchmarkTest00024` |
| TC-05 false positive | `F-00052` | `BenchmarkTest00052` |

Hermes clones the same fork into `/opt/data/workspace/BenchmarkJava` on first start (see deploy bootstrap).

---

## 6. Stub Fortify-shaped findings MCP

```bash
oc apply -f lab/stub-findings-mcp/deploy.yaml
oc rollout status deploy/stub-findings-mcp -n remediation-pov
curl -sk https://stub-findings-mcp-remediation-pov.apps.<cluster>/health
curl -sk https://stub-findings-mcp-remediation-pov.apps.<cluster>/findings | jq .
curl -s localhost:8080/findings/F-00052 | jq .
```

Tools exposed (REST + MCP bridge): `list_findings`, `get_finding`, `request_rescan`, `run_build`, `record_decision`.

Cutover later: replace this Deployment with the scanner partner Fortify MCP; keep the same tool names if possible.

---

## 7. Hermes agent + dashboard

Apply network controls **after** the model download Job has succeeded (and preferably after stub is running). See section 3 if CDN redirects fail under the EgressFirewall.

```bash
oc apply -f lab/networkpolicy.yaml   # NetworkPolicy + EgressFirewall
oc apply -f lab/hermes/deploy.yaml
oc rollout status deploy/hermes-agent -n remediation-pov
```

Defaults in this prep:

| Item | Value |
|---|---|
| Image | `docker.io/nousresearch/hermes-agent:v0.23.3` |
| UI | `https://hermes-agent-remediation-pov.apps.<cluster>` |
| Login | admin + password from Hermes Secret (not committed) |
| Model | `qwen25-7b` via Chat Completions (`api_mode: chat_completions`) |
| Context | `16384` (Hermes `MINIMUM_CONTEXT_LENGTH` patched in `start.sh` for L4) |

### L4-critical config (do not skip)

Already baked into `lab/hermes/deploy.yaml` ConfigMap:

1. `platform_toolsets.cli: [file, terminal]` - drop web/browser/vision/…  
2. `tools.tool_search.enabled: off` - **must** inline MCP tools (otherwise mid-turn `tool_search` looks like context overflow)  
3. `agent.reasoning_effort: low` - vLLM rejects `none`  
4. `model.context_length: 16384` matching vLLM `--max-model-len`

---

## 8. Wire-check (before any customer demo)

```bash
# MCP bridge from Hermes pod
HERMES=$(oc get pods -n remediation-pov -l app=hermes-agent -o jsonpath='{.items[0].metadata.name}')
oc exec -n remediation-pov "$HERMES" -c hermes -- \
  hermes tools list | grep -E 'enabled|MCP|stub'

# CLI oneshot smoke (same path as UI tools)
oc exec -n remediation-pov "$HERMES" -c hermes -- bash -lc '
  HERMES_HOME=/opt/data HOME=/opt/data \
  hermes chat --oneshot -Q --max-turns 6 --in /opt/data/workspace/BenchmarkJava \
    -q "Triage finding F-00052. Read the code, decide true or false positive, give your reason, call record_decision. Only change code for a true positive."
'
```

Expect: FP decision from code review, no file edits, `record_decision` recorded. Then run the customer demo script (`docs/customer/demo-script.md`).

---

## 9. Rebuild order (cheat sheet)

```bash
oc project remediation-pov
oc apply -f lab/phase2-model-pvc-job.yaml          # once; wait for Completed
oc apply -f lab/phase2-inferenceservice.yaml
oc apply -f lab/stub-findings-mcp/deploy.yaml
oc apply -f lab/networkpolicy.yaml                # after download (+ stub); includes EgressFirewall
oc apply -f lab/hermes/deploy.yaml
oc delete pod -n remediation-pov -l app=hermes-agent --force --grace-period=0   # pick up bootstrap
```

---

## 10. Known failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| “conversation grown too long” at ~5–6k/16k | `tool_search` deferring MCP | `tools.tool_search.enabled: off` + restart |
| HTTP 400 `reasoning_effort` | `none` sent to vLLM | set `low` / `medium` / `high` |
| Predictor Pending / GPU busy | old pod not releasing GPU | force-delete predictor pod |
| Hermes CrashLoop IndentationError | broken `start.sh` heredoc | re-apply `hermes/deploy.yaml` |
| Free-form patch lies / no file change | 7B weak at apply_patch | retry with Coder-7B or note POV 27B for free-form patch |
| Quay `aicatalyst/hermes-agent` pull fail | private image | use `nousresearch/hermes-agent:v0.23.3` |
| Model download fails on HF redirects | EgressFirewall too early / CDN hosts | Delete `EgressFirewall/default`, finish Job + stub, then re-apply `lab/networkpolicy.yaml` |

---

## 11. What this prep intentionally skips

- Live Fortify / Sonatype MCP (the scanner partner)
- ROSA on customer AWS
- Larger-context / 27B model
- Production auth hardening beyond Hermes basic auth
- Full OWASP Benchmark scorecard run

---

## Related files

| Path | Role |
|---|---|
| `lab/phase2-*.yaml` | Model PVC, InferenceService, Route |
| `lab/stub-findings-mcp/` | Stub scanner |
| `lab/hermes/deploy.yaml` | Hermes + bootstrap config |
| `lab/phase3-golden-findings.json` | TC-04/05 catalog |
| `docs/customer/demo-script.md` | Customer walkthrough + screenshots |


## Manual stub checks (no public Route)

```bash
oc port-forward -n remediation-pov svc/stub-findings-mcp 8080:80
curl -s localhost:8080/health
```

## Terminal toolset

Hermes keeps `file` + `terminal` for this lab so the agent can edit and `git` locally.
The POV restricts tools through an MCP gateway — do not imply that control plane exists here.
