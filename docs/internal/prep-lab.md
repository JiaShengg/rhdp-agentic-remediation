# RHDP remediation lab - Platform + LLM + BenchmarkJava

Internal prep lab: agentic remediation dry-run on RHDP OpenShift + Red Hat OpenShift AI while real scanner MCP servers are unavailable. This lab uses a **stub** Fortify-shaped findings service. The model is Qwen3.6-27B FP8 on one L40S at 128K, the same model as the POV. The L4 Qwen2.5 path is still in the repo.

## What is real vs stubbed

| Piece | In this lab |
|---|---|
| Cluster | RHDP OpenShift + RHOAI (ephemeral) |
| Model | Qwen3.6-27B FP8 on one L40S, 128K (same as the POV). Qwen2.5-7B on the L4 remains in the repo. |
| Scanner | Stub MCP over BenchmarkJava cases (POV uses partner Fortify/Sonatype MCP) |
| Agent harness | Hermes for prep only (customer materials leave harness TBC) |
| Access control | Basic auth + NetworkPolicy + EgressFirewall only (POV adds Keycloak, Authorino, MCP gateway, scoped Git) |

## Catalog order (fill from RHDP service page)

| Field | Value |
|---|---|
| Item | **RHOAI on OCP on AWS with NVIDIA GPUs** |
| Activity | Practice / Enablement |
| Purpose | Internal remediation lab rehearsal |
| Region | us-east-2 |
| GPU node | **g6.4xlarge** (1x NVIDIA L4 24GB) |
| Features | OPEN Environment ON |
| Auto-stop / auto-destroy | Copy from RHDP service page |
| GUID / API / console | Copy from RHDP service page - **never commit** |
| Credentials | Copy from RHDP service Details - **never commit** |
| Model (Phase 2) | **Qwen2.5-7B-Instruct** via vLLM on L4 |
| OpenAI base (in-cluster) | `http://qwen25-7b-openai.remediation-pov.svc.cluster.local/v1` |
| Served model name | `qwen25-7b` |
| Stub findings (in-cluster) | `http://stub-findings-mcp.remediation-pov.svc.cluster.local` |
| Hermes UI | Route created by `lab/hermes/deploy.yaml` (hostname from `oc get route`) |

No customer data on this cluster.

## Agent harness (prep)

Customer materials leave the harness as TBC. This lab uses **Hermes Agent (NousResearch)** for prep only.

| Need | Hermes fit |
|---|---|
| OpenAI-compatible model endpoint | Talks to RHOAI vLLM via `OPENAI_BASE_URL` |
| MCP tools (scanner later) | stdio bridge to stub; swap URL for real scanner MCP |
| File / terminal tools | Local toolsets for read/patch/git |

**Reference deployments**

| Path | Repo | Use when |
|---|---|---|
| Hermes on RHOAI + vLLM | https://github.com/aicatalyst-team/hermes-openshift | Closest to RHOAI serving |
| Upstream | https://github.com/NousResearch/Hermes-Agent | Skills / config reference |

**Prep default:** Hermes on RHOAI pointed at the L4 vLLM service. Stub findings MCP plugs in the same way a real scanner MCP will.

## What this proves vs full POV

| POV outcome | This prep |
|---|---|
| RHOAI + LLM | Yes (7B on L4; POV uses larger Qwen3.6-27B) |
| Agent harness | Hermes for prep (customer materials: TBC) |
| Agent remediates Java/Maven | Yes (Hermes skills + build-runner) |
| OWASP BenchmarkJava FP scoring | Yes (offline `scripts/score.py`, not as agent input) |
| Dev Spaces developer path | Optional |
| Team-lead PR batches | Optional |
| Fortify + Sonatype MCP + rescan | Stub only - swap later |

## Model on L4 24GB

The POV names Qwen3.6-27B at 128K. Full BF16 27B needs ~65GB. On this catalog GPU:

```text
Lab default:   Qwen2.5-7B-Instruct (~16K context)
Lab option:    Qwen2.5-Coder-7B-Instruct (better patches; still not POV size)
POV target:    Qwen3.6-27B, 128K on L40S/A100-class
```

Serve with vLLM on RHOAI. Cap `--max-model-len` (16384) so KV cache fits the L4.

## Phase plan (1-2 days once Running)

### Day 0 - platform smoke

1. From RHDP service page: copy console URL, admin password, API URL (do not commit)
2. `oc login` as admin
3. Confirm GPU and RHOAI ready
4. Create Hermes Secret from `lab/hermes/secret.example.yaml`
5. Deploy model; curl `/v1/models` and a short completion

### Day 1 - BenchmarkJava + stub findings MCP

1. Clone OWASP BenchmarkJava into a GitHub fork under your account
2. Deploy stub-findings MCP that returns Fortify-shaped JSON (no answer-key fields in the agent payload)
3. Deploy Hermes against the in-cluster vLLM endpoint
4. Register MCP tools: `list_findings`, `get_finding`, `request_rescan`, `run_build`, `record_decision`
5. Success metrics: agent triages FP from code alone; agent remediates TP; build + stub rescan; offline score

## Stub -> real scanner cutover (later)

Keep MCP tool names stable. When Fortify/Sonatype MCP arrive from the scanner partner:

1. Point agent config at the real MCP endpoints
2. Drop stub server
3. Wire rescan API if available

## Out of scope for this prep

- Customer production code / scanners
- ROSA on a customer AWS account
- Kata / SPIFFE / EvalHub
- Full BF16 Qwen 27B on L4
- OpenShell, MLflow, SIEM integration, Red Hat COE hardware options

## When cluster is Running - first commands

```bash
# after copying login from RHDP service page
oc whoami
oc get nodes -L node.kubernetes.io/instance-type
oc get csv -A | grep -iE 'rhods|opendatahub|gpu'
```

Then create the Hermes Secret and deploy the model and lab manifests under `lab/`.
