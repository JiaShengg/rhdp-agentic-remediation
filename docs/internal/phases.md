# RHDP remediation lab - Phased Build + Teach Plan

Goal: end-to-end agentic remediation demo on an RHDP cluster, using open-source BenchmarkJava + Hermes (prep harness), with a stub scanner MCP until real scanner MCP servers arrive.

```text
You (operator)         Cluster (<GUID>)
     |                      |
     |  oc / Hermes UI      |
     +-----> model (vLLM) --+
     |                      |
     +-----> stub MCP ------+-----> BenchmarkJava workspace
     |                      |
     +-----> build-runner --+
```

## What is real vs stubbed

- **Real:** OpenShift, RHOAI, vLLM, Hermes, BenchmarkJava source, Maven compile via build-runner
- **Stub:** Fortify-shaped findings, rescan rule, no Keycloak/Authorino/MCP gateway
- **Not in lab:** OpenShell, MLflow, EvalHub, Kata, SIEM, COE hardware SKUs

## Phase checklist

### Phase 0 - lock plan + extend auto-stop
- Extend RHDP auto-stop (cluster dies if skipped)
- Confirm auto-destroy separately

### Phase 1 - platform smoke
- `oc login`, whoami, nodes, GPU, RHOAI dashboard
- Teach: RHDP vs long-lived cluster

### Phase 2 - model on L4
- PVC + download Job + InferenceService (Qwen2.5-7B, 16K)
- Optional Coder variant for stronger patches
- Teach: the L4 path is the smaller model. The current serve path is Qwen3.6-27B FP8 at 128K on one L40S.

### Phase 3 - BenchmarkJava
- Upstream: https://github.com/OWASP-Benchmark/BenchmarkJava
- Clone: `~/BenchmarkJava` or `<LOCAL_CLONE>`
- Golden catalog ~20 cases (TP/FP mix); answer key stays offline for scoring only

### Phase 4 - stub findings MCP
- Deploy stub; tools: `list_findings`, `get_finding`, `request_rescan`, `run_build`, `record_decision`
- No ground-truth tool for the agent

### Phase 5 - Hermes
- Secret from `lab/hermes/secret.example.yaml`
- Deploy Hermes; wire stub-fortify only (no catalog MCP installs; NetworkPolicy egress)
- In-cluster vLLM only (MoA off; auxiliary = main)

### Phase 6 - dry-run
- FP triage from code alone → `record_decision`
- TP remediate on branch `fix/<id>` → `run_build` → `request_rescan`
- Offline `scripts/score.py` against local `expectedresults-1.2.csv`
