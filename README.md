# RHDP agentic remediation lab

Public lab materials for an RHDP OpenShift + Red Hat OpenShift AI dry-run: vLLM model serving, stub Fortify-shaped findings MCP, build-runner compile, and an agent walkthrough on OWASP BenchmarkJava.

## Layout

| Path | Purpose |
|---|---|
| `lab/` | Manifests (model, stub MCP, Hermes prep harness, NetworkPolicy + EgressFirewall, build-runner) |
| `docs/internal/` | Operator runbook, phases, primers |
| `docs/customer/` | Customer-facing demo script (no hostnames, logins, or harness product names) |
| `scripts/scan-secrets.sh` | Fail CI/local checks on leaked identifiers |
| `scripts/score.py` | Offline score of agent decisions vs Benchmark CSV |

## Secrets

Copy OpenShift credentials from your RHDP service page. Create Hermes dashboard auth from `lab/hermes/secret.example.yaml` — **never commit live passwords**.

```bash
./scripts/scan-secrets.sh
```

## Lab vs POV

| Component | In this lab | In the POV |
|---|---|---|
| Model | Qwen3.6-27B FP8 on one L40S, 128K, same as the POV | Qwen3.6-27B FP8, 128K context, L40S or A100-class |
| Scanner | Stub MCP with ~20 BenchmarkJava cases | Fortify and Sonatype via scanner partner MCP servers |
| Rescan | Stub pattern check (`still_present`, `checks`, `stub: true`). SQL fixes must keep the input, use a placeholder, and bind it. | Real Fortify rescan plus human review |
| Tracing | JSON Lines audit log of every tool call, on a volume the agent cannot read | POV tracing of the agent run |
| Triage | Two independent sessions. Agreement is recorded. A disagreement is handed to a developer | Human review of disagreements |
| Build | In-cluster build-runner (`mvn -q -DskipTests compile`) | Maven build and available tests |
| Hand over | Branch + `git diff` (optional Gitea PR) | Git platform PR; agent never merges |
| Access control | Basic auth + NetworkPolicy + EgressFirewall | Keycloak, Authorino, MCP gateway, scoped Git permissions |
| Workflows | Chat on single findings | Developer in Dev Spaces and team-lead repository runs |
| Library upgrade | OpenRewrite `UpgradeDependencyVersion` via `run_recipe`, one dependency | Sonatype findings across the repository |
| Agent harness | Hermes used for prep only | To be confirmed in customer materials |

## Demo integrity rules

1. The agent never receives the Benchmark answer key (`expectedresults*.csv` stripped from the workspace).
2. Triage is from the code; `scripts/score.py` runs afterwards.
3. The agent writes the fix itself — no pre-written `fix-*.py` helpers.
4. Only in-cluster vLLM is used (no OpenRouter / cloud MoA).
