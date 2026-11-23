# Phase 5 - Hermes (prep harness)

| Item | Value |
|---|---|
| Secret | Create from `lab/hermes/secret.example.yaml` — do not commit passwords |
| Password | set in Secret; do not commit |
| Model | In-cluster vLLM only (MoA disabled; auxiliary = main) |
| MCP | `stub-fortify` only — do not install dashboard catalog servers |

MCP tools available to the agent: `list_findings`, `get_finding`, `request_rescan`, `run_build`, `record_decision`.

Notes:
- **MCP bridge** = stdio adapter so Hermes can call the REST stub with standard MCP tool names.
- **build-runner** = OpenJDK sidecar on the Hermes pod; compiles the shared workspace.
- Lab agent has `terminal` + `file` toolsets. The POV restricts tools through an MCP gateway — this lab does not.
