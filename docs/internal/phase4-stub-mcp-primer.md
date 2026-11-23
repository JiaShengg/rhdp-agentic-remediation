# Phase 4 - Stub findings MCP

A small FastAPI service that **pretends to be Fortify** for the lab. The agent calls the same tool names later when a real scanner MCP arrives.

## Tools (agent-facing)

| Tool | HTTP | Notes |
|---|---|---|
| `list_findings` | `GET /findings` | ~20 BenchmarkJava cases |
| `get_finding` | `GET /findings/{id}` | No answer-key fields |
| `request_rescan` | `POST /rescan` | Stub rule re-check; `still_present` + `stub: true` |
| `run_build` | `POST /build` | Proxies to Hermes build-runner sidecar |
| `record_decision` | `POST /decisions` | JSONL for offline `scripts/score.py` |

Manual check (no public Route):

```bash
oc port-forward -n remediation-pov svc/stub-findings-mcp 8080:80
curl -s localhost:8080/health
curl -s localhost:8080/findings | jq '.count'
```

## Cutover

Keep tool names stable. Point config at the scanner partner MCP endpoints and drop the stub.
