#!/usr/bin/env python3
"""Stdio MCP bridge → stub-findings-mcp REST.

Agent tools only — no ground-truth / answer-key access.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

BASE = os.environ.get(
    "STUB_FINDINGS_URL",
    "http://stub-findings-mcp.remediation-pov.svc.cluster.local",
).rstrip("/")
SESSION_ID = os.environ.get("RHDP_SESSION_ID") or str(uuid.uuid4())
SESSION_FILE = Path(os.environ.get("RHDP_SESSION_FILE", "/tmp/rhdp-session-id"))


def current_session() -> str:
    """Read the id on every call so a long-lived bridge follows the runner."""
    try:
        value = SESSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    return value or SESSION_ID
WORKSPACE = Path(
    os.environ.get("WORKSPACE_ROOT", "/opt/data/workspace/BenchmarkJava")
)


def http_json(method: str, path: str, body: dict | None = None, base: str = BASE, internal: bool = False) -> dict:
    data = None if body is None else json.dumps(body).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Session-Id": current_session(),
    }
    if internal:
        headers["X-Internal"] = "true"
    req = urllib.request.Request(
        f"{base}{path}",
        data=data,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode() if e.fp else str(e)
        raise RuntimeError(f"{method} {path} failed: {e.code} {detail}") from e


TOOLS = [
    {
        "name": "list_findings",
        "description": "List Fortify-shaped vulnerability findings from the stub scanner",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_finding",
        "description": "Get one finding by id",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "request_rescan",
        "description": "Stub rescan: re-read the target file and re-run the stub rule",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "scope": {"type": "string"},
            },
        },
    },
    {
        "name": "run_build",
        "description": "Compile workspace with mvn -q -DskipTests compile via build-runner",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_recipe",
        "description": (
            "Run OpenRewrite UpgradeDependencyVersion only "
            "(dry_run true|false) via build-runner"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "group_id": {"type": "string"},
                "artifact_id": {"type": "string"},
                "new_version": {"type": "string"},
                "dry_run": {"type": "boolean"},
            },
            "required": ["group_id", "artifact_id", "new_version", "dry_run"],
        },
    },
    {
        "name": "record_decision",
        "description": "Record a decision (TP, FP, or NEEDS_DEVELOPER) and the reason",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "decision": {"type": "string"},
                "reason": {"type": "string"},
                "changed_files": {"type": "array", "items": {"type": "string"}},
                "build_ok": {"type": "boolean"},
            },
            "required": ["finding_id", "decision", "reason"],
        },
    },
]


def call_tool(name: str, arguments: dict) -> dict:
    if name == "list_findings":
        return http_json("GET", "/findings")
    if name == "get_finding":
        return http_json("GET", f"/findings/{arguments['id']}")
    if name == "request_rescan":
        body = dict(arguments or {})
        fid = body.get("id")
        if fid:
            finding = http_json("GET", f"/findings/{fid}", internal=True)
            rel = finding.get("file")
            if rel:
                path = WORKSPACE / rel
                if path.exists():
                    body["file_content"] = path.read_text(errors="replace")
        return http_json("POST", "/rescan", body)
    if name == "run_build":
        return http_json("POST", "/build", arguments or {})
    if name == "run_recipe":
        return http_json("POST", "/recipe", arguments or {})
    if name == "record_decision":
        return http_json("POST", "/decisions", arguments or {})
    raise ValueError(f"unknown tool: {name}")


def respond(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        if method == "initialize":
            respond(
                msg_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "stub-fortify", "version": "0.2.0"},
                },
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            respond(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                result = call_tool(name, args)
                respond(
                    msg_id,
                    {
                        "content": [
                            {"type": "text", "text": json.dumps(result, indent=2)}
                        ]
                    },
                )
            except Exception as e:  # noqa: BLE001
                respond(
                    msg_id,
                    {
                        "content": [{"type": "text", "text": f"error: {e}"}],
                        "isError": True,
                    },
                )
        elif method == "ping":
            respond(msg_id, {})
        else:
            if msg_id is not None:
                respond(
                    msg_id,
                    error={"code": -32601, "message": f"Method not found: {method}"},
                )


if __name__ == "__main__":
    main()
