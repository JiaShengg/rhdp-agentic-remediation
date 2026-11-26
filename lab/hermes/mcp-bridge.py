#!/usr/bin/env python3
"""Stdio Model Context Protocol bridge to the stub findings service.

Agent tools only. No ground-truth or answer-key access.

WORKSPACE_MCP_URL selects the developer workspace server and hides
run_build, run_recipe, and request_rescan. REMOTE_EDIT_SSH_HOST selects
an SSH read of the same workspace. With neither variable set, request_rescan
reads a local file when that file exists.
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


def _mcp_post(url: str, payload: dict | None, session: str, timeout: int = 30) -> tuple[int, str, str]:
    data = None if payload is None else json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            sid = resp.headers.get("Mcp-Session-Id", session)
            return resp.status, sid, resp.read().decode()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode() if exc.fp else str(exc)
        raise RuntimeError(f"workspace mcp {exc.code} {detail}") from exc


def read_via_workspace_mcp(rel: str) -> str:
    """Read through the workspace server so the rescan sees the developer pod."""
    url = os.environ["WORKSPACE_MCP_URL"].rstrip("/")
    _, session, _raw = _mcp_post(
        url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "stub-bridge", "version": "0.1"},
            },
        },
        "",
    )
    _mcp_post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    _, _, raw = _mcp_post(
        url,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": rel}},
        },
        session,
    )
    msg = json.loads(raw)
    if msg.get("error"):
        raise RuntimeError(msg["error"])
    result = msg.get("result") or {}
    if result.get("isError"):
        text = ""
        for block in result.get("content") or []:
            text += block.get("text") or ""
        raise RuntimeError(text or "workspace read failed")
    parts = []
    for block in result.get("content") or []:
        parts.append(block.get("text") or "")
    return "".join(parts)


def read_workspace_file(rel: str) -> str:
    """Read a workspace file over SSH or through the workspace server."""
    if rel.startswith("/") or ".." in Path(rel).parts:
        raise ValueError("refusing workspace path")
    if os.environ.get("WORKSPACE_MCP_URL"):
        return read_via_workspace_mcp(rel)
    host = os.environ.get("REMOTE_EDIT_SSH_HOST", "")
    if not host:
        path = WORKSPACE / rel
        return path.read_text(errors="replace") if path.exists() else ""
    import shlex
    import subprocess

    remote = "/workspace/BenchmarkJava/" + rel
    cmd = [
        "ssh",
        "-i",
        os.environ.get("REMOTE_EDIT_SSH_KEY", "/etc/remote-edit/id_ed25519"),
        "-p",
        os.environ.get("REMOTE_EDIT_SSH_PORT", "2222"),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{os.environ.get('REMOTE_EDIT_SSH_USER', 'default')}@{host}",
        f"cat {shlex.quote(remote)}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "remote read failed")
    return proc.stdout


def active_tools() -> list:
    """Hide the build-runner tools when the workspace server owns compile and rescan."""
    if os.environ.get("WORKSPACE_MCP_URL"):
        hidden = ("run_build", "run_recipe", "request_rescan")
        return [tool for tool in TOOLS if tool["name"] not in hidden]
    return TOOLS


def call_tool(name: str, arguments: dict) -> dict:
    if name == "list_findings":
        return http_json("GET", "/findings")
    if name == "get_finding":
        return http_json("GET", f"/findings/{arguments['id']}")
    if name in ("run_build", "run_recipe", "request_rescan") and os.environ.get("WORKSPACE_MCP_URL"):
        raise ValueError("that tool is not on this path")
    if name == "request_rescan":
        body = dict(arguments or {})
        fid = body.get("id")
        if fid:
            finding = http_json("GET", f"/findings/{fid}", internal=True)
            rel = finding.get("file")
            if rel and (os.environ.get("WORKSPACE_MCP_URL") or os.environ.get("REMOTE_EDIT_SSH_HOST")):
                body["file_content"] = read_workspace_file(rel)
            elif rel:
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
            respond(msg_id, {"tools": active_tools()})
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
