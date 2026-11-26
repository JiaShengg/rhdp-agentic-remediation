#!/usr/bin/env python3
"""HTTP Model Context Protocol server bound to the developer workspace.

Tools: read_file, apply_patch, git_diff, run_build, run_tests, rescan.
Every call appends one JSON line to the audit file. Paths stay inside
the workspace root.

A diff that touches a file with no finding is rejected by design.
The server restores the previous bytes and returns status rejected.

If WORKSPACE_MCP_TOKEN is set, every request except /health must send
Authorization: Bearer and that token. If the variable is unset, requests
are accepted as before. The lab manifests do not set the variable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace/BenchmarkJava")).resolve()
AUDIT = Path(os.environ.get("WORKSPACE_AUDIT", "/audit/workspace-audit.jsonl"))
PORT = int(os.environ.get("WORKSPACE_MCP_PORT", "8090"))
STUB = os.environ.get(
    "STUB_FINDINGS_URL",
    "http://stub-findings-mcp.remediation-pov.svc.cluster.local",
).rstrip("/")
PROTOCOL = "2025-03-26"
_MUTATION = threading.Lock()
_FORBIDDEN_DIFF = (
    "rename from",
    "rename to",
    "copy from",
    "copy to",
    "new mode",
    "old mode",
    "GIT binary patch",
)

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file inside the developer workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "apply_patch",
        "description": (
            "Apply a unified diff inside the developer workspace. "
            "The server then compiles and rescans every finding whose file the diff changed. "
            "status is applied only when the compile exits 0 and every rescan reports "
            "still_present false. Otherwise the server restores the previous file bytes "
            "and returns status rejected with the failed check names."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"unified_diff": {"type": "string"}},
            "required": ["unified_diff"],
        },
    },
    {
        "name": "git_diff",
        "description": "Show git diff for the developer workspace.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_build",
        "description": "Compile the developer workspace with mvn -q -DskipTests compile.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "rescan",
        "description": (
            "Re-check one finding. Reads its file in this workspace and "
            "sends that content to the findings service."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        },
    },
    {
        "name": "run_tests",
        "description": "Run one JUnit test class in the developer workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"test_class": {"type": "string"}},
            "required": ["test_class"],
        },
    },
]


def _audit(
    tool: str,
    ok: bool,
    detail: str,
    finding_ids: list[str] | None = None,
    diff: str | None = None,
    session: str | None = None,
) -> None:
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "tool": tool,
        "ok": ok,
        "finding_ids": list(finding_ids or []),
        "session": Handler.session if session is None else session,
        "detail": detail[:2000],
    }
    if diff is not None:
        record["diff_sha256"] = hashlib.sha256(diff.encode()).hexdigest()
    with AUDIT.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _authorized(header: str) -> bool:
    token = os.environ.get("WORKSPACE_MCP_TOKEN", "")
    if not token:
        return True
    expected = f"Bearer {token}".encode()
    got = (header or "").encode()
    if len(got) != len(expected):
        return False
    return hmac.compare_digest(got, expected)


def _reject_diff_headers(unified_diff: str) -> None:
    for line in unified_diff.splitlines():
        for token in _FORBIDDEN_DIFF:
            if token in line:
                raise ValueError(f"diff contains a forbidden header: {token}")
        if re.search(r"\bmode\s+120000\b", line):
            raise ValueError("diff contains a forbidden header: mode 120000")


def _finding_ids_from_result(name: str, arguments: dict, text: str) -> list[str]:
    if name == "rescan":
        finding_id = (arguments or {}).get("finding_id")
        return [finding_id] if isinstance(finding_id, str) and finding_id else []
    if name != "apply_patch":
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    found: list[str] = []
    for item in payload.get("rescan") or []:
        if not isinstance(item, dict):
            continue
        finding_id = item.get("finding_id") or item.get("id")
        if isinstance(finding_id, str) and finding_id and finding_id not in found:
            found.append(finding_id)
    return found


def _resolve(path: str) -> Path:
    if not isinstance(path, str) or path == "":
        raise ValueError("path required")
    if path.startswith("/") or path.startswith("~"):
        raise ValueError("absolute paths are rejected")
    parts = Path(path).parts
    if ".." in parts:
        raise ValueError("parent segments are rejected")
    full = (ROOT / path).resolve()
    if full != ROOT and ROOT not in full.parents:
        raise ValueError("path escapes the workspace")
    return full


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "safe.directory"
    env["GIT_CONFIG_VALUE_0"] = str(ROOT)
    return env


def read_file(path: str) -> str:
    full = _resolve(path)
    if not full.is_file():
        raise FileNotFoundError(path)
    return full.read_text(errors="replace")


def _normalize_diff(unified_diff: str) -> str:
    """Blank context lines must keep a leading space or git apply rejects the hunk."""
    out: list[str] = []
    in_hunk = False
    for line in unified_diff.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            out.append(line)
            continue
        if line.startswith("diff --git") or line.startswith("--- ") or line.startswith("+++ "):
            in_hunk = False
            out.append(line)
            continue
        if in_hunk and line == "":
            out.append(" ")
            continue
        out.append(line)
    text = "\n".join(out)
    if not text.endswith("\n"):
        text += "\n"
    return text


def _snapshot(paths: list[str]) -> dict[str, bytes | None]:
    snaps: dict[str, bytes | None] = {}
    for rel in paths:
        path = _resolve(rel)
        snaps[rel] = path.read_bytes() if path.is_file() else None
    return snaps


def _restore(snaps: dict[str, bytes | None]) -> None:
    for rel, data in snaps.items():
        path = _resolve(rel)
        if data is None:
            if path.is_file():
                path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _matches(snaps: dict[str, bytes | None]) -> bool:
    for rel, data in snaps.items():
        path = _resolve(rel)
        if data is None:
            if path.exists():
                return False
            continue
        if not path.is_file() or path.read_bytes() != data:
            return False
    return True


def _brief_build(build: dict) -> dict:
    return {"ok": bool(build.get("ok")), "output": str(build.get("output") or "")[-800:]}


def _failed_checks(build: dict, rescans: list) -> list[str]:
    failed: list[str] = []
    if not build.get("ok"):
        failed.append("compile")
    if not rescans:
        failed.append("rescan")
    for item in rescans:
        if not isinstance(item, dict):
            failed.append("rescan")
            continue
        if item.get("still_present") is False and not item.get("error"):
            continue
        checks = item.get("checks")
        names = []
        if isinstance(checks, dict):
            names = [name for name, value in checks.items() if value is False]
        if names:
            failed.extend(names)
            continue
        failed.append("rescan")
    unique: list[str] = []
    for name in failed:
        if name not in unique:
            unique.append(name)
    return unique


def apply_patch(unified_diff: str) -> str:
    if not isinstance(unified_diff, str) or "--- " not in unified_diff or "+++ " not in unified_diff:
        raise ValueError("unified_diff required")
    _reject_diff_headers(unified_diff)
    with _MUTATION:
        return _apply_patch_locked(unified_diff)


def _apply_patch_locked(unified_diff: str) -> str:
    unified_diff = _normalize_diff(unified_diff)
    paths: list[str] = []
    for line in unified_diff.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            name = line[4:].split("\t", 1)[0].strip()
            if name in ("/dev/null",):
                continue
            name = name.removeprefix("a/").removeprefix("b/")
            _resolve(name)
            if name not in paths:
                paths.append(name)
    snaps = _snapshot(paths)
    proc = subprocess.run(
        ["git", "apply", "--recount", "--whitespace=nowarn", "-"],
        input=unified_diff,
        text=True,
        cwd=str(ROOT),
        capture_output=True,
        timeout=60,
        env=_git_env(),
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise RuntimeError(out[-4000:] or f"patch exit {proc.returncode}")
    try:
        build = _compile_result()
        _audit("run_build", bool(build.get("ok")), str(build.get("output") or "")[:500])
        rescans = _rescan_changed(unified_diff)
        failed = _failed_checks(build, rescans)
        if failed:
            _restore(snaps)
            payload = {
                "status": "rejected",
                "restored": _matches(snaps),
                "failed_checks": failed,
                "build": _brief_build(build),
                "rescan": rescans,
            }
        else:
            payload = {
                "status": "applied",
                "patch": (out[-2000:] or "applied"),
                "build": _brief_build(build),
                "rescan": rescans,
            }
        return json.dumps(payload)
    except Exception:
        _restore(snaps)
        raise


def _stub_json(method: str, path: str, body: dict | None = None, timeout: int = 60) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"{STUB}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode() if exc.fp else str(exc)
        raise RuntimeError(f"{method} {path} failed: {exc.code} {detail[:500]}") from exc


def _diff_paths(unified_diff: str) -> list[str]:
    paths: list[str] = []
    for line in unified_diff.splitlines():
        if not (line.startswith("+++ ") or line.startswith("--- ")):
            continue
        name = line[4:].split("\t", 1)[0].strip()
        if name == "/dev/null":
            continue
        name = name.removeprefix("a/").removeprefix("b/")
        if name and name not in paths:
            paths.append(name)
    return paths


def _compile_result() -> dict:
    try:
        return {"ok": True, "output": _run_build_unlocked()}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "output": str(exc)[-4000:]}


def rescan_finding(finding_id: str) -> dict:
    if not isinstance(finding_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", finding_id):
        raise ValueError("finding_id required")
    finding = _stub_json("GET", f"/findings/{finding_id}")
    rel = finding.get("file") or ""
    source = read_file(rel)
    result = _stub_json(
        "POST",
        "/rescan",
        {"id": finding_id, "file_content": source},
        timeout=60,
    )
    _audit(
        "rescan",
        result.get("still_present") is False,
        json.dumps(
            {
                "finding_id": finding_id,
                "still_present": result.get("still_present"),
                "status": result.get("status"),
            }
        ),
        finding_ids=[finding_id],
    )
    return result


def _rescan_changed(unified_diff: str) -> list:
    paths = set(_diff_paths(unified_diff))
    try:
        catalog = _stub_json("GET", "/findings", timeout=30)
    except Exception as exc:  # noqa: BLE001
        return [{"ok": False, "error": str(exc)}]
    findings = catalog.get("findings") or []
    matched = [
        item.get("id")
        for item in findings
        if item.get("id") and item.get("file") in paths
    ]
    if not matched:
        return [{"ok": False, "error": "no finding for the changed paths", "paths": sorted(paths)}]
    results = []
    for finding_id in matched:
        try:
            result = rescan_finding(finding_id)
            if isinstance(result, dict):
                result.setdefault("finding_id", finding_id)
            results.append(result)
        except Exception as exc:  # noqa: BLE001
            err = {"finding_id": finding_id, "ok": False, "error": str(exc)}
            _audit("rescan", False, json.dumps(err), finding_ids=[finding_id])
            results.append(err)
    return results


def git_diff() -> str:
    proc = subprocess.run(
        ["git", "diff", "HEAD"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        timeout=60,
        env=_git_env(),
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "git diff failed")[-4000:])
    return proc.stdout[-16000:]


def _run_build_unlocked() -> str:
    mvn = os.environ.get("MVN", "mvn")
    proc = subprocess.run(
        [mvn, "-q", "-DskipTests", "compile"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        timeout=600,
    )
    tail = ((proc.stdout or "") + (proc.stderr or ""))[-4000:]
    if proc.returncode != 0:
        raise RuntimeError(tail or f"mvn exit {proc.returncode}")
    return tail or f"mvn exit {proc.returncode}"


def run_build() -> str:
    with _MUTATION:
        return _run_build_unlocked()


def _run_tests_unlocked(test_class: str) -> str:
    mvn = os.environ.get("MVN", "mvn")
    proc = subprocess.run(
        [mvn, "-q", f"-Dtest={test_class}", "test"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        timeout=600,
    )
    tail = ((proc.stdout or "") + (proc.stderr or ""))[-4000:]
    if proc.returncode != 0:
        raise RuntimeError(tail or f"mvn exit {proc.returncode}")
    return tail or f"mvn exit {proc.returncode}"


def run_tests(test_class: str) -> str:
    if not isinstance(test_class, str) or not re.fullmatch(r"[A-Za-z0-9_.]+", test_class):
        raise ValueError("test_class must be a Java class name")
    with _MUTATION:
        return _run_tests_unlocked(test_class)


def _call(name: str, arguments: dict) -> str:
    arguments = arguments or {}
    if name == "read_file":
        return read_file(arguments.get("path", ""))
    if name == "apply_patch":
        return apply_patch(arguments.get("unified_diff", ""))
    if name == "git_diff":
        return git_diff()
    if name == "run_build":
        return run_build()
    if name == "rescan":
        return json.dumps(rescan_finding(arguments.get("finding_id", "")))
    if name == "run_tests":
        return run_tests(arguments.get("test_class", ""))
    raise ValueError(f"unknown tool {name}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    session = ""

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if Handler.session:
            self.send_header("Mcp-Session-Id", Handler.session)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _rpc_result(self, msg_id, result=None, error=None) -> None:
        payload: dict = {"jsonrpc": "2.0", "id": msg_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        raw = json.dumps(payload).encode()
        accept = self.headers.get("Accept", "")
        if "text/event-stream" in accept and "application/json" not in accept:
            data = b"event: message\ndata: " + raw + b"\n\n"
            self._send(200, data, "text/event-stream")
            return
        self._send(200, raw, "application/json")

    def _require_auth(self) -> bool:
        if _authorized(self.headers.get("Authorization", "")):
            return True
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        self._send(401, b"unauthorized\n", "text/plain")
        return False

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] not in ("/mcp", "/"):
            self._send(404, b"not found", "text/plain")
            return
        if not self._require_auth():
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            msg = json.loads(self.rfile.read(length).decode() or "{}")
        except json.JSONDecodeError:
            self._send(400, b"bad json", "text/plain")
            return
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}
        if method == "initialize":
            Handler.session = uuid.uuid4().hex
            offered = (params.get("protocolVersion") or PROTOCOL)
            version = offered if offered else PROTOCOL
            self._rpc_result(
                msg_id,
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "workspace-mcp", "version": "0.1.0"},
                },
            )
            return
        if method == "notifications/initialized":
            self._send(202, b"", "application/json")
            return
        if method == "ping":
            self._rpc_result(msg_id, {})
            return
        if method == "tools/list":
            self._rpc_result(msg_id, {"tools": TOOLS})
            return
        if method == "tools/call":
            name = params.get("name") or ""
            arguments = params.get("arguments") or {}
            diff = arguments.get("unified_diff") if name == "apply_patch" else None
            if not isinstance(diff, str):
                diff = None
            try:
                text = _call(name, arguments)
                _audit(
                    name,
                    True,
                    text,
                    finding_ids=_finding_ids_from_result(name, arguments, text),
                    diff=diff,
                )
                self._rpc_result(
                    msg_id,
                    {"content": [{"type": "text", "text": text}], "isError": False},
                )
            except Exception as exc:  # noqa: BLE001
                _audit(
                    name or "unknown",
                    False,
                    str(exc),
                    finding_ids=_finding_ids_from_result(name, arguments, ""),
                    diff=diff,
                )
                self._rpc_result(
                    msg_id,
                    {"content": [{"type": "text", "text": str(exc)}], "isError": True},
                )
            return
        if msg_id is None:
            self._send(202, b"", "application/json")
            return
        self._rpc_result(msg_id, error={"code": -32601, "message": f"Method not found: {method}"})

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == "/health":
            self._send(200, b"ok\n", "text/plain")
            return
        if not self._require_auth():
            return
        self._send(405, b"post only", "text/plain")

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._require_auth():
            return
        self._send(200, b"", "application/json")


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"workspace-mcp listening on {PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
