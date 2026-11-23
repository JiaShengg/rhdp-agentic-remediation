#!/usr/bin/env python3
"""Stub Fortify-shaped findings service for the RHDP remediation lab.

Agent-facing tools (also exposed via MCP bridge):
  - list_findings
  - get_finding
  - request_rescan   (stub rule re-check; returns still_present + stub:true)
  - run_build        (proxied to in-cluster build-runner)
  - run_recipe       (OpenRewrite UpgradeDependencyVersion via build-runner)
  - record_decision  (append JSONL for offline scoring)

Ground truth is NOT an agent tool. Score offline with scripts/score.py
against a local expectedresults-1.2.csv checkout.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

FINDINGS_PATH = Path(os.environ.get("FINDINGS_PATH", "/data/findings.json"))
BASELINES_PATH = Path(os.environ.get("BASELINES_PATH", "/data/baselines.json"))
DECISIONS_PATH = Path(os.environ.get("DECISIONS_PATH", "/data/decisions.jsonl"))
AUDIT_PATH = Path(os.environ.get("AUDIT_PATH", "/audit/audit.jsonl"))
WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace/BenchmarkJava"))
BUILD_RUNNER_URL = os.environ.get(
    "BUILD_RUNNER_URL", "http://hermes-agent.remediation-pov.svc.cluster.local:8081"
).rstrip("/")

app = FastAPI(
    title="stub-findings-mcp",
    description="Fortify-shaped findings stub (BenchmarkJava lab cases)",
    version="0.3.0",
)

_SESSION_ID: ContextVar[str] = ContextVar("rhdp_session_id", default="unknown")
_AUDIT_INTERNAL: ContextVar[bool] = ContextVar("rhdp_audit_internal", default=False)

# Same patterns as scripts/scan-secrets.sh. POSIX classes are written as Python.
_REDACT_PATTERNS = tuple(
    re.compile(part)
    for part in (
        r"opentlc\.com",
        "sandbox" + "[0-9]",
        "/Use" + "rs/",
        r"password\s*[:=]\s*\S+",
        "".join(["BEGIN ", ".*", "PRIVATE", " KEY"]),
        "AKIA" + "[0-9A-Z]{16}",
        "hf_" + "[A-Za-z0-9]{20,}",
    )
)


@app.middleware("http")
async def _bind_audit_context(request, call_next):
    session = _SESSION_ID.set(request.headers.get("x-session-id") or "unknown")
    # A caller may label a lookup as internal. That flag never suppresses the record.
    internal = _AUDIT_INTERNAL.set(request.headers.get("x-internal", "").lower() == "true")
    try:
        return await call_next(request)
    finally:
        _SESSION_ID.reset(session)
        _AUDIT_INTERNAL.reset(internal)


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        for pattern in _REDACT_PATTERNS:
            value = pattern.sub("[redacted]", value)
        return value
    if isinstance(value, dict):
        return {str(key): _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def write_audit(tool: str, arguments: Any, result: Any, finding_id: str = "") -> None:
    """Append one tool call. Not exposed as a tool and not mounted on the agent.

    Every call is written. `internal` marks a bridge lookup that is not an agent
    tool call. Nothing in the request can turn the write off.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": _SESSION_ID.get() or "unknown",
        "finding_id": finding_id or "",
        "tool": tool,
        "internal": bool(_AUDIT_INTERNAL.get()),
        "arguments": _redact(arguments if isinstance(arguments, dict) else {"value": arguments}),
        "result": _redact(result),
    }
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:
        sys.stderr.write(f"audit write failed: {exc.__class__.__name__}\n")
        return


def _audited(tool: str, arguments: dict[str, Any], result: dict[str, Any], finding_id: str = "") -> dict[str, Any]:
    write_audit(tool, arguments, result, finding_id)
    return result


def load_catalog() -> dict[str, Any]:
    if not FINDINGS_PATH.exists():
        raise HTTPException(status_code=500, detail=f"missing catalog: {FINDINGS_PATH}")
    return json.loads(FINDINGS_PATH.read_text())


def public_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Payload the agent may see — no answer-key fields."""
    out = {
        "id": raw["id"],
        "tool": raw.get("tool", "stub-fortify"),
        "cwe": raw.get("cwe"),
        "category": raw.get("category"),
        "severity": raw.get("severity", "high"),
        "file": raw["file"],
        "line": raw.get("line"),
        "message": raw["message"],
        "test_case": raw.get("test_case"),
        "scanner_verdict": "vulnerable",
    }
    # Library / Sonatype-shaped fields (no expected TP/FP labels).
    for key in (
        "component",
        "group_id",
        "artifact_id",
        "version",
        "cve",
        "fixed_version",
        "advisory_url",
    ):
        if key in raw:
            out[key] = raw[key]
    return out


def _parse_pom_dep_version(pom_text: str, group_id: str, artifact_id: str) -> str | None:
    import re
    import xml.etree.ElementTree as ET

    text_ns = re.sub(r'\sxmlns="[^"]+"', "", pom_text, count=1)
    root = ET.fromstring(text_ns)
    for dep in root.findall(".//dependency"):
        g = (dep.findtext("groupId") or "").strip()
        a = (dep.findtext("artifactId") or "").strip()
        if g == group_id and a == artifact_id:
            return (dep.findtext("version") or "").strip() or None
    return None


def _version_tuple(v: str) -> tuple:
    parts = []
    for p in re.split(r"[^0-9]+", v):
        if p.isdigit():
            parts.append(int(p))
    return tuple(parts) or (0,)


def library_still_present(raw: dict[str, Any], pom_text: str) -> bool:
    """True if pom still has component version below fixed_version."""
    gid = raw.get("group_id") or ""
    aid = raw.get("artifact_id") or ""
    fixed = raw.get("fixed_version") or ""
    current = _parse_pom_dep_version(pom_text, gid, aid)
    if current is None:
        return True
    try:
        return _version_tuple(current) < _version_tuple(fixed)
    except Exception:  # noqa: BLE001
        return current != fixed


def _load_baseline(finding_id: str) -> str | None:
    """Scanned method text for a finding. Not an answer-key label."""
    if not BASELINES_PATH.exists():
        return None
    try:
        data = json.loads(BASELINES_PATH.read_text())
    except json.JSONDecodeError:
        return None
    text = data.get(finding_id)
    return text if isinstance(text, str) and text.strip() else None


def find_raw(finding_id: str) -> dict[str, Any]:
    for raw in load_catalog().get("demo_cases", []):
        if raw["id"] == finding_id:
            return raw
    raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")


_SQL_CONCAT = re.compile(
    r"""PASSWORD\s*=\s*['\"]\s*\+\s*param|['\"]\s*\+\s*param\s*\+\s*['\"].*?(?:SELECT|INSERT|UPDATE|DELETE)""",
    re.I | re.S,
)
_XSS_SINK = re.compile(r"getWriter\(\)\.(?:write|print)|innerHTML|response\.getWriter", re.I)
_PATH_SINK = re.compile(r"new\s+File(?:InputStream|Reader|)\s*\(|Paths\.get\s*\(.*param", re.I)
_CMDI_SINK = re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder", re.I)


_SOURCE_CALL = re.compile(
    r"(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|"
    r"getQueryString|getCookies|getPathInfo|getRequestURI|getInputStream|"
    r"getReader|getTheValue|getTheParameter|getTheHeaders)\s*\(",
    re.I,
)
_SQL_KEYWORD = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|CALL)\b|\{call", re.I)
_SETTER = (
    "setString|setNString|setObject|setInt|setLong|setShort|setByte|"
    "setFloat|setDouble|setBoolean|setBigDecimal|setDate|setTime|"
    "setTimestamp|setBytes|setBlob|setClob|setNull|setAsciiStream|"
    "setCharacterStream|setNCharacterStream"
)
_QUOTED_LITERAL = re.compile(r"'[^']+'|\"[^\"]+\"")


def _strip_java_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    source = re.sub(r"//[^\n]*", "", source)
    return source


def _enclosing_method(source: str, line: int | None) -> str:
    """Method that contains the finding line. The whole file if the line is unknown."""
    if not line or line < 1:
        return source
    lines = source.splitlines()
    if line > len(lines):
        return source
    start = None
    for i in range(line - 1, -1, -1):
        if re.search(r"\b[\w<>\[\]]+\s+\w+\s*\([^;]*\)\s*(?:throws[^{]*)?\{", lines[i]):
            start = i
            break
        if "{" in lines[i] and re.search(r"\b(public|protected|private)\b", lines[i]):
            start = i
            break
    if start is None:
        return source
    depth = 0
    seen = False
    end = len(lines)
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            seen = True
        if seen and depth <= 0:
            end = i + 1
            break
    return "\n".join(lines[start:end])


def _java_string_contents(text: str) -> str:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    return " ".join(parts)


_ASSIGNMENT = re.compile(
    r"(?:^|[;{}\n])\s*(?:[\w.\[\]<>,\s]+\s+)?(\w+)\s*=\s*([^;]+)",
)


def _tainted_names(method: str) -> list[str]:
    """Names that carry a request value, including through calls and decoding.

    `headers = request.getHeaders(...)` taints `headers`. A later
    `param = headers.nextElement()` and `param = URLDecoder.decode(param, ...)`
    keep `param` tainted. A constant assignment does not clear an earlier one.
    """
    assignments: list[tuple[str, str]] = []
    for match in _ASSIGNMENT.finditer(method):
        name, expr = match.group(1), match.group(2)
        if name in {"if", "for", "while", "return", "switch"}:
            continue
        assignments.append((name, expr))
    names: list[str] = []
    changed = True
    while changed:
        changed = False
        have = set(names)
        for name, expr in assignments:
            if name in have:
                continue
            mentions = any(re.search(rf"\b{re.escape(item)}\b", expr) for item in have)
            if _SOURCE_CALL.search(expr) or mentions:
                names.append(name)
                changed = True
    return names


def _sql_statements(method: str) -> list[str]:
    statements = []
    for statement in method.split(";"):
        contents = _java_string_contents(statement)
        if _SQL_KEYWORD.search(contents) or _SQL_KEYWORD.search(statement):
            statements.append(statement)
    return statements


def _concatenates(statement: str, name: str) -> bool:
    return re.search(rf"(?:\+\s*{re.escape(name)}\b|\b{re.escape(name)}\s*\+)", statement) is not None


def _is_bound(method: str, name: str) -> bool:
    return (
        re.search(
            rf"\b(?:{_SETTER})\s*\([^;]*\b{re.escape(name)}\b",
            method,
        )
        is not None
    )


def _norm_sql(sql: str) -> str:
    """Collapse whitespace, including the space before a placeholder."""
    sql = re.sub(r"\s+", " ", sql).strip()
    return re.sub(r"\s*([?,()\[\]{}])\s*", r"\1", sql)


def _sql_expr(method: str) -> str | None:
    match = re.search(r"\bString\s+sql\s*=\s*(.*?);", method, re.S)
    if match:
        return match.group(1)
    match = re.search(
        r"\.(?:prepareStatement|prepareCall|executeUpdate|executeQuery)\s*\(\s*"
        r"(\"(?:[^\"\\]|\\.)*\"(?:\s*\+\s*(?:\"(?:[^\"\\]|\\.)*\"|\w+))*)",
        method,
        re.S,
    )
    if match:
        return match.group(1)
    return None


def _concat_parts(expr: str) -> list[tuple[str, str]]:
    return [
        ("lit", match.group(1)) if match.group(1) is not None else ("id", match.group(2))
        for match in re.finditer(r'"((?:[^"\\]|\\.)*)"|(\w+)', expr)
    ]


def _render_sql(expr: str, tainted: set[str], replace: bool) -> str:
    """Join a Java string expression. Tainted slots become ? when replace is set."""
    parts = _concat_parts(expr)
    out: list[str] = []
    strip_next = False
    for kind, value in parts:
        if kind == "id":
            if replace and value in tainted:
                if out and out[-1].endswith("'"):
                    out[-1] = out[-1][:-1]
                out.append("?")
                strip_next = True
            continue
        if strip_next:
            if value.startswith("'"):
                value = value[1:]
            strip_next = False
        out.append(value)
    return "".join(out)


def _statement_kinds(method: str) -> set[str]:
    kinds: set[str] = set()
    if re.search(r"\.prepareCall\s*\(", method):
        kinds.add("callable")
    if re.search(r"\.prepareStatement\s*\(", method):
        kinds.add("prepared")
    if re.search(r"\.createStatement\s*\(|\bgetSqlStatement\s*\(", method):
        kinds.add("statement")
    return kinds


def _call_type_kept(original: str, method: str) -> bool:
    old = _statement_kinds(original)
    new = _statement_kinds(method)
    if "callable" in old:
        return new == {"callable"}
    if "prepared" in old and "callable" not in old:
        return new == {"prepared"}
    # A plain Statement may become a PreparedStatement. Any other change fails.
    if "callable" in new:
        return False
    return bool(new) and new <= {"statement", "prepared"}


_IDENT_PLACEHOLDER = re.compile(
    r"\{\s*call\s+\?"
    r"|\bcall\s+\?"
    r"|\b(?:from|join|update|into|table)\s+\?"
    r"|\b(?:order|group)\s+by\s+\?",
    re.I,
)


def _java_literals(method: str) -> list[str]:
    return re.findall(r'"((?:[^"\\]|\\.)*)"', method)


def _is_sql_literal(text: str) -> bool:
    return re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|CALL)\b|\{call", text, re.I) is not None


def _quoted_literals(sql: str) -> set[str]:
    return set(re.findall(r"'[^']*'", sql))


def _literal_replaced_taint(original_expr: str, new_expr: str, tainted: set[str]) -> bool:
    """True when a new quoted literal stands where a tainted value stood.

    A literal that was already in the original SQL, such as a fixed username,
    is not a replacement.
    """
    expected = _norm_sql(_render_sql(original_expr, tainted, replace=True))
    actual = _norm_sql(_render_sql(new_expr, tainted, replace=False))
    return bool(_quoted_literals(actual) - _quoted_literals(expected))


def _no_new_string_literals(original: str, method: str) -> bool:
    from collections import Counter

    def others(text: str) -> Counter[str]:
        return Counter(item for item in _java_literals(text) if not _is_sql_literal(item))

    return not (others(method) - others(original))


def sqli_behaviour_checks(
    source: str, line: int | None = None, original: str | None = None
) -> dict[str, Any]:
    """Stub behaviour check for a SQL-injection fix. Not a Fortify rescan.

    still_present stays true unless every check passes. The later checks
    compare the method with the scanned original, so a missing original fails
    closed.
    """
    method = _strip_java_comments(_enclosing_method(source, line))
    names = _tainted_names(method)
    sql_statements = _sql_statements(method)
    sql_text = _java_string_contents("\n".join(sql_statements))
    no_tainted_concat = all(
        not _concatenates(statement, name) for name in names for statement in sql_statements
    )
    if not sql_statements and names:
        no_tainted_concat = all(not _concatenates(method, name) for name in names)
    uses_placeholder = bool(
        re.search(r"\.(?:prepareStatement|prepareCall)\s*\(", method) and "?" in sql_text
    )
    # Any tainted variable bound to a placeholder is enough. An intermediate
    # name such as the header enumeration does not also have to be bound.
    tainted_input_bound = bool(names) and any(_is_bound(method, name) for name in names)

    original_method = None
    if original:
        original_method = _strip_java_comments(_enclosing_method(original, line))
    sql_text_preserved = False
    no_identifier_placeholders = False
    call_type_kept = False
    no_new_string_literals = False
    no_hardcoded_replacement = False
    if original_method is not None:
        original_names = set(_tainted_names(original_method))
        old_expr = _sql_expr(original_method)
        new_expr = _sql_expr(method)
        if old_expr is not None and new_expr is not None:
            expected = _norm_sql(_render_sql(old_expr, original_names, replace=True))
            actual_raw = _render_sql(new_expr, original_names, replace=False)
            actual = _norm_sql(actual_raw)
            sql_text_preserved = bool(expected) and expected == actual
            no_identifier_placeholders = _IDENT_PLACEHOLDER.search(actual_raw) is None
            no_hardcoded_replacement = not _literal_replaced_taint(old_expr, new_expr, original_names)
        call_type_kept = _call_type_kept(original_method, method)
        no_new_string_literals = _no_new_string_literals(original_method, method)
    else:
        quoted = bool(_QUOTED_LITERAL.search(sql_text))
        if not names:
            no_hardcoded_replacement = not quoted
        else:
            no_hardcoded_replacement = not (quoted and not tainted_input_bound)
    checks = {
        "no_tainted_concat": no_tainted_concat,
        "uses_placeholder": uses_placeholder,
        "tainted_input_bound": tainted_input_bound,
        "no_hardcoded_replacement": no_hardcoded_replacement,
        "sql_text_preserved": sql_text_preserved,
        "no_identifier_placeholders": no_identifier_placeholders,
        "call_type_kept": call_type_kept,
        "no_new_string_literals": no_new_string_literals,
    }
    return {
        "checks": checks,
        "still_present": not all(checks.values()),
        "tainted": names,
        "stub": True,
    }


def stub_rule_still_present(category: str, source: str) -> bool:
    """Honest stub rescan: re-apply the same naive pattern that 'found' the issue."""
    if category == "sqli":
        return bool(sqli_behaviour_checks(source)["still_present"])
    if category == "xss":
        return bool(_XSS_SINK.search(source) and "param" in source)
    if category == "pathtraver":
        return bool(_PATH_SINK.search(source) and "param" in source)
    if category == "cmdi":
        return bool(_CMDI_SINK.search(source) and "param" in source)
    return "param" in source


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "stub-findings-mcp"}


@app.get("/tools")
def tools() -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": "list_findings",
                "description": "List Fortify-shaped vulnerability findings from the stub scanner",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "get_finding",
                "description": "Get one finding by id",
                "parameters": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                },
            },
            {
                "name": "request_rescan",
                "description": "Stub rescan: re-read the finding file and re-run the stub rule",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "finding id"},
                        "scope": {"type": "string"},
                    },
                },
            },
            {
                "name": "run_build",
                "description": "Compile the BenchmarkJava workspace via build-runner (mvn -q -DskipTests compile)",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "run_recipe",
                "description": (
                    "Run OpenRewrite UpgradeDependencyVersion only "
                    "(dry_run true|false) via build-runner"
                ),
                "parameters": {
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
                "description": "Append a triage/remediation decision for offline scoring",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "decision": {
                            "type": "string",
                            "description": "TP, FP, or NEEDS_DEVELOPER",
                        },
                        "reason": {"type": "string"},
                        "changed_files": {"type": "array", "items": {"type": "string"}},
                        "build_ok": {"type": "boolean"},
                    },
                    "required": ["finding_id", "decision", "reason"],
                },
            },
        ]
    }


@app.get("/findings")
def list_findings() -> dict[str, Any]:
    catalog = load_catalog()
    findings = [public_finding(f) for f in catalog.get("demo_cases", [])]
    return _audited("list_findings", {}, {"findings": findings, "count": len(findings), "tool": "stub-fortify"})


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict[str, Any]:
    return _audited("get_finding", {"id": finding_id}, public_finding(find_raw(finding_id)), finding_id)


@app.post("/rescan")
def request_rescan(body: dict[str, Any] | None = None) -> dict[str, Any]:
    body = body or {}
    finding_id = body.get("id") or body.get("finding_id")
    if not finding_id:
        return _audited(
            "request_rescan",
            body,
            {
                "status": "accepted",
                "message": "Pass finding id to run stub rule re-check",
                "stub": True,
                "scope": body.get("scope", "all"),
            },
        )
    raw = find_raw(finding_id)
    rel = raw["file"]
    tool = raw.get("tool", "stub-fortify")

    # Library / Sonatype-shaped: re-read pom.xml and compare to fixed_version.
    if raw.get("category") == "library" or tool == "stub-sonatype":
        pom_rel = rel if rel.endswith("pom.xml") else "pom.xml"
        pom_path = WORKSPACE_ROOT / pom_rel
        pom_text = body.get("file_content")
        if pom_text is None:
            if not pom_path.exists():
                raise HTTPException(
                    status_code=400,
                    detail=f"workspace pom missing: {pom_path}; pass file_content",
                )
            pom_text = pom_path.read_text(errors="replace")
        present = library_still_present(raw, pom_text)
        return _audited(
            "request_rescan",
            body,
            {
                "status": "completed",
                "finding_id": finding_id,
                "file": pom_rel,
                "still_present": present,
                "stub": True,
                "tool": "stub-sonatype",
                "component": raw.get("component"),
                "fixed_version": raw.get("fixed_version"),
                "message": "Stub library rescan (pom version vs fixed_version)",
            },
            finding_id,
        )

    path = WORKSPACE_ROOT / rel
    # Also accept content from bridge if workspace not mounted here
    source = body.get("file_content")
    if source is None:
        if not path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"workspace file missing: {path}; pass file_content or mount WORKSPACE_ROOT",
            )
        source = path.read_text(errors="replace")
    category = raw.get("category") or ""
    if category == "sqli":
        behaviour = sqli_behaviour_checks(source, raw.get("line"), _load_baseline(finding_id))
        return _audited(
            "request_rescan",
            body,
            {
                "status": "completed",
                "finding_id": finding_id,
                "file": rel,
                "still_present": behaviour["still_present"],
                "checks": behaviour["checks"],
                "stub": True,
                "tool": "stub-fortify",
                "message": (
                    "Stub SQL behaviour check (pattern rules, not a live Fortify scan)"
                ),
            },
            finding_id,
        )
    present = stub_rule_still_present(category, source)
    return _audited(
        "request_rescan",
        body,
        {
            "status": "completed",
            "finding_id": finding_id,
            "file": rel,
            "still_present": present,
            "stub": True,
            "tool": "stub-fortify",
            "message": "Stub rule re-check (not a live Fortify scan)",
        },
        finding_id,
    )


def _proxy_build_runner(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{BUILD_RUNNER_URL}{path}",
        data=json.dumps(body or {}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode() if e.fp else str(e)
        raise HTTPException(status_code=502, detail=f"build-runner error: {e.code} {detail}")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"build-runner unreachable: {e}")


@app.post("/build")
def run_build(body: dict[str, Any] | None = None) -> dict[str, Any]:
    body = body or {}
    return _audited("run_build", body, _proxy_build_runner("/compile", body))


@app.post("/recipe")
def run_recipe(body: dict[str, Any] | None = None) -> dict[str, Any]:
    body = body or {}
    return _audited(
        "run_recipe",
        body,
        _proxy_build_runner("/recipe", body),
        str(body.get("finding_id") or ""),
    )


@app.post("/decisions")
def record_decision(body: dict[str, Any]) -> dict[str, Any]:
    required = ("finding_id", "decision", "reason")
    for k in required:
        if k not in body:
            raise HTTPException(status_code=400, detail=f"{k} required")
    decision = str(body["decision"]).upper().strip().replace(" ", "_").replace("-", "_")
    if decision not in ("TP", "FP", "NEEDS_DEVELOPER"):
        raise HTTPException(
            status_code=400,
            detail="decision must be TP, FP, or NEEDS_DEVELOPER",
        )
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "finding_id": body["finding_id"],
        "decision": decision,
        "reason": body["reason"],
        "changed_files": body.get("changed_files") or [],
        "build_ok": bool(body.get("build_ok", False)),
    }
    DECISIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DECISIONS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return _audited(
        "record_decision",
        body,
        {"status": "recorded", "record": record},
        str(body["finding_id"]),
    )


@app.get("/decisions")
def list_decisions() -> dict[str, Any]:
    if not DECISIONS_PATH.exists():
        return {"decisions": [], "count": 0}
    rows = []
    for line in DECISIONS_PATH.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return {"decisions": rows, "count": len(rows)}


@app.post("/mcp")
async def mcp_dispatch(payload: dict[str, Any]) -> JSONResponse:
    method = payload.get("method") or payload.get("name")
    params = payload.get("params") or payload.get("arguments") or {}
    req_id = payload.get("id")
    try:
        if method == "list_findings":
            result = list_findings()
        elif method == "get_finding":
            fid = params.get("id")
            if not fid:
                raise HTTPException(status_code=400, detail="params.id required")
            result = get_finding(fid)
        elif method == "request_rescan":
            result = request_rescan(params)
        elif method == "run_build":
            result = run_build(params)
        elif method == "run_recipe":
            result = run_recipe(params)
        elif method == "record_decision":
            result = record_decision(params)
        elif method in ("tools/list", "list_tools"):
            result = tools()
        else:
            raise HTTPException(status_code=400, detail=f"unknown method: {method}")
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})
    except HTTPException as exc:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": exc.status_code, "message": exc.detail},
            },
            status_code=200,
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
