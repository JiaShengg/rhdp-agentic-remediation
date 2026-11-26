#!/usr/bin/env python3
"""Promote markdown/JSON tool stubs into real tool_calls (Qwen2.5-Coder + tool_choice=auto).

Idempotent. Finds the first JSON object with {"name", "arguments"} anywhere in the
assistant content, using json.raw_decode so nested arguments parse correctly.

Allowlist only (stub MCP tools). Any other name is logged and dropped, and is never
executed. Native Hermes file/terminal tool_calls (not text stubs) are untouched.
"""
from __future__ import annotations

import re
from pathlib import Path

MARKER = "RHDP_CODER_TOOL_JSON_PROMOTE"
TARGET = Path("/opt/hermes/agent/chat_completion_helpers.py")
NEEDLE = (
    "        mock_tool_calls, has_truncated_tool_args = "
    "self._assemble_tool_calls(tool_calls_acc, finish_reason)\n"
)

# Base tool names the promote path may execute. MCP-prefixed forms
# (mcp__stub_fortify__get_finding, mcp__stub_sonatype__run_recipe, …) are
# accepted when their suffix matches one of these.
ALLOWED_TOOL_BASES = frozenset(
    {
        "list_findings",
        "get_finding",
        "run_build",
        "request_rescan",
        "record_decision",
        "run_recipe",
    }
)

INSERT = r'''        mock_tool_calls, has_truncated_tool_args = self._assemble_tool_calls(tool_calls_acc, finish_reason)
        # RHDP_CODER_TOOL_JSON_PROMOTE
        if not mock_tool_calls and full_content:
            import json as _json, os as _os, re as _re, uuid as _uuid
            from types import SimpleNamespace as _NS
            _fallback = _os.environ.get("HERMES_TEXT_TOOLCALL_FALLBACK", "").lower() == "true"
            _ALLOWED = {
                "list_findings", "get_finding", "run_build",
                "request_rescan", "record_decision", "run_recipe",
            }
            def _base_tool_name(_n: str) -> str:
                if "__" in _n:
                    return _n.rsplit("__", 1)[-1]
                return _n
            _raw = full_content
            _obj = None
            _dropped = None
            _dec = _json.JSONDecoder()
            for _m in _re.finditer(r"\{\s*\"name\"\s*:", _raw):
                try:
                    _cand, _ = _dec.raw_decode(_raw[_m.start():])
                except Exception:
                    continue
                if not (isinstance(_cand, dict) and isinstance(_cand.get("name"), str) and "arguments" in _cand):
                    continue
                _bn = _base_tool_name(_cand["name"])
                if _bn not in _ALLOWED:
                    _dropped = _cand["name"]
                    logger.warning(
                        "Dropped markdown/JSON tool stub outside allowlist name=%s base=%s",
                        _cand["name"], _bn,
                    )
                    continue
                _obj = _cand
                break
            if _obj is not None and not _fallback:
                logger.warning(
                    "Text tool stub seen but not promoted (set HERMES_TEXT_TOOLCALL_FALLBACK=true to enable) name=%s",
                    _obj["name"],
                )
            elif _obj is not None:
                _args = _obj.get("arguments")
                if not isinstance(_args, str):
                    _args = _json.dumps(_args)
                mock_tool_calls = [
                    _NS(
                        id="call_" + _uuid.uuid4().hex[:24],
                        type="function",
                        function=_NS(name=_obj["name"], arguments=_args),
                    )
                ]
                full_content = None
                content_parts = []
                logger.warning(
                    "Text tool-call fallback fired name=%s",
                    _obj["name"],
                )
            elif _dropped is not None:
                # Leave content as the final answer; do not invent a tool call.
                pass
'''


def main() -> None:
    text = TARGET.read_text()
    if MARKER in text:
        text = re.sub(
            r"        mock_tool_calls, has_truncated_tool_args = self\._assemble_tool_calls\(tool_calls_acc, finish_reason\)\n"
            r"        # RHDP_CODER_TOOL_JSON_PROMOTE\n"
            r".*?(?=\n        # Zero-chunk guard:|\n        if finish_reason is None and not content_parts)",
            "",
            text,
            count=1,
            flags=re.S,
        )
        print("Removed prior tool-json promote block")

    if NEEDLE not in text:
        print("WARN: assemble_tool_calls needle missing; skip promote patch")
        return
    TARGET.write_text(text.replace(NEEDLE, INSERT, 1))
    print("Patched chat_completion_helpers tool-json promote (allowlist enforced)")


if __name__ == "__main__":
    main()
