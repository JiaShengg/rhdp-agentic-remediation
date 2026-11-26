#!/usr/bin/env python3
"""Unit tests for the workspace Model Context Protocol server.

The git repository and the stub responses live only in this file.
They are not written into the agent workspace.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "workspace_mcp_under_test",
        ROOT / "lab" / "remote-edit" / "workspace_mcp.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


mod = _load()


class SharedBridgeCopyTests(unittest.TestCase):
    def test_remote_edit_copies_match_hermes(self) -> None:
        pairs = [
            (
                "lab/hermes/mcp-bridge.py",
                "lab/remote-edit/mcp-bridge-remote-edit.py",
            ),
            (
                "lab/hermes/patch_coder_tool_json.py",
                "lab/remote-edit/patch_coder_tool_json-remote-edit.py",
            ),
        ]
        for shared_name, copy_name in pairs:
            shared = (ROOT / shared_name).read_text().splitlines()
            copy = (ROOT / copy_name).read_text().splitlines()
            self.assertTrue(copy[1].startswith("# Same program as " + shared_name))
            self.assertEqual([copy[0], *copy[2:]], shared)


class WorkspaceMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / "src" / "App.java"
        self.source.parent.mkdir()
        self.source.write_text("alpha\nbeta\n", encoding="utf-8")
        subprocess.check_call(
            ["git", "init", "-b", "main"],
            cwd=self.root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["git", "add", "src/App.java"],
            cwd=self.root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            [
                "git",
                "-c",
                "user.email=lab@local",
                "-c",
                "user.name=lab",
                "commit",
                "-m",
                "seed",
            ],
            cwd=self.root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._old_root = mod.ROOT
        self._old_audit = mod.AUDIT
        self._old_run = mod.subprocess.run
        self._old_stub = mod._stub_json
        self._old_build = mod._run_build_unlocked
        self._old_tests = mod._run_tests_unlocked
        mod.ROOT = self.root.resolve()
        mod.AUDIT = self.root / "audit.jsonl"
        os.environ.pop("WORKSPACE_MCP_TOKEN", None)

    def tearDown(self) -> None:
        mod.ROOT = self._old_root
        mod.AUDIT = self._old_audit
        mod.subprocess.run = self._old_run
        mod._stub_json = self._old_stub
        mod._run_build_unlocked = self._old_build
        mod._run_tests_unlocked = self._old_tests
        os.environ.pop("WORKSPACE_MCP_TOKEN", None)
        self.tmp.cleanup()

    def test_path_escape(self) -> None:
        for path in ("../secret", "/etc/passwd", "src/../../etc/passwd", "~/secret"):
            with self.assertRaises(ValueError):
                mod._resolve(path)

    def test_rejected_headers_leave_the_file(self) -> None:
        before = self.source.read_bytes()
        samples = [
            "rename from src/Old.java\nrename to src/App.java\n",
            "copy from src/Old.java\ncopy to src/App.java\n",
            "old mode 100644\nnew mode 100755\n",
            "new file mode 120000\n",
            "GIT binary patch\n",
        ]
        for extra in samples:
            diff = (
                "diff --git a/src/App.java b/src/App.java\n"
                + extra
                + "--- a/src/App.java\n+++ b/src/App.java\n"
                + "@@ -1,2 +1,2 @@\nalpha\n-beta\n+BETA\n"
            )
            with self.assertRaises(ValueError) as caught:
                mod.apply_patch(diff)
            self.assertIn("forbidden header", str(caught.exception))
            self.assertEqual(self.source.read_bytes(), before)

    def test_restore_on_failed_rescan(self) -> None:
        before = self.source.read_bytes()

        def fake_run(cmd, *args, **kwargs):
            argv = list(cmd) if isinstance(cmd, (list, tuple)) else []
            if argv and (argv[0] == "mvn" or argv[0].endswith("/mvn")):
                return subprocess.CompletedProcess(argv, 0, stdout="mvn exit 0", stderr="")
            return self._old_run(cmd, *args, **kwargs)

        def fake_stub(method, path, body=None, timeout=60):
            if method == "GET" and path == "/findings":
                return {"findings": [{"id": "F-1", "file": "src/App.java"}], "count": 1}
            if method == "GET" and path == "/findings/F-1":
                return {"id": "F-1", "file": "src/App.java"}
            if method == "POST" and path == "/rescan":
                return {
                    "finding_id": "F-1",
                    "still_present": True,
                    "checks": {"uses_placeholder": False},
                    "stub": True,
                }
            raise AssertionError(f"unexpected {method} {path}")

        mod.subprocess.run = fake_run
        mod._stub_json = fake_stub
        diff = (
            "diff --git a/src/App.java b/src/App.java\n"
            "--- a/src/App.java\n"
            "+++ b/src/App.java\n"
            "@@ -1,2 +1,2 @@\n"
            " alpha\n"
            "-beta\n"
            "+BETA\n"
        )
        payload = json.loads(mod.apply_patch(diff))
        self.assertEqual(payload["status"], "rejected")
        self.assertTrue(payload["restored"])
        self.assertIn("uses_placeholder", payload["failed_checks"])
        self.assertEqual(self.source.read_bytes(), before)

    def test_lock_serializes_build_and_tests(self) -> None:
        entered: list[str] = []
        release = threading.Event()
        started = threading.Event()

        def slow_build() -> str:
            self.assertTrue(mod._MUTATION.locked())
            entered.append("build")
            started.set()
            self.assertTrue(release.wait(5))
            return "mvn exit 0"

        def slow_test(_name: str) -> str:
            entered.append("test")
            return "ok"

        mod._run_build_unlocked = slow_build
        mod._run_tests_unlocked = slow_test
        worker = threading.Thread(target=mod.run_build)
        worker.start()
        self.assertTrue(started.wait(2))
        other = threading.Thread(target=lambda: mod.run_tests("com.example.Demo"))
        other.start()
        other.join(0.3)
        self.assertTrue(other.is_alive())
        self.assertEqual(entered, ["build"])
        release.set()
        worker.join(5)
        other.join(5)
        self.assertEqual(entered, ["build", "test"])

    def test_audit_record_fields(self) -> None:
        mod._audit("apply_patch", True, "kept", finding_ids=["F-1"], diff="diff --git a/a b/a\n")
        record = json.loads(mod.AUDIT.read_text(encoding="utf-8").splitlines()[-1])
        self.assertTrue(record["ts"].endswith("Z"))
        self.assertEqual(record["tool"], "apply_patch")
        self.assertTrue(record["ok"])
        self.assertEqual(record["finding_ids"], ["F-1"])
        self.assertEqual(record["session"], "")
        self.assertEqual(record["detail"], "kept")
        self.assertEqual(
            record["diff_sha256"],
            hashlib.sha256(b"diff --git a/a b/a\n").hexdigest(),
        )

    def test_bearer_token_when_set(self) -> None:
        os.environ["WORKSPACE_MCP_TOKEN"] = "lab-token"
        server = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            health = urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5)
            self.assertEqual(health.status, 200)
            denied = urllib.request.Request(
                f"http://127.0.0.1:{port}/mcp",
                data=b"{}",
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(denied, timeout=5)
            self.assertEqual(caught.exception.code, 401)
            caught.exception.close()
            allowed = urllib.request.Request(
                f"http://127.0.0.1:{port}/mcp",
                data=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-03-26"},
                    }
                ).encode(),
                method="POST",
                headers={"Authorization": "Bearer lab-token", "Content-Type": "application/json"},
            )
            response = urllib.request.urlopen(allowed, timeout=5)
            self.assertEqual(response.status, 200)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
