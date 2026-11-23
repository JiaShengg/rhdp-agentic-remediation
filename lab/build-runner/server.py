#!/usr/bin/env python3
"""Tiny HTTP compile + OpenRewrite runner for the lab workspace."""
from __future__ import annotations

import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORKSPACE = Path(os.environ.get("WORKSPACE_ROOT", "/opt/data/workspace/BenchmarkJava"))
PORT = int(os.environ.get("PORT", "8081"))
# Pin rewrite-maven-plugin (lab reproducible). Bump deliberately when needed.
REWRITE_PLUGIN = os.environ.get(
    "REWRITE_MAVEN_PLUGIN",
    "org.openrewrite.maven:rewrite-maven-plugin:5.40.0",
)
REWRITE_YML = "rewrite.yml"
ALLOWED_RECIPE = "org.openrewrite.maven.UpgradeDependencyVersion"
RECIPE_NAME = "com.rhdp.lab.UpgradeOneDependency"


def _run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(WORKSPACE),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _pom_version(group_id: str, artifact_id: str) -> str | None:
    pom = WORKSPACE / "pom.xml"
    if not pom.exists():
        return None
    # Strip default namespace for easy finds
    text = pom.read_text(errors="replace")
    text_ns = re.sub(r'\sxmlns="[^"]+"', "", text, count=1)
    root = ET.fromstring(text_ns)
    for dep in root.findall(".//dependency"):
        g = (dep.findtext("groupId") or "").strip()
        a = (dep.findtext("artifactId") or "").strip()
        if g == group_id and a == artifact_id:
            return (dep.findtext("version") or "").strip() or None
    return None


def _write_rewrite_yml(group_id: str, artifact_id: str, new_version: str) -> Path:
    path = WORKSPACE / REWRITE_YML
    path.write_text(
        f"""\
---
type: specs.openrewrite.org/v1beta/recipe
name: {RECIPE_NAME}
displayName: Upgrade one Maven dependency (lab)
recipeList:
  - {ALLOWED_RECIPE}:
      groupId: {group_id}
      artifactId: {artifact_id}
      newVersion: {new_version}
"""
    )
    return path


def _rewrite_patch() -> str:
    """OpenRewrite dryRun writes the diff here and does not touch pom.xml."""
    candidates = [
        WORKSPACE / "target" / "rewrite" / "rewrite.patch",
        WORKSPACE / "target" / "rewrite" / "rewrite.patch.bak",
    ]
    for path in candidates:
        if path.is_file() and path.stat().st_size > 0:
            return path.read_text(errors="replace")[-16000:]
    rewrite_dir = WORKSPACE / "target" / "rewrite"
    if rewrite_dir.is_dir():
        patches = sorted(rewrite_dir.rglob("*.patch"))
        if patches:
            return patches[0].read_text(errors="replace")[-16000:]
    return ""


def _git_diff() -> str:
    try:
        proc = _run(["git", "diff", "--", "pom.xml"])
    except FileNotFoundError:
        return ""
    return (proc.stdout or "")[-8000:]


def _changed_files() -> list[str]:
    try:
        proc = _run(["git", "status", "--porcelain"])
    except FileNotFoundError:
        proc = None
    files: list[str] = []
    if proc is not None and proc.returncode == 0:
        for line in (proc.stdout or "").splitlines():
            path = line[3:].strip()
            if path:
                files.append(path)
    return files


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quieter
        pass

    def _json(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode())

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok", "workspace": str(WORKSPACE)})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/compile":
            self._compile()
            return
        if self.path == "/recipe":
            self._recipe()
            return
        self._json(404, {"error": "not found"})

    def _compile(self):
        if not WORKSPACE.exists():
            self._json(400, {"ok": False, "error": f"missing workspace {WORKSPACE}"})
            return
        # Spotless ratchet expects origin/master. The lab seed is a fresh main.
        proc = _run(
            [
                "mvn",
                "-q",
                "-DskipTests",
                "-Dspotless.check.skip=true",
                "-Dspotless.apply.skip=true",
                "compile",
            ],
            timeout=300,
        )
        self._json(
            200,
            {
                "ok": proc.returncode == 0,
                "command": "mvn -q -DskipTests -Dspotless.check.skip=true -Dspotless.apply.skip=true compile",
                "exit_code": proc.returncode,
                "stdout": (proc.stdout or "")[-4000:],
                "stderr": (proc.stderr or "")[-4000:],
            },
        )

    def _recipe(self):
        if not WORKSPACE.exists():
            self._json(400, {"ok": False, "error": f"missing workspace {WORKSPACE}"})
            return
        body = self._read_body()
        # Reject anything that is not UpgradeDependencyVersion inputs.
        recipe = body.get("recipe") or ALLOWED_RECIPE
        if recipe != ALLOWED_RECIPE:
            self._json(
                400,
                {
                    "ok": False,
                    "error": f"only {ALLOWED_RECIPE} is supported",
                    "rejected_recipe": recipe,
                },
            )
            return
        for key in ("group_id", "artifact_id", "new_version"):
            if not body.get(key) or not isinstance(body.get(key), str):
                self._json(400, {"ok": False, "error": f"{key} required string"})
                return
        # No free-text recipe payloads
        if body.get("recipe_yaml") or body.get("extra_args") or body.get("command"):
            self._json(400, {"ok": False, "error": "free-text recipe fields rejected"})
            return

        group_id = body["group_id"].strip()
        artifact_id = body["artifact_id"].strip()
        new_version = body["new_version"].strip()
        dry_run = bool(body.get("dry_run", True))
        finding_id = body.get("finding_id")

        before = _pom_version(group_id, artifact_id)
        _write_rewrite_yml(group_id, artifact_id, new_version)
        goal = "dryRun" if dry_run else "run"
        # Skip Spotless: BenchmarkJava ratchet expects origin/master; lab seed is a fresh main.
        cmd = [
            "mvn",
            "-q",
            f"{REWRITE_PLUGIN}:{goal}",
            f"-Drewrite.configLocation={REWRITE_YML}",
            f"-Drewrite.activeRecipes={RECIPE_NAME}",
            "-Dspotless.check.skip=true",
            "-Dspotless.apply.skip=true",
        ]
        try:
            proc = _run(cmd, timeout=600)
        except subprocess.TimeoutExpired:
            self._json(200, {"ok": False, "error": "rewrite timed out", "command": cmd})
            return
        after = _pom_version(group_id, artifact_id)
        # dryRun leaves the tree unchanged and writes target/rewrite/rewrite.patch.
        # The build-runner image has no git, so do not depend on git for the patch.
        patch = _rewrite_patch() or _git_diff()
        changed = _changed_files()
        if not dry_run and not changed and before != after:
            changed = ["pom.xml"]
            if (WORKSPACE / REWRITE_YML).exists():
                changed.append(REWRITE_YML)
        self._json(
            200,
            {
                "ok": proc.returncode == 0,
                "finding_id": finding_id,
                "recipe": ALLOWED_RECIPE,
                "dry_run": dry_run,
                "group_id": group_id,
                "artifact_id": artifact_id,
                "new_version": new_version,
                "version_before": before,
                "version_after": after,
                "command": " ".join(cmd),
                "exit_code": proc.returncode,
                "stdout": (proc.stdout or "")[-4000:],
                "stderr": (proc.stderr or "")[-4000:],
                "patch": patch if dry_run else None,
                "changed_files": changed if not dry_run else [],
            },
        )


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
