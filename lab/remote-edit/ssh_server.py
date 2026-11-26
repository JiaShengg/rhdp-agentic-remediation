#!/usr/bin/env python3
"""Key-only SSH server for the remote-edit developer workspace.

Runs as the workspace user. There is no password auth and no privilege
escalation. Exec requests are passed to the user's shell the way OpenSSH
does. SFTP and legacy scp are enabled because the Hermes SSH backend uses
both during file sync.
"""

from __future__ import annotations

import asyncio
import os
import sys

import asyncssh


HOST_KEY = os.environ.get("REMOTE_EDIT_HOST_KEY", "/etc/remote-edit/ssh_host_ed25519")
AUTHORIZED = os.environ.get("REMOTE_EDIT_AUTHORIZED_KEYS", "/etc/remote-edit/authorized_keys")
PORT = int(os.environ.get("REMOTE_EDIT_SSH_PORT", "2222"))
ALLOW_USER = os.environ.get("REMOTE_EDIT_SSH_USER", "")
START_DIR = os.environ.get("REMOTE_EDIT_START_DIR", "/workspace/BenchmarkJava")


async def _pump(reader: asyncio.StreamReader, writer) -> None:
    while True:
        data = await reader.read(65536)
        if not data:
            break
        if isinstance(data, bytes):
            data = data.decode(errors="replace")
        writer.write(data)
        await writer.drain()


async def handle_process(process: asyncssh.SSHServerProcess) -> None:
    try:
        await _handle_process(process)
    except Exception as exc:  # noqa: BLE001
        print(f"ssh session error: {exc!r}", flush=True)
        try:
            process.stderr.write(f"{exc}\n")
            process.exit(1)
        except Exception:
            return


async def _handle_process(process: asyncssh.SSHServerProcess) -> None:
    username = process.get_extra_info("username")
    if ALLOW_USER and username != ALLOW_USER:
        process.stderr.write("user rejected\n")
        process.exit(1)
        return
    command = process.command
    if isinstance(command, bytes):
        command = command.decode()
    shell = os.environ.get("SHELL") or "/bin/bash"
    if command:
        argv = [shell, "-c", command]
    else:
        argv = [shell, "-l"]
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=START_DIR if os.path.isdir(START_DIR) else None,
        env=os.environ.copy(),
    )

    async def from_client() -> None:
        try:
            while True:
                data = await process.stdin.read(65536)
                if not data:
                    break
                if isinstance(data, str):
                    data = data.encode()
                if proc.stdin is not None:
                    proc.stdin.write(data)
                    await proc.stdin.drain()
        finally:
            if proc.stdin is not None:
                proc.stdin.close()

    await asyncio.gather(
        from_client(),
        _pump(proc.stdout, process.stdout),
        _pump(proc.stderr, process.stderr),
    )
    code = await proc.wait()
    process.exit(code if code is not None else 1)


async def main() -> None:
    if not os.path.isfile(HOST_KEY):
        raise SystemExit(f"missing host key {HOST_KEY}")
    if not os.path.isfile(AUTHORIZED):
        raise SystemExit(f"missing authorized keys {AUTHORIZED}")
    def _conn_error(conn, exc):
        if exc is not None:
            print(f"ssh connection error: {exc!r}", flush=True)

    await asyncssh.listen(
        host="0.0.0.0",
        port=PORT,
        server_host_keys=[HOST_KEY],
        authorized_client_keys=AUTHORIZED,
        process_factory=handle_process,
        sftp_factory=True,
        allow_scp=True,
        error_handler=_conn_error,
        password_auth=False,
        kbdint_auth=False,
        allow_pty=True,
        agent_forwarding=False,
        x11_forwarding=False,
    )
    print(f"ssh listening on {PORT}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit) as exc:
        if isinstance(exc, SystemExit) and exc.code not in (0, None):
            print(exc, file=sys.stderr)
            raise
