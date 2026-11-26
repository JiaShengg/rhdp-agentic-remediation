#!/bin/bash
# Seed BenchmarkJava and start the workspace SSH and MCP servers.
# Runs as whatever UID the pod gives us. Does not install sudo.
set -euo pipefail

TOOLS=/workspace/.tools
mkdir -p "$TOOLS/bin" /workspace /workspace/.home /workspace/.keys /audit
export PATH="$TOOLS/bin:$TOOLS/maven/bin:$PATH"
export HOME=/workspace/.home

if ! command -v git >/dev/null 2>&1; then
  GIT_TGZ=/tmp/git-minimal.tar.xz
  GIT_URL=https://github.com/baulk/git-minimal/releases/download/v2.56.1/git-minimal-musl-v2.56.1-linux-amd64.tar.xz
  GIT_SHA=a14f174686ede200651b41152a6ad3a6075ced0335cca83fbc419d1bbb7b3502
  curl -fsSL --connect-timeout 15 --max-time 90 "$GIT_URL" -o "$GIT_TGZ"
  echo "$GIT_SHA  $GIT_TGZ" | sha256sum -c -
  python3 - << 'PY'
import lzma, tarfile
with lzma.open("/tmp/git-minimal.tar.xz") as raw, tarfile.open(fileobj=raw) as tar:
    tar.extractall("/workspace/.tools/git")
PY
  if [ -x "$TOOLS/git/bin/git" ]; then
    ln -sf "$TOOLS/git/bin/git" "$TOOLS/bin/git"
  else
    found=$(find "$TOOLS/git" -type f -name git -perm -111 | head -1)
    ln -sf "$found" "$TOOLS/bin/git"
  fi
  git --version
fi

if [ ! -x "$TOOLS/maven/bin/mvn" ]; then
  MAVEN_TGZ=/tmp/apache-maven-3.9.9-bin.tar.gz
  MAVEN_SHA512=a555254d6b53d267965a3404ecb14e53c3827c09c3b94b5678835887ab404556bfaf78dcfe03ba76fa2508649dca8531c74bca4d5846513522404d48e8c4ac8b
  curl -fsSL --connect-timeout 15 --max-time 180 https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz -o "$MAVEN_TGZ"
  echo "$MAVEN_SHA512  $MAVEN_TGZ" | sha512sum -c -
  python3 - << 'PY'
import tarfile
with tarfile.open("/tmp/apache-maven-3.9.9-bin.tar.gz", "r:gz") as tar:
    tar.extractall("/workspace/.tools")
PY
  ln -sfn "$TOOLS/apache-maven-3.9.9" "$TOOLS/maven"
fi

# The DevWorkspace assigns a high UID and cannot create accounts.
# The SSH login name is fixed so the agent config does not depend on that UID.
SSH_USER=default
export REMOTE_EDIT_SSH_USER="$SSH_USER"

WS=/workspace/BenchmarkJava
if [ ! -d "$WS/src" ]; then
  rm -rf "$WS"
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git "$WS" \
    || echo "clone failed"
fi
if [ ! -d "$WS/src" ]; then
  echo "workspace tree missing"
  exit 1
fi
rm -f "$WS"/expectedresults*.csv || true
if [ ! -d "$WS/.git" ]; then
  git -C "$WS" init -b main
  git -C "$WS" add -A
  git -C "$WS" -c user.email=lab@local -c user.name=lab commit -m "lab workspace seed"
fi
chmod -R u+rwX,g+rX "$WS" /workspace/.tools || true

if ! python3 -c 'import asyncssh' >/dev/null 2>&1; then
  if ! python3 -m pip --version >/dev/null 2>&1; then
    python3 -m ensurepip --user || true
    export PATH="$HOME/.local/bin:$PATH"
  fi
  if [ -d /bootstrap/wheels ]; then
    python3 -m pip install --user --no-index --find-links /bootstrap/wheels 'asyncssh==2.21.0' 'cryptography==41.0.7'
  else
    python3 -m pip install --user 'asyncssh==2.21.0' 'cryptography==41.0.7'
  fi
fi

export REMOTE_EDIT_HOST_KEY=/workspace/.keys/ssh_host_ed25519
export REMOTE_EDIT_AUTHORIZED_KEYS=/workspace/.keys/authorized_keys
chmod 600 "$REMOTE_EDIT_HOST_KEY" || true
chmod 644 "$REMOTE_EDIT_AUTHORIZED_KEYS" || true

echo "workspace user $(id -un) sudo=$(command -v sudo || echo none)"
python3 /bootstrap/ssh_server.py &
python3 /bootstrap/workspace_mcp.py &
wait -n
exit $?
