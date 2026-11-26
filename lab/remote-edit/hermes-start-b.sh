#!/bin/bash
# Start the Path B Hermes. No SSH key, no build-runner, no hermes-data.
set -eo pipefail
export HERMES_HOME=/opt/data
export HOME=/opt/data
mkdir -p "$HERMES_HOME"/{cron,sessions,skills/triage,skills/sqli-remediation,memories,logs,attachments,scratch}
cp /bootstrap/config.yaml "$HERMES_HOME/config.yaml"
cp /bootstrap/mcp-bridge.py "$HERMES_HOME/mcp-bridge.py"
cp /bootstrap/triage.md "$HERMES_HOME/skills/triage/SKILL.md"
cp /bootstrap/sqli-remediation-b.md "$HERMES_HOME/skills/sqli-remediation/SKILL.md"
cat /bootstrap/triage.md /bootstrap/sqli-remediation-b.md > "$HERMES_HOME/SOUL.md"
chmod +x "$HERMES_HOME/mcp-bridge.py"

unset OPENROUTER_API_KEY NOUS_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY || true
cat > "$HERMES_HOME/.env" << EOF
OPENAI_BASE_URL=${OPENAI_BASE_URL}
OPENAI_API_KEY=${OPENAI_API_KEY:-not-needed}
HERMES_DASHBOARD_BASIC_AUTH_USERNAME=${HERMES_DASHBOARD_BASIC_AUTH_USERNAME}
HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=${HERMES_DASHBOARD_BASIC_AUTH_PASSWORD}
HERMES_DASHBOARD_BASIC_AUTH_SECRET=${HERMES_DASHBOARD_BASIC_AUTH_SECRET}
EOF
sed -i '/OPENROUTER/d;/ANTHROPIC_API_KEY/d;/NOUS_API_KEY/d' "$HERMES_HOME/.env" || true

if [ -f /bootstrap/patch_coder_tool_json.py ]; then
  cp /bootstrap/patch_coder_tool_json.py "$HERMES_HOME/patch_coder_tool_json.py"
  python3 "$HERMES_HOME/patch_coder_tool_json.py" || true
fi

if id hermes >/dev/null 2>&1; then
  chown -R hermes:hermes "$HERMES_HOME"
else
  chmod -R a+rwX "$HERMES_HOME"
fi

echo "Starting remote-edit Hermes B on 0.0.0.0:9119"
if command -v runuser >/dev/null 2>&1 && id hermes >/dev/null 2>&1; then
  runuser -u hermes -- bash -lc 'mkdir -p /opt/data/logs /opt/data/scratch; nohup hermes gateway run --accept-hooks >> /opt/data/logs/gateway.log 2>&1 &'
  exec runuser -u hermes -- hermes dashboard --host 0.0.0.0 --port 9119 --no-open --skip-build
fi
exec hermes dashboard --host 0.0.0.0 --port 9119 --no-open --skip-build
