#!/usr/bin/env bash
# Fail if tracked files look like they contain secrets or private identifiers.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PATTERNS=(
  'opentlc\.com'
  'sandbox[0-9]'
  '/Users/'
  'password[[:space:]]*[:=][[:space:]]*[^[:space:]<$]'
  'BEGIN .*PRIVATE KEY'
  'AKIA[0-9A-Z]{16}'
  'hf_[A-Za-z0-9]{20,}'
)

# Optional extra patterns (e.g. partner names) — keep untracked:
#   scripts/scan-patterns.local  (one regex per line, # comments allowed)
LOCAL_PATTERNS_FILE="$ROOT/scripts/scan-patterns.local"
if [[ -f "$LOCAL_PATTERNS_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    PATTERNS+=("$line")
  done < "$LOCAL_PATTERNS_FILE"
fi

hits=0
for pat in "${PATTERNS[@]}"; do
  if git grep -n -E -I -e "$pat" -- . \
    ':(exclude)*.png' ':(exclude)*.jpg' ':(exclude)*.jpeg' ':(exclude)*.gif' ':(exclude)*.webp' \
    ':(exclude)scripts/scan-secrets.sh' ':(exclude)scripts/scan-patterns.local' >/dev/null 2>&1; then
    echo "FAIL: pattern matched: $pat" >&2
    git grep -n -E -I -e "$pat" -- . \
      ':(exclude)*.png' ':(exclude)*.jpg' ':(exclude)*.jpeg' ':(exclude)*.gif' ':(exclude)*.webp' \
      ':(exclude)scripts/scan-secrets.sh' ':(exclude)scripts/scan-patterns.local' >&2 || true
    hits=$((hits + 1))
  fi
done

if [[ "$hits" -gt 0 ]]; then
  echo "scan-secrets: $hits pattern group(s) failed" >&2
  exit 1
fi
echo "scan-secrets: ok"
