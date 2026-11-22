#!/usr/bin/env bash
set -euo pipefail

# Run Semgrep OSS SAST across the repository.
if command -v semgrep >/dev/null 2>&1; then
  SEMGREP_CMD=(semgrep)
elif command -v uvx >/dev/null 2>&1; then
  SEMGREP_CMD=(uvx semgrep)
elif command -v pipx >/dev/null 2>&1; then
  SEMGREP_CMD=(pipx run semgrep)
else
  echo "error: semgrep is required (install via 'pip install semgrep', 'pipx install semgrep', or 'uvx semgrep')" >&2
  exit 1
fi

# Work around semgrep/semgrep#11979: Python 3.15 reports RLIM_INFINITY as 2^64-1
# instead of -1, causing semgrep to pass a ~6 EB stack limit and crash semgrep-core (-11).
if [ "$(ulimit -Hs 2>/dev/null || true)" = "unlimited" ]; then
  if ! ulimit -Hs 1048576 2>/dev/null; then
    ulimit -Ss 8192 2>/dev/null || true
    ulimit -Hs 1048576 2>/dev/null || true
  fi
fi

exec "${SEMGREP_CMD[@]}" scan \
  --config p/default \
  --metrics=off \
  --error \
  --exclude-rule yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag \
  "$@"
