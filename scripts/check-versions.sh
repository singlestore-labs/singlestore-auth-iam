#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

latest_v=$(git tag -l 'v[0-9]*' | sed 's/^v//' | sort -V | tail -1)
latest_go=$(git tag -l 'go/v[0-9]*' | sed 's/^go\/v//' | sort -V | tail -1)

err=0
warn() { echo "WARN: $*" >&2; }
fail() { echo "ERROR: $*" >&2; err=1; }

semver_lt() {
  local a=$1 b=$2
  [ "$(printf '%s\n' "$a" "$b" | sort -V | head -1)" = "$a" ] && [ "$a" != "$b" ]
}

# Strict CHANGELOG section check applies on main pushes (and local runs on main).
# PRs may carry [Unreleased] work without a section for the latest tag yet.
is_main_context() {
  if [ "${GITHUB_EVENT_NAME:-}" = "push" ] && [ "${GITHUB_REF:-}" = "refs/heads/main" ]; then
    return 0
  fi
  if [ -z "${GITHUB_EVENT_NAME:-}" ] && [ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")" = "main" ]; then
    return 0
  fi
  return 1
}

[ -n "$latest_v" ] || fail "no v* release tags found"
[ -n "$latest_go" ] || fail "no go/v* tags found"
[ "$latest_v" = "$latest_go" ] || fail "tag mismatch: v${latest_v} vs go/v${latest_go}"

# README: fail only when pinned versions are older than the latest release.
while read -r ver; do
  if semver_lt "$ver" "$latest_v"; then
    fail "README.md pins ${ver}, which is older than latest release ${latest_v}"
  fi
done < <(grep -oE '0\.[0-9]+\.[0-9]+' README.md | grep -v SNAPSHOT | sort -u)

if is_main_context; then
  grep -q "## \\[v${latest_v}\\]" CHANGELOG.md \
    || warn "CHANGELOG.md missing section for v${latest_v}"
fi

py_ver=$(grep -E '^__version__ = ' python/src/s2iam/__init__.py | sed -E 's/.*"([^"]+)".*/\1/')
[ "$py_ver" = "$latest_v" ] \
  || warn "python __init__.py is ${py_ver} (latest release is ${latest_v}; dev placeholder is OK if intentional)"

if [ "$err" -eq 0 ]; then
  echo "OK: release version ${latest_v} (v${latest_v} and go/v${latest_go} aligned)"
fi

exit $err
