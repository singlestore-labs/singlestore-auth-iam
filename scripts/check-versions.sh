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

# Release flow: prep PR bumps CHANGELOG/README, merge to main, then tag v* and go/v*.
# Strict CHANGELOG section check applies on main pushes (and local runs on main).
# Prep PRs may carry [Unreleased] work and README pins newer than the latest tag.
is_main_context() {
  if [ "${GITHUB_EVENT_NAME:-}" = "push" ] && [ "${GITHUB_REF:-}" = "refs/heads/main" ]; then
    return 0
  fi
  if [ -z "${GITHUB_EVENT_NAME:-}" ] && [ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")" = "main" ]; then
    return 0
  fi
  return 1
}

# Maven/Gradle dependency pins in the root README (0.x.y semver only).
readme_pins() {
  grep -oE '0\.[0-9]+\.[0-9]+' README.md | grep -v SNAPSHOT | sort -u
}

[ -n "$latest_v" ] || fail "no v* release tags found"
[ -n "$latest_go" ] || fail "no go/v* tags found"
[ "$latest_v" = "$latest_go" ] || fail "tag mismatch: v${latest_v} vs go/v${latest_go}"

# README: all Maven/Gradle pins must agree with each other.
mapfile -t readme_pin_list < <(readme_pins)
if [ "${#readme_pin_list[@]}" -gt 1 ]; then
  fail "README.md has inconsistent pins: ${readme_pin_list[*]}"
fi

# README: fail when pinned versions are older than the latest tag; newer pins are OK on prep PRs.
for ver in "${readme_pin_list[@]}"; do
  if semver_lt "$ver" "$latest_v"; then
    fail "README.md pins ${ver}, which is older than latest release ${latest_v}"
  fi
done

if is_main_context; then
  grep -q "## \\[v${latest_v}\\]" CHANGELOG.md \
    || fail "CHANGELOG.md missing section for v${latest_v}"
fi

py_ver=$(grep -E '^__version__ = ' python/src/s2iam/__init__.py | sed -E 's/.*"([^"]+)".*/\1/')
[ "$py_ver" = "$latest_v" ] \
  || warn "python __init__.py is ${py_ver} (latest release is ${latest_v}; dev placeholder is OK if intentional)"

if [ "$err" -eq 0 ]; then
  echo "OK: release version ${latest_v} (v${latest_v} and go/v${latest_go} aligned)"
fi

exit $err
