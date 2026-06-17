# Releasing

Release versions are defined by **git tags**, not by files in the repo. Java (`pom.xml`) and Python (`__init__.py`) use dev placeholders locally; publish workflows set the real version at release time.

## Overview

1. **Prep PR** — decide the new version and update docs in the repo.
2. **Merge to `main`** — ship the version bump and changelog.
3. **Tag** — create and push release tags (CLI or GitHub Releases UI). Tagging happens **after** merge, not as the first step.

## Checklist

### 1. Prep PR (before merge)

1. Move `[Unreleased]` entries in `CHANGELOG.md` to a new `## [vX.Y.Z] - YYYY-MM-DD` section.
2. Update pinned versions in `README.md` (Maven/Gradle snippets) to match the release.
3. Run `make check-versions` locally (or wait for CI). README pins **newer** than the latest tag are OK on the prep PR; pins **older** than the latest tag fail.
4. Open a PR and merge to `main`.

### 2. Tag and publish (after merge)

Create **both** tags for each aligned release (same semver, different prefixes):

| Tag | When | Effect |
|-----|------|--------|
| `vX.Y.Z` | After merge | Triggers [PyPI](.github/workflows/publish-pypi.yml) and [Maven Central](.github/workflows/publish-maven.yml) publish workflows on tag push |
| `go/vX.Y.Z` | After merge | Go module available on proxy / [pkg.go.dev](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam) |

**Option A — CLI**

```bash
git checkout main && git pull
git tag vX.Y.Z && git push origin vX.Y.Z
git tag go/vX.Y.Z && git push origin go/vX.Y.Z
```

**Option B — GitHub Releases UI**

1. **Releases → New release**, choose tag `vX.Y.Z` (creates the tag on publish).
2. This triggers the PyPI and Maven Central workflows for `v*`.
3. Still create and push the Go tag separately (GitHub Releases does not add `go/v*`):

   ```bash
   git tag go/vX.Y.Z && git push origin go/vX.Y.Z
   ```

Both tags must exist for each aligned release. Order between `v*` and `go/v*` does not matter as long as both land on the merge commit (or a descendant of it).

### 3. Verify artifacts

- Go: [pkg.go.dev](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
- Python: [PyPI](https://pypi.org/project/singlestore-auth-iam/)
- Java: [Maven Central](https://central.sonatype.com/artifact/com.singlestore/s2iam)

## `make check-versions` rules

CI runs `scripts/check-versions.sh` on every push and pull request. The script compares **git tags** (source of truth for releases) against docs in the repo. It is designed to catch forgotten bumps and tag drift, not to block normal prep work.

### When it passes vs fails

| Situation | Expected result |
|-----------|-------------------|
| Any branch/PR: tags aligned, README pins not stale | **Pass** |
| Prep PR: README bumped to `0.6.0`, latest tag still `0.5.0` | **Pass** (ahead-of-tag doc bump is OK) |
| Prep PR: only some README snippets updated (mixed `0.5.0` / `0.6.0`) | **Fail** (inconsistent pins) |
| Any branch/PR: README still shows `0.4.0` but latest tag is `0.5.0` | **Fail** (stale docs) |
| Any branch/PR: `v0.5.0` exists but `go/v0.5.0` missing (or vice versa) | **Fail** |
| PR (not `main`): CHANGELOG has `[Unreleased]` only, no `## [v0.6.0]` yet | **Pass** (section not required until release) |
| `main` push (or local run on `main`): latest tag is `0.5.0` but CHANGELOG has no `## [v0.5.0]` | **Fail** |
| After merge + tag: `main` has CHANGELOG section and README pins match tag | **Pass** |

**It should not fail most of the time.** After the relaxed PR rules (commit `86f395e`), only real drift or mistakes should fail CI. Prep PRs that bump README ahead of tagging are expected to pass.

### Checks performed

| Location / check | Enforced? | Notes |
|------------------|-----------|-------|
| Latest `v*` tag vs latest `go/v*` tag | **Fail** if mismatch | Both tags required for every release |
| `README.md` Maven/Gradle pins (4 snippets) | **Fail** if stale or inconsistent | Must all pin the same semver; may be **newer** than latest tag on prep PRs |
| `CHANGELOG.md` `## [vX.Y.Z]` for latest tag | **Fail** on `main` only | Skipped on PRs so prep work can stay under `[Unreleased]` |
| `python/src/s2iam/__init__.py` `__version__` | **Warn** only | Dev placeholder; publish workflow sets version from tag |
| `java/pom.xml` `<version>` | Not checked | `0.0.1-SNAPSHOT` locally; Maven publish sets version from tag |
| `python/pyproject.toml` | Not checked | Uses `dynamic = ["version"]` from `__init__.py` |
| Go module (`go.mod`) | Not checked | Go modules are versioned by `go/v*` tags |
| `docs/api/openapi.yaml` `info.version` | Not checked | API spec version, not library release semver |
| CHANGELOG footer compare links | Not checked | Update manually in prep PR |
| Language-specific READMEs (`go/`, `python/`, `java/`) | Not checked | No pinned release versions today |

On prep PRs, `[Unreleased]` changelog entries are fine; the script does not require a released section for work that has not shipped to a tag yet.
