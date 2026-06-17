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

CI runs this on every push and pull request. It detects release drift without blocking normal PR work:

| Check | Result |
|-------|--------|
| Latest `v*` and `go/v*` tags differ | **Fail** |
| No release tags found | **Fail** |
| README pins a version **older** than the latest tag | **Fail** (stale docs) |
| README pins a version **newer** than the latest tag | OK (pre-release doc bump on prep PR) |
| CHANGELOG missing `## [vX.Y.Z]` for the latest tag | **Warn** on `main` only; skipped on PRs |
| Python `__version__` differs from latest tag | **Warn** (dev placeholder is expected locally) |

On prep PRs, `[Unreleased]` changelog entries are fine; the script does not require a released section for work that has not shipped to a tag yet.
