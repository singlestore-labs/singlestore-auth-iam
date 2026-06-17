# Releasing

Release versions are defined by **git tags**, not by files in the repo. Java (`pom.xml`) and Python (`__init__.py`) use dev placeholders locally; publish workflows set the real version at release time.

## Checklist

1. Move `[Unreleased]` entries in `CHANGELOG.md` to a new `## [vX.Y.Z] - YYYY-MM-DD` section.
2. Update pinned versions in `README.md` (Maven/Gradle snippets) to match the release.
3. Run `make check-versions` locally (or wait for CI).
4. Push **both** tags (same semver, different prefixes):
   ```bash
   git tag go/vX.Y.Z && git push origin go/vX.Y.Z
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```
5. Verify artifacts:
   - Go: [pkg.go.dev](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
   - Python: [PyPI](https://pypi.org/project/singlestore-auth-iam/)
   - Java: [Maven Central](https://central.sonatype.com/artifact/com.singlestore/s2iam)

## Tag conventions

| Tag | Effect |
|-----|--------|
| `go/vX.Y.Z` | Go module on proxy / pkg.go.dev |
| `vX.Y.Z` | Triggers PyPI and Maven Central publish workflows |

Both tags must exist for each aligned release. `make check-versions` fails if the latest `v*` and `go/v*` tags differ.
