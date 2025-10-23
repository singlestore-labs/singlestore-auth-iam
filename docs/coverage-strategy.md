## Unified Coverage Strategy

Goal: Produce a single, comprehensible coverage signal for the repository while preserving fast, cloud‑validated tests.

### Principles
1. One authoritative coverage number per language; optionally aggregate for a top‑line repo metric.
2. No artificial tests solely to inflate coverage (avoid flakiness / cost). Real cloud detection paths matter more than synthetic branches.
3. Fail fast on any failure in coverage generation (no best‑effort merging). Aligns with project fail‑fast rule.

### Current State
| Language | Coverage Artifact | Source of Truth |
|----------|-------------------|-----------------|
| Go       | go-coverage-*.out | `go test -coverprofile` on real CSP VMs |
| Python   | (planned) .coverage / XML | pytest with `coverage run` (local + CSP) |
| Java     | jacoco XML (java-coverage-*.xml) | Maven/Gradle test runs on CSP |

### Recommended Workflow
1. Generate per-language coverage in CI matrix (aws, gcp, azure) – each run uploads an artifact.
2. Use a merge script (example skeleton below) on a final aggregation job to:
   - Download artifacts
   - Merge same-language coverage (e.g., Go multi-run) using native tooling
   - Convert all to a common format (LCOV or Cobertura XML)
   - (Optional) Sum line totals for a single repo “blended” ratio, clearly labeling it non-standard.
3. Publish per-language badges; only show blended if stakeholders request it.

### Skeleton Merge Script (pseudo)
```bash
set -euo pipefail
ART_DIR=artifacts
mkdir -p merged

# Go merge (go tool cover doesn't merge; use gocovmerge if added)
gocovmerge ${ART_DIR}/go-coverage-*.out > merged/go-all.out

# Java: merge Jacoco XML (jacoco-cli or report goal if we unify exec files)
# Example: java -jar jacococli.jar merge $(ls ${ART_DIR}/java-coverage-*.exec) --destfile merged/jacoco.exec

# Python: coverage combine
coverage combine ${ART_DIR}/py-*/.coverage*
coverage xml -o merged/python-coverage.xml

# (Optional) Convert all to LCOV using 3rd party tools if needed
```

### Throttling / Retry Considerations
Coverage collection must not introduce extra retries that mask latency issues. Keep detection paths identical; only the test harness adds measurement.

### When NOT to Increase Coverage
If a missing branch represents defensive error handling for external systems (e.g., unexpected metadata HTTP codes), prefer targeted fault injection tests over contrived mocks.

### Next Enhancements
- Add Python coverage invocation in CI similar to Go style.
- Provide a Jacoco merge step if/when multiple Java runs are split per provider.
- Optional aggregated coverage badge generation script.
