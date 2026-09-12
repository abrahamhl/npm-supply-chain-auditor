# SRE & Observability Audit

## Perspective: Staff Site Reliability Engineer
**Focus:** CI pipeline integration, deterministic execution.

### Findings
1. **CI Integration:** Tool needs to exit with code 1 if malicious findings occur, to break builds.
2. **Determinism:** Tests run entirely offline using synthetic datasets, avoiding flaky network calls to NPM registry.

### Action Items
- [x] Created offline fixture sets (clean vs malicious) to guarantee CI stability.
