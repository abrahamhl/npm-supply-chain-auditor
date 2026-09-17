# Recruiter Evidence

This document maps the claims made in the project to exact code and test evidence. It is intended for technical recruiters and hiring managers evaluating Abraham Haddioui.

| Claim | Exact Code/Test Evidence | What it Proves | Target Role | Limitation |
|---|---|---|---|---|
| **Incident Response Automation** | `Invoke-SupplyChainAudit.ps1` logic (IOC extraction, cross-referencing dependencies, hooks, and npm logs). | Understanding of how to script targeted forensic evidence gathering quickly. | Supply-chain security, DevTools | It relies on known IOCs; it is not zero-day detection. |
| **Safe Execution & Opt-in Remediation** | `-Remediate` switch with `Read-Host` confirmation and `Test-Path` checks before any deletion. | Commitment to safety when operating on developer machines; preventing accidental data loss. | Developer productivity, DevTools | Automation of remediation is deliberately constrained. |
| **Deterministic Testing** | `tests/Run-Tests.ps1` and synthetic fixtures (`tests/fixtures/clean/`, `tests/fixtures/malicious/`). | Ability to create deterministic, reproducible test environments without relying on real compromised systems. | DevTools, CI/CD, Supply-chain security | Tests rely on mocked paths; environmental differences may exist in the wild. |
| **CI Integration** | `.github/workflows/ci.yml` triggering `pwsh` on tests. | Knowledge of modern CI/CD pipelines and automated verifications for PowerShell tools. | Developer productivity, CI/CD | Tests run on Linux runners, while real target is usually Windows (though PS Core is cross-platform). |
| **False Positive Mitigation** | Size checks against known legitimate payloads (`$ioc.Size` check) and `Test-Benign` path allowlist. | Real-world experience with security scanners where false positives cause alert fatigue. | Security tooling, DevTools | Hardcoded sizes and paths require maintenance as legitimate tools update. |
