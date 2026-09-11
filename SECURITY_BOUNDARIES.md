# Security Boundaries

## Safe Execution Guarantee
This auditor operates strictly under a "Do No Harm" constraint. 
1. **Read-Only by Default:** The script will never modify, quarantine, or delete a file unless the `-Remediate` flag is explicitly passed.
2. **Opt-In Remediation:** Even with `-Remediate` active, the script pauses and asks for explicit `yes/NO` console confirmation before deleting any single artifact.
3. **No Execution:** The script parses JSON files (`package.json`, `.vscode/settings.json`) but uses `ConvertFrom-Json`. It never `eval`s, sources, or executes any code found on disk.
4. **Symlink Safety:** It uses PowerShell's `-LiteralPath` and explicitly avoids following malicious reparse points that could direct deletions to critical system files.

## Testing Boundary
Our automated test suite (`tests/Run-Tests.ps1`) uses purely synthetic, benign text files named to match IOCs (e.g. creating an empty `setup.mjs`). We **never** embed actual malicious payloads, live malware, or obfuscated droppers in this repository to prevent triggering corporate EDRs or accidentally infecting contributors.
