# Engineering Case Study: Supply Chain Auditor

## 1. CURRENT TRUTH
When a supply-chain attack hits (like the ChainDrop / Shai-Hulud npm worm), engineers scramble to determine if their machines are compromised. Writing a quick shell script to find `setup.mjs` is easy, but it quickly yields hundreds of false positives, eroding trust in the tool and leading engineers to ignore actual threats. Furthermore, embedding IOCs directly in the script makes it hard to maintain and version control as the threat evolves.

## 2. CHANGES
To transform this script into a robust, defensible forensic tool:
- Decoupled IOCs (Indicators of Compromise) from the PowerShell logic, storing them in a versioned `ioc_dataset.json`.
- Implemented a structured JSON reporting schema to integrate with SIEM or IT ticket automation, logging exactly why a file was flagged, the scanner version, and confidence levels.
- Created fully synthetic, safe test fixtures (`tests/fixtures`) that emulate the directory structures of both clean and compromised states without containing actual malware.
- Implemented deterministic PowerShell Pester-style tests in `tests/Run-Tests.ps1` to assert that the scanner finds exactly what it should, and nothing it shouldn't.

## 3. TEST EVIDENCE
The tests validate:
- **Clean Fixture:** The scanner correctly ignores benign files, properly uses the `$Benign` allowlist, and returns zero critical alerts.
- **Malicious Fixture:** The scanner identifies the fake `bun` runtime, the `setup.mjs` dropper, the compromised `keyv` package version, the agent persistence in `.claude/settings.json`, and the malicious `npm` log entries, correctly returning 6 critical alerts.

## 4. ARCHITECTURE DECISIONS
- **Why PowerShell?** It's ubiquitous on Windows and natively parses JSON without requiring external dependencies like `jq`. For cross-platform support, PowerShell Core is easily available.
- **Why JSON configuration?** Separating the intel from the execution logic allows security analysts to update the IOC dataset without touching the underlying PowerShell script. It prevents logic regressions when simply adding a new known-bad filename.
- **Explicit Remediation:** We chose to make remediation interactive and opt-in rather than automatic. Automatically deleting files identified by heuristics is a recipe for system corruption if a false positive slips through.

## 5. INTERVIEW DEFENSE
**"Why spend time on false-positive policies when dealing with a critical worm?"**
*Because security tools lose value when false positives train operators to ignore them. If an engineer runs a script and sees 50 'CRITICAL' alerts that turn out to be legitimate files, they will assume the tool is broken and miss the 1 actual piece of malware. By prioritizing confidence (e.g. knowing the payload requires `bun` to run), we provide high-signal, actionable intelligence.*

**"Why didn't you write this in Go or Rust for speed?"**
*Forensic sweeps like this are usually distributed via MDM (like Intune or Jamf) immediately following an incident disclosure. Requiring IT to push a compiled binary creates friction and requires security review of the binary itself. A readable PowerShell script can be reviewed, approved, and executed across an organization in minutes.*
