# npm Supply-Chain Auditor

Forensic scanner for the self-propagating npm worms of the **Shai-Hulud lineage** —
`Shai-Hulud` (Sep 2025), `Shai-Hulud 2.0` (Nov 2025) and **`ChainDrop` (Aug 2026)**.

Read-only by default. Single PowerShell file. No dependencies, no install, no network calls.

```powershell
.\Invoke-SupplyChainAudit.ps1
```

---

## Why this exists

Antivirus scans files **when they are downloaded**. It does not re-scan a package
that was clean yesterday and got hijacked today. That gap is exactly what these
worms live in: a legitimate, widely-trusted package is republished with a
malicious `preinstall` hook, and the payload runs *before* installation even
completes — so it fires even when `npm install` fails.

ChainDrop reached **452 packages across 2,251 versions**, roughly **2 billion
monthly downloads**, in under four hours.

## What it detects

| # | Check | What it means |
|---|---|---|
| 1 | **Bun runtime** | The payload cannot run without Bun. This is the highest-signal check in the whole tool. |
| 2 | **Payload files** | `setup.mjs`, `setup_bun.js`, `bun_environment.js`, `Math_Symbol.js`, `.truffler-cache`, … |
| 3 | **Compromised versions** | Exact `package@version` pairs from published advisories. |
| 4 | **Editor persistence** | Droppers planted in `.claude/` and `.vscode/` so the worm survives a clean reinstall. |
| 5 | **Install hooks** | `preinstall`/`postinstall` scripts matching worm patterns. |
| 6 | **npm history** | Exfil domains and malicious versions in npm's own logs. |

## The part that actually matters: false positives

Three legitimate files collide by name with ChainDrop's payload. A scanner that
flags them produces noise, gets ignored, and then misses the real thing.

| File | Reality |
|---|---|
| `motion-dom/**/setup.mjs` | framer-motion's gesture helper — 15 lines |
| `regenerate-unicode-properties/**/Math_Symbol.js` | Unicode category data — **1 KB vs the payload's 727,680 bytes** |
| `**/*.xcassets/Contents.json` | Xcode asset catalogs |

The scanner discriminates by **path allowlist plus exact file size**, and reports
cleared matches as `INFO` rather than hiding them — so you can audit the audit.

Every entry above was hit during a real engagement on 2026-08-06 and cleared by hand.

## Output

Console verdict plus two files: a human-readable `.txt` and a machine-readable
`.json` for piping into a SIEM or a CI gate.

```
========================================================================
  VERDICT: CLEAN - no evidence of ChainDrop / Shai-Hulud compromise.
  No credential rotation required on the basis of this scan.
========================================================================
```

## Remediation

`-Remediate` enables removal. It is **opt-in**, asks per item, and requires typing
`yes` — never a blanket delete.

Order matters when a host is compromised. The scanner prints this, and the reason
is not obvious: **remove `gh-token-monitor` before revoking any credential.** It
watches for revocation and fires a malicious handler when it sees one.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `-Path` | profile + `C:\dev`, `C:\src`, … | Roots to scan |
| `-Remediate` | off | Interactive removal |
| `-OutputDir` | Desktop | Report destination |
| `-IncludeCloudMounts` | off | Google Drive / OneDrive mounts are skipped — scanning them forces a full download of every file |

## Extending it for the next campaign

The intel lives in data blocks at the top of the file, not scattered through the
logic. Adding a new advisory is one row:

```powershell
$IOC_Packages = @(
    @{ Name = 'keyv'; Bad = '6.0.0'; Safe = '5.6.0' }
    # ...
)
```

## Prevention beats detection

This tool tells you whether you were hit. It does not stop the next one. For that:

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 3d
```

pnpm then refuses any version published less than three days ago. ChainDrop's
malicious versions were live for under four hours — this setting alone would have
blocked the entire campaign, and the two before it.

## References

- [ChainDrop npm Worm — StepSecurity](https://www.stepsecurity.io/blog/chaindrop-npm-worm)
- [Anatomy of a self-propagating worm — Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/)
- [CHAINDROP worm hits 400+ npm packages — Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain)
- [Shai-Hulud worm compromises npm ecosystem — Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)

## License

MIT
