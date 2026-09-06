<#
.SYNOPSIS
    Forensic scanner for npm supply-chain worms (ChainDrop / Shai-Hulud family).

.DESCRIPTION
    READ-ONLY BY DEFAULT. This script never deletes, kills or modifies anything
    unless you explicitly pass -Remediate, and even then it asks for confirmation
    per item.

    It hunts for the on-disk artefacts left by the self-propagating npm worms of
    the Shai-Hulud lineage:

      Shai-Hulud   (Sep 2025)  -> bundle.js dropper
      Shai-Hulud 2 (Nov 2025)  -> setup_bun.js + bun_environment.js
      ChainDrop    (Aug 2026)  -> setup.mjs + Math_Symbol.js / math_init.js

    All three share one design: a "preinstall" hook in a hijacked package
    downloads the Bun runtime, then runs an obfuscated payload that harvests
    npm/GitHub tokens, cloud credentials, .env files and AI-tool credentials,
    and republishes itself through the maintainer's stolen tokens.

    KEY INSIGHT this scanner is built around: the payload cannot execute without
    Bun. If Bun is absent from a machine that never installed it deliberately,
    the malware did not run - regardless of what files are lying around.

.PARAMETER Path
    Roots to scan. Defaults to the user profile plus common out-of-profile
    project locations. Network drives and cloud mounts are skipped by default.

.PARAMETER Remediate
    Enables interactive removal of CONFIRMED malicious artefacts. Off by default.

.PARAMETER OutputDir
    Where the report is written. Defaults to the Desktop.

.PARAMETER IncludeCloudMounts
    Also scan mapped cloud drives (Google Drive, OneDrive). Off by default
    because it forces a full download of every file.

.EXAMPLE
    .\Invoke-SupplyChainAudit.ps1
    Read-only audit of the default roots, report written to the Desktop.

.EXAMPLE
    .\Invoke-SupplyChainAudit.ps1 -Path C:\dev, C:\Users\me -Remediate
    Audit those roots and offer to remove confirmed artefacts one by one.

.NOTES
    Author : Abraham Haddioui
    License: MIT
    Refs   : https://www.stepsecurity.io/blog/chaindrop-npm-worm
             https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain
             https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
#>

[CmdletBinding()]
param (
    [string[]] $Path,
    [switch]   $Remediate,
    [string]   $OutputDir = "$env:USERPROFILE\Desktop",
    [switch]   $IncludeCloudMounts,
    # TEST HOOKS: Do not use in production
    [string]   $TestUserProfile,
    [string]   $TestLocalAppData
)

# Setup environment overrides
$resolvedUserProfile = if ($TestUserProfile) { $TestUserProfile } else { $env:USERPROFILE }
$resolvedLocalAppData = if ($TestLocalAppData) { $TestLocalAppData } else { $env:LOCALAPPDATA }

# Overwrite output dir if test user profile is provided and outputdir hasn't been changed explicitly
if ($TestUserProfile -and $OutputDir -eq "$env:USERPROFILE\Desktop") {
    $OutputDir = Join-Path $TestUserProfile "Desktop"
}


$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# IOC DEFINITIONS - edit this block when a new campaign lands.
# Keeping the intel as data (not code) is what makes this reusable.
# ---------------------------------------------------------------------------

# Payload filenames. ExpectedSize (bytes) disambiguates name collisions with
# legitimate packages; $null means "any size is suspicious".
$IOC_Files = @(
    @{ Name = 'setup_bun.js';       Campaign = 'Shai-Hulud 2.0'; Size = $null   }
    @{ Name = 'bun_environment.js'; Campaign = 'Shai-Hulud 2.0'; Size = $null   }
    @{ Name = 'setup.mjs';          Campaign = 'ChainDrop';      Size = $null   }
    @{ Name = 'Math_Symbol.js';     Campaign = 'ChainDrop';      Size = 727680  }
    @{ Name = 'math_init.js';       Campaign = 'ChainDrop';      Size = 727680  }
    @{ Name = 'truffleSecrets.json';   Campaign = 'Shai-Hulud';  Size = $null   }
    @{ Name = 'actionsSecrets.json';   Campaign = 'Shai-Hulud';  Size = $null   }
    @{ Name = 'gh-token-monitor.sh';   Campaign = 'ChainDrop';   Size = $null   }
)

# Directories dropped by the credential harvester.
$IOC_Dirs = @('.truffler-cache', 'gh-token-monitor')

# KNOWN-BENIGN PATH PATTERNS.
# Every one of these was hit during a real audit on 2026-08-06 and manually
# cleared. Without this list the scanner cries wolf and gets ignored - which is
# how real detections get missed.
$Benign = @(
    '\\node_modules\\motion-dom\\',                      # framer-motion gesture helper
    '\\node_modules\\regenerate-unicode-properties\\',   # Unicode category data files
    '\\anaconda3\\pkgs\\',                               # Xcode asset catalogs in test fixtures
    '\\.xcassets\\'
)

# Compromised package@version pairs. Add rows as advisories are published.
$IOC_Packages = @(
    @{ Name = 'keyv';                    Bad = '6.0.0';    Safe = '5.6.0'  }
    @{ Name = 'flat-cache';              Bad = '6.1.24';   Safe = '6.1.23' }
    @{ Name = 'file-entry-cache';        Bad = '11.1.6';   Safe = '11.1.5' }
    @{ Name = 'cacheable';               Bad = '2.5.1';    Safe = '2.5.0'  }
    @{ Name = 'cacheable-request';       Bad = '13.0.20';  Safe = '13.0.19'}
    @{ Name = 'cache-manager';           Bad = '7.2.10';   Safe = '7.2.9'  }
    @{ Name = 'ecto';                    Bad = '5.0.1';    Safe = '5.0.0'  }
    @{ Name = '@cacheable/utils';        Bad = '2.5.1';    Safe = '2.5.0'  }
    @{ Name = '@cacheable/memory';       Bad = '2.2.1';    Safe = '2.2.0'  }
    @{ Name = '@cacheable/node-cache';   Bad = '3.1.2';    Safe = '3.1.1'  }
    @{ Name = '@cacheable/net';          Bad = '2.1.1';    Safe = '2.1.0'  }
)

# Exfiltration endpoints and payload markers, grepped from npm logs.
$IOC_Network = @(
    'npm-cache\.com'
    'thebeautifulmarchoftime'
    '0xE1f2395ee43e45A1556EC6438a88c31B83493103'
)

# ---------------------------------------------------------------------------

function Add-Finding {
    param(
        [ValidateSet('CRITICAL','WARNING','INFO','CLEAR')] [string]$Severity,
        [string]$Check, [string]$Detail, [string]$Target = '', [switch]$Removable
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Check = $Check; Detail = $Detail
        Target = $Target; Removable = [bool]$Removable
    })
    $colour = switch ($Severity) {
        'CRITICAL' { 'Red' }; 'WARNING' { 'Yellow' }; 'CLEAR' { 'Green' }; default { 'Gray' }
    }
    Write-Host ("  [{0,-8}] {1}" -f $Severity, $Detail) -ForegroundColor $colour
}

function Test-Benign {
    param([string]$FullPath)
    foreach ($p in $Benign) { if ($FullPath -match $p) { return $true } }
    return $false
}

function Get-ScanRoots {
    if ($Path) { return $Path | Where-Object { Test-Path -LiteralPath $_ } }
    $candidates = @(
        $resolvedUserProfile, 'C:\dev', 'C:\Abraham_OS', 'C:\projects', 'C:\src', 'C:\repos'
    )
    $roots = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique
    if (-not $IncludeCloudMounts) {
        # Google Drive / OneDrive mounts: scanning them forces a full download.
        $cloud = Get-PSDrive -PSProvider FileSystem |
                 Where-Object { $_.DisplayRoot -or (Test-Path "$($_.Root)Mi unidad") -or (Test-Path "$($_.Root)My Drive") } |
                 Select-Object -ExpandProperty Root
        $roots = $roots | Where-Object { $r = $_; -not ($cloud | Where-Object { $r.StartsWith($_) }) }
    }
    return $roots
}

# ===========================================================================

Write-Host ""
Write-Host "  npm SUPPLY-CHAIN AUDITOR" -ForegroundColor Cyan
Write-Host "  ChainDrop / Shai-Hulud family - READ-ONLY unless -Remediate" -ForegroundColor DarkGray
Write-Host ("  {0}" -f (Get-Date)) -ForegroundColor DarkGray
Write-Host ""

$roots = Get-ScanRoots
Write-Host "Roots to scan:" -ForegroundColor White
$roots | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
Write-Host ""

# --- CHECK 1: Bun runtime -------------------------------------------------
# The single highest-signal check. No Bun == the payload never executed.
Write-Host "[1/6] Bun runtime (the worm's execution prerequisite)" -ForegroundColor White
$bunFound = $false
if ((-not $TestUserProfile) -and (Get-Command bun -ErrorAction SilentlyContinue)) {
    $bunFound = $true
    Add-Finding CRITICAL 'Bun' "Bun is on PATH: $((Get-Command bun).Source)" (Get-Command bun).Source
}
foreach ($bp in @("$resolvedUserProfile\.bun", "$resolvedLocalAppData\bun")) {
    if (Test-Path -LiteralPath $bp) { $bunFound = $true; Add-Finding CRITICAL 'Bun' "Bun install dir present: $bp" $bp -Removable }
}
$staging = Get-ChildItem -LiteralPath $env:TEMP -Force | Where-Object { $_.Name -like 'bun-dl-*' -or $_.Name -like 'tmp.dpkg_*' }
foreach ($s in $staging) { $bunFound = $true; Add-Finding CRITICAL 'Bun' "Dropper staging artefact: $($s.FullName)" $s.FullName -Removable }
if (-not $bunFound) { Add-Finding CLEAR 'Bun' 'Bun absent - the worm payload could not have executed on this host.' }

# --- CHECK 2: payload files ----------------------------------------------
Write-Host "[2/6] Payload files on disk" -ForegroundColor White
$payloadHits = 0
foreach ($ioc in $IOC_Files) {
    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -Filter $ioc.Name -File -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-Benign $_.FullName) {
                Add-Finding INFO 'Payload' "Known-benign, ignored: $($_.FullName)"
                return
            }
            # Size discriminator: the real stage-2 blob is ~727 KB. A 1 KB file
            # with the same name is a coincidence, not a compromise.
            if ($ioc.Size -and $_.Length -ne $ioc.Size) {
                Add-Finding INFO 'Payload' "Name match but wrong size ($($_.Length) B, expected $($ioc.Size)): $($_.FullName)"
                return
            }
            $payloadHits++
            Add-Finding CRITICAL 'Payload' "$($ioc.Campaign) payload: $($_.FullName)" $_.FullName -Removable
        }
    }
}
foreach ($d in $IOC_Dirs) {
    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -Filter $d -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $payloadHits++
            Add-Finding CRITICAL 'Payload' "Harvester cache directory: $($_.FullName)" $_.FullName -Removable
        }
    }
}
if ($payloadHits -eq 0) { Add-Finding CLEAR 'Payload' 'No worm payload files found.' }

# --- CHECK 3: compromised package versions -------------------------------
Write-Host "[3/6] Compromised package versions in node_modules" -ForegroundColor White
$pkgHits = 0
foreach ($root in $roots) {
    foreach ($p in $IOC_Packages) {
        $leaf = ($p.Name -split '/')[-1]
        Get-ChildItem -LiteralPath $root -Recurse -Force -Directory -Filter $leaf -ErrorAction SilentlyContinue |
          Where-Object { $_.Parent.Name -eq 'node_modules' -or $_.Parent.Parent.Name -eq 'node_modules' } |
          ForEach-Object {
            $pj = Join-Path $_.FullName 'package.json'
            if (-not (Test-Path -LiteralPath $pj)) { return }
            try { $m = Get-Content -LiteralPath $pj -Raw | ConvertFrom-Json } catch { return }
            # Authoritative identity check. Matching on directory name alone
            # reports "@cacheable/utils" for any vendored node_modules/*/utils.
            if ($m.name -ne $p.Name) { return }
            $v = $m.version
            if ($v -eq $p.Bad) {
                $pkgHits++
                Add-Finding CRITICAL 'Package' "COMPROMISED $($p.Name)@$v - downgrade to $($p.Safe): $($_.FullName)" $_.FullName
            } else {
                Add-Finding INFO 'Package' "$($p.Name)@$v (safe; malicious is $($p.Bad))"
            }
          }
    }
}
if ($pkgHits -eq 0) { Add-Finding CLEAR 'Package' 'No compromised package versions installed.' }

# --- CHECK 4: editor / agent persistence ---------------------------------
# ChainDrop re-arms itself through Claude Code hooks and VS Code tasks, so a
# clean node_modules is not enough on its own.
Write-Host "[4/6] Editor and AI-agent persistence" -ForegroundColor White
$persistHits = 0
foreach ($root in $roots) {
    Get-ChildItem -LiteralPath $root -Recurse -Force -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -in @('.claude', '.vscode') } | ForEach-Object {
        $drop = Join-Path $_.FullName 'setup.mjs'
        if (Test-Path -LiteralPath $drop) {
            $persistHits++
            Add-Finding CRITICAL 'Persistence' "Dropper planted in editor config: $drop" $drop -Removable
        }
      }
}
foreach ($cfg in @("$resolvedUserProfile\.claude\settings.json", "$resolvedUserProfile\.claude\settings.local.json")) {
    if (-not (Test-Path -LiteralPath $cfg)) { continue }
    $raw = Get-Content -LiteralPath $cfg -Raw
    if ($raw -match 'setup\.mjs|bun_environment|setup_bun') {
        $persistHits++
        Add-Finding CRITICAL 'Persistence' "Agent hook references a dropper: $cfg" $cfg
    }
}
if ($persistHits -eq 0) { Add-Finding CLEAR 'Persistence' 'No dropper persistence in .claude/.vscode configs.' }

# --- CHECK 5: install lifecycle hooks ------------------------------------
Write-Host "[5/6] preinstall/postinstall hooks in dependencies" -ForegroundColor White
$hookHits = 0
foreach ($root in $roots) {
    Get-ChildItem -LiteralPath $root -Recurse -Force -Directory -Filter 'node_modules' -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch '\\node_modules\\.*\\node_modules' } | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -Recurse -Force -Filter 'package.json' -File -ErrorAction SilentlyContinue | ForEach-Object {
            try { $j = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } catch { return }
            if (-not $j.scripts) { return }
            foreach ($k in @('preinstall','postinstall','install')) {
                $s = $j.scripts.$k
                if (-not $s) { continue }
                if ($s -match 'setup\.mjs|setup_bun|bun_environment|curl|Invoke-WebRequest|wget|bun\s+(add|install|run)') {
                    $hookHits++
                    Add-Finding CRITICAL 'Hook' "Suspicious $k in $($j.name): $s" $_.FullName
                }
            }
        }
      }
}
if ($hookHits -eq 0) { Add-Finding CLEAR 'Hook' 'No install hooks matching worm patterns.' }

# --- CHECK 6: npm history -------------------------------------------------
Write-Host "[6/6] npm log history (exfil domains, malicious versions)" -ForegroundColor White
$logDir = "$resolvedLocalAppData\npm-cache\_logs"
if (Test-Path -LiteralPath $logDir) {
    $pattern = ($IOC_Network + ($IOC_Packages | ForEach-Object { "$([regex]::Escape($_.Name))@$([regex]::Escape($_.Bad))" })) -join '|'
    $hits = Select-String -Path "$logDir\*.log" -Pattern $pattern -ErrorAction SilentlyContinue
    if ($hits) { foreach ($h in $hits) { Add-Finding CRITICAL 'History' "npm log hit in $($h.Filename):$($h.LineNumber): $($h.Line.Trim())" } }
    else { Add-Finding CLEAR 'History' 'No exfil domains or malicious versions in npm history.' }
    $last = Get-ChildItem -LiteralPath $logDir -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($last) { Add-Finding INFO 'History' "Most recent npm invocation: $($last.LastWriteTime)" }
} else {
    Add-Finding INFO 'History' 'No npm log directory found.'
}

# ===========================================================================
# VERDICT
# ===========================================================================

$crit = @($script:Findings | Where-Object Severity -eq 'CRITICAL')
Write-Host ""
Write-Host ("=" * 72) -ForegroundColor DarkGray
if ($crit.Count -eq 0) {
    Write-Host "  VERDICT: CLEAN - no evidence of ChainDrop / Shai-Hulud compromise." -ForegroundColor Green
    Write-Host "  No credential rotation required on the basis of this scan." -ForegroundColor Green
} else {
    Write-Host "  VERDICT: $($crit.Count) CRITICAL FINDING(S) - TREAT THIS HOST AS COMPROMISED." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Do this, in this order:" -ForegroundColor Yellow
    Write-Host "   1. Disconnect from the network." -ForegroundColor Yellow
    Write-Host "   2. Remove gh-token-monitor BEFORE revoking anything - it fires a" -ForegroundColor Yellow
    Write-Host "      malicious handler when it sees a token get revoked." -ForegroundColor Yellow
    Write-Host "   3. Rotate, from a DIFFERENT machine: npm tokens, GitHub PATs + SSH" -ForegroundColor Yellow
    Write-Host "      keys, AWS/GCP/Azure keys, Vault tokens, AI-tool credentials." -ForegroundColor Yellow
    Write-Host "   4. Audit CloudTrail / GitHub audit log for the exposure window." -ForegroundColor Yellow
    Write-Host "   5. Check github.com for repos you did not create." -ForegroundColor Yellow
}
Write-Host ("=" * 72) -ForegroundColor DarkGray

# --- report files ---------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$txt  = Join-Path $OutputDir "supply-chain-audit-$stamp.txt"
$json = Join-Path $OutputDir "supply-chain-audit-$stamp.json"

$header = @(
    "npm SUPPLY-CHAIN AUDIT - $(Get-Date)"
    "Host: $env:COMPUTERNAME   User: $env:USERNAME"
    "Roots: $($roots -join '; ')"
    "Verdict: $(if ($crit.Count -eq 0) { 'CLEAN' } else { "$($crit.Count) CRITICAL" })"
    ''
)
$header + ($script:Findings | Format-Table Severity, Check, Detail -AutoSize -Wrap | Out-String) |
    Out-File -FilePath $txt -Encoding UTF8
$script:Findings | ConvertTo-Json -Depth 4 | Out-File -FilePath $json -Encoding UTF8

Write-Host ""
Write-Host "Report: $txt"  -ForegroundColor Cyan
Write-Host "JSON:   $json" -ForegroundColor Cyan

# --- remediation (opt-in, per-item confirmation) --------------------------
if ($Remediate) {
    $removable = @($script:Findings | Where-Object { $_.Severity -eq 'CRITICAL' -and $_.Removable -and $_.Target })
    if ($removable.Count -eq 0) {
        Write-Host ""
        Write-Host "Nothing safely auto-removable. Remaining findings need manual review." -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "REMEDIATION - each item asks separately. Ctrl+C aborts." -ForegroundColor Red
        foreach ($r in $removable) {
            Write-Host ""
            Write-Host "  Target: $($r.Target)" -ForegroundColor White
            $a = Read-Host "  Delete this? (yes/NO)"
            if ($a -eq 'yes') {
                Remove-Item -LiteralPath $r.Target -Recurse -Force -Confirm:$false
                if (Test-Path -LiteralPath $r.Target) { Write-Host "  FAILED - still present." -ForegroundColor Red }
                else { Write-Host "  Removed." -ForegroundColor Green }
            } else { Write-Host "  Skipped." -ForegroundColor DarkGray }
        }
    }
}

Write-Host ""
