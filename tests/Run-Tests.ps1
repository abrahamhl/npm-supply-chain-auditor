$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$AuditScript = Join-Path $RepoRoot "Invoke-SupplyChainAudit.ps1"

Write-Host "--- Running Clean Fixture Test ---"
$CleanRoot = Join-Path $ScriptDir "fixtures/clean"
$CleanDesktop = Join-Path $CleanRoot "Desktop"
if (-not (Test-Path $CleanDesktop)) { New-Item -ItemType Directory -Force -Path $CleanDesktop | Out-Null }

$CleanLocalAppData = Join-Path $CleanRoot "AppData/Local"

& $AuditScript -Path $CleanRoot -TestUserProfile $CleanRoot -TestLocalAppData $CleanLocalAppData

$cleanJson = Get-ChildItem -Path $CleanDesktop -Filter "*.json" | Select-Object -First 1
if (-not $cleanJson) { throw "No JSON output found for clean test." }

$cleanResults = Get-Content $cleanJson.FullName -Raw | ConvertFrom-Json
$criticals = @($cleanResults | Where-Object { $_.Severity -eq 'CRITICAL' })
if ($criticals.Count -gt 0) {
    throw "Expected 0 criticals for clean test, found $($criticals.Count)."
}
Write-Host "Clean test passed!" -ForegroundColor Green


Write-Host "--- Running Malicious Fixture Test ---"
$MaliciousRoot = Join-Path $ScriptDir "fixtures/malicious"
$MaliciousDesktop = Join-Path $MaliciousRoot "Desktop"
if (-not (Test-Path $MaliciousDesktop)) { New-Item -ItemType Directory -Force -Path $MaliciousDesktop | Out-Null }

$MaliciousLocalAppData = Join-Path $MaliciousRoot "AppData/Local"

& $AuditScript -Path $MaliciousRoot -TestUserProfile $MaliciousRoot -TestLocalAppData $MaliciousLocalAppData

$maliciousJson = Get-ChildItem -Path $MaliciousDesktop -Filter "*.json" | Select-Object -First 1
if (-not $maliciousJson) { throw "No JSON output found for malicious test." }

$maliciousResults = Get-Content $maliciousJson.FullName -Raw | ConvertFrom-Json
$criticals = @($maliciousResults | Where-Object { $_.Severity -eq 'CRITICAL' })

$hasBun = $criticals | Where-Object { $_.Check -eq 'Bun' }
$hasPayload = $criticals | Where-Object { $_.Check -eq 'Payload' }
$hasPackage = $criticals | Where-Object { $_.Check -eq 'Package' }
$hasPersistence = $criticals | Where-Object { $_.Check -eq 'Persistence' }
$hasHook = $criticals | Where-Object { $_.Check -eq 'Hook' }
$hasHistory = $criticals | Where-Object { $_.Check -eq 'History' }

if (-not $hasBun) { throw "Expected Bun finding." }
if (-not $hasPayload) { throw "Expected Payload finding." }
if (-not $hasPackage) { throw "Expected Package finding." }
if (-not $hasPersistence) { throw "Expected Persistence finding." }
if (-not $hasHook) { throw "Expected Hook finding." }
if (-not $hasHistory) { throw "Expected History finding." }

Write-Host "Malicious test passed! Found $($criticals.Count) critical findings as expected." -ForegroundColor Green
