<#
.SYNOPSIS
    Entra ID Stale Device Lifecycle Management — Report, Disable, Delete

.DESCRIPTION
    Three-stage lifecycle for stale devices in Microsoft Entra ID (Azure AD).
    Stage 1: REPORT — Identify stale devices, export CSV. No action taken.
    Stage 2: DISABLE — Disable devices that have been stale beyond the grace period.
    Stage 3: DELETE — Remove devices that have been disabled beyond the hold period.

    Default mode is DRY-RUN. No changes are made without explicit -Execute flag.
    Delete requires BOTH -Execute AND -DeleteEnabled flags.

    All configurable variables are at the top of the script in the USER CONFIGURATION
    region. Adjust them to match your environment before running.

.PARAMETER Execute
    Enable actual disable/delete operations. Without this, script runs in report-only mode.

.PARAMETER DeleteEnabled
    Enable delete operations for devices past the disable hold period. Requires -Execute.

.PARAMETER SendEmail
    Send an HTML summary email after the run completes. Requires Mail.Send permission
    on the App Registration and a configured sender/recipient in the EMAIL section.

.PARAMETER StaleThreshold
    Days of inactivity before a device is considered stale. Default: 90

.PARAMETER GracePeriod
    Days a device must remain on the stale report before eligible for disable. Default: 30

.PARAMETER DisableHold
    Days a device must remain disabled before eligible for deletion. Default: 60

.PARAMETER ReportPath
    Directory for CSV reports and logs. Default: .\reports

.PARAMETER ExclusionFile
    Path to CSV of devices to never touch. Default: .\exclusions.csv

.EXAMPLE
    # Dry-run — report only, no changes (default for testing)
    .\Azure_Stale_Data.ps1

.EXAMPLE
    # Execute disable operations
    .\Azure_Stale_Data.ps1 -Execute

.EXAMPLE
    # Execute disable AND delete, send email summary
    .\Azure_Stale_Data.ps1 -Execute -DeleteEnabled -SendEmail

.NOTES
    Author:  Mitchell Brown
    Version: 2.0
    Requires: PowerShell 7+ and Microsoft.Graph module v2.0+
    License: MIT — Use at your own risk. No warranty expressed or implied.
             The author is not responsible for any damage, data loss, or
             unintended device modifications resulting from use of this script.
             Always test with dry-run mode before enabling execution.

    Auth Setup:
    1. Create App Registration in Entra ID
    2. Grant API permissions: Device.Read.All, Device.ReadWrite.All, Directory.Read.All
       (add Mail.Send if using -SendEmail)
    3. Create a client secret on the App Registration
    4. Update USER CONFIGURATION region with TenantId, ClientId, ClientSecret
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Execute,
    [switch]$DeleteEnabled,
    [switch]$SendEmail,

    [int]$StaleThreshold = 90,
    [int]$GracePeriod = 30,
    [int]$DisableHold = 60,

    [string]$ReportPath = (Join-Path $PSScriptRoot "reports"),
    [string]$ExclusionFile = (Join-Path $PSScriptRoot "exclusions.csv")
)

#region ===== USER CONFIGURATION =====
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │  EVERYTHING YOU NEED TO CUSTOMIZE IS IN THIS SECTION                        │
# │  Adjust these variables to match YOUR environment before first run.         │
# │  The rest of the script should not need modification.                       │
# └─────────────────────────────────────────────────────────────────────────────┘

$ErrorActionPreference = 'Stop'
$dateStamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$today = Get-Date

# ─── AUTHENTICATION ──────────────────────────────────────────────────────────
# Create an App Registration in Entra ID and populate these values.
# If left as placeholders, the script falls back to interactive browser auth
# (useful for local testing — just run Connect-MgGraph first).
#
# For Azure Key Vault retrieval, replace the ClientSecret line with:
#   $authConfig.ClientSecret = (Get-AzKeyVaultSecret -VaultName "YourVault" -Name "SecretName" -AsPlainText)

$authConfig = @{
    TenantId     = "YOUR_TENANT_ID"          # e.g., "contoso.onmicrosoft.com" or GUID
    ClientId     = "YOUR_APP_CLIENT_ID"      # App Registration Application (client) ID
    ClientSecret = "YOUR_CLIENT_SECRET"      # App Registration client secret value
}

# ─── TARGET DEVICE TYPES ─────────────────────────────────────────────────────
# Which operating systems should this script evaluate for staleness?
# Add or remove entries to control scope. Common values:
#   "Windows"   — Windows desktops/laptops
#   "macOS"     — Apple Mac computers
#   "Android"   — Android phones/tablets
#   "iOS"       — iPhones
#   "iPadOS"    — iPads (some tenants report as "iOS" — include both if unsure)
#   "Linux"     — Linux workstations
#
# Only devices matching these OS values will be evaluated.
# Everything else is ignored entirely.

$targetOS = @(
    # "Windows"    # Uncomment to include Windows devices
    # "macOS"      # Uncomment to include Mac devices
     "Android"    # Uncomment to include Android devices
     "iOS"        # Uncomment to include iPhones
     "iPadOS"     # Uncomment to include iPads
    # "Linux"      # Uncomment to include Linux workstations
)

# ─── DEVICE TRUST TYPES ──────────────────────────────────────────────────────
# Controls which join types are in scope. This determines whether you're
# targeting corporate-managed devices, personal/BYOD, or both.
#
# Trust Type Values:
#   "AzureAd"   — Azure AD Joined (corporate cloud-managed devices)
#   "ServerAd"  — Hybrid Azure AD Joined (domain-joined + cloud-registered)
#   "Workplace" — Azure AD Registered (personal/BYOD devices)
#
# DEFAULT: Corporate only. Add "Workplace" if you want to include BYOD.
# WARNING: Including "Workplace" means personal devices will be subject to
#          disable/delete lifecycle. Make sure that's what you want.

$corporateTrustTypes = @(
    "AzureAd"      # Cloud-joined corporate devices
    "ServerAd"     # Hybrid-joined corporate devices
    # "Workplace"  # Uncomment to include personal/BYOD devices
)

# ─── NAME PATTERN EXCLUSIONS (Built-in Filter) ───────────────────────────────
# These patterns catch devices by naming convention that should NEVER be touched.
# Common use: servers, infrastructure, VDI hosts, lab machines.
#
# WHY THIS EXISTS: The exclusions.csv is great for quick one-off additions,
# but name patterns catch entire CLASSES of devices automatically — even new
# ones that haven't been added to the CSV yet. Use both together for defense
# in depth, or disable either one independently.
#
# Uses wildcard matching (* = any characters). Add your org's naming patterns.
# Set $enableNamePatternExclusions = $false to disable this filter entirely.

$enableNamePatternExclusions = $true

$excludedNamePatterns = @(
    # --- Servers / Infrastructure (customize to YOUR naming convention) ---
    "SRV-*"           # Example: servers prefixed with SRV-
    "*-DC*"           # Example: domain controllers
    "*-SQL*"          # Example: SQL servers
    "*-FS*"           # Example: file servers
    # --- Virtual Desktop / VDI ---
    "AVD-*"           # Example: Azure Virtual Desktop hosts
    "VDI-*"           # Example: VDI machines
    # --- Lab / Test ---
    "*-TEST*"         # Example: test machines
    "*-DEV*"          # Example: dev machines
    "*-LAB*"          # Example: lab machines
)

# ─── OS-BASED SERVER EXCLUSIONS ──────────────────────────────────────────────
# Catches servers by their OS name or build number, regardless of device name.
# This is a safety net — even if a server has an unexpected name, it won't
# slip through if its OS identifies it as a server edition.

$excludedOSPatterns = @("*Server*", "*Datacenter*")

# Known server OS build numbers (e.g., 20348 = Windows Server 2022)
$excludedOSVersionPatterns = @("*20348*")

# ─── CSV EXCLUSION FILE ──────────────────────────────────────────────────────
# The exclusions.csv provides a way to protect specific devices by their Object ID.
# Use this for one-off exceptions: conference rooms, seasonal equipment, shared
# devices, or anything that legitimately goes inactive but shouldn't be touched.
#
# WHY BOTH? Name patterns catch classes of devices automatically. The CSV catches
# specific individual devices that don't fit a pattern. Together they form a
# layered exclusion system. You can use one, both, or neither.
#
# Set $enableCsvExclusions = $false to skip the CSV file entirely.
# File format: DeviceId,DisplayName,Reason (see exclusions.csv for examples)

$enableCsvExclusions = $false

# ─── REPORT RETENTION / CLEANUP ──────────────────────────────────────────────
# Automatically clean up old report files to prevent folder bloat.
# Set $enableReportRetention = $true to turn on cleanup.
# $reportRetentionDays controls how old a file must be before deletion.
#
# Common values:
#   7   = Keep one week of reports
#   14  = Keep two weeks
#   30  = Keep one month (default)
#   90  = Keep three months

$enableReportRetention = $true
$reportRetentionDays = 30

# ─── GRAPH API BATCH CONFIGURATION ───────────────────────────────────────────
# The script sends disable/delete requests in batches to the Graph API.
# These settings control batch behavior — tune them based on your tenant size
# and throttling tolerance.
#
# BatchSize: How many requests per batch (Graph API max is 20)
# MaxRetries: How many times to retry a failed batch before giving up
# PauseBetweenBatchesMs: Milliseconds to wait between batches (throttle prevention)
#
# Conservative (large tenants, cautious): BatchSize=10, Pause=500
# Balanced (most environments):          BatchSize=20, Pause=200
# Aggressive (small tenants, fast):       BatchSize=20, Pause=100

$batchConfig = @{
    BatchSize              = 20      # Requests per batch (max 20 per Graph API limit)
    MaxRetries             = 3       # Retry attempts for transient failures (429, 503, 504)
    PauseBetweenBatchesMs  = 200     # Milliseconds between batches to avoid throttling
}

# ─── EMAIL NOTIFICATION (Optional) ───────────────────────────────────────────
# Sends an HTML summary email after each run. OFF by default.
# To enable: pass -SendEmail flag when running the script.
#
# Requirements:
#   - Mail.Send permission granted to the App Registration
#   - A valid sender mailbox (licensed user or shared mailbox)
#
# This feature is completely isolated — if misconfigured or if Mail.Send
# permission is missing, it logs a warning and the rest of the script
# completes normally. It will never block the core lifecycle operations.

$emailConfig = @{
    Sender     = "yourserviceaccount@yourdomain.com"    # From address
    Recipients = @("admin@yourdomain.com")              # Who gets the summary
    Subject    = "Entra ID Stale Device Report — $($today.ToString('yyyy-MM-dd'))"
}

# ─── LIFECYCLE THRESHOLDS (calculated — do not edit) ─────────────────────────
$staleDate           = $today.AddDays(-$StaleThreshold)
$disableEligibleDate = $today.AddDays(-($StaleThreshold + $GracePeriod))
$deleteEligibleDate  = $today.AddDays(-($StaleThreshold + $GracePeriod + $DisableHold))

# ─── MINIMUM MODULE VERSION ──────────────────────────────────────────────────
$requiredModuleVersion = [version]"2.0.0"

#endregion

#region ===== FUNCTIONS =====

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "ACTION", "DRYRUN")]
        [string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(switch ($Level) {
        "ERROR"  { "Red" }
        "WARN"   { "Yellow" }
        "ACTION" { "Green" }
        "DRYRUN" { "Cyan" }
        default  { "White" }
    })
    $script:runLog += @{ Timestamp = $timestamp; Level = $Level; Message = $Message }
}

function Test-IsServer {
    param([string]$OperatingSystem, [string]$OSVersion, [string]$DisplayName)

    # Check OS name patterns (e.g., "Windows Server 2022")
    foreach ($p in $excludedOSPatterns) {
        if ($OperatingSystem -like $p -or $OSVersion -like $p) { return $true }
    }
    # Check OS build number patterns (e.g., build 20348 = Server 2022)
    foreach ($p in $excludedOSVersionPatterns) {
        if ($OSVersion -like $p) { return $true }
    }
    # Check device name patterns (if enabled)
    if ($enableNamePatternExclusions) {
        foreach ($p in $excludedNamePatterns) {
            if ($DisplayName -like $p) { return $true }
        }
    }
    return $false
}

function Test-IsExcluded {
    param([string]$DeviceObjectId)
    if (-not $enableCsvExclusions) { return $false }
    if (-not $script:exclusionList) { return $false }
    return ($script:exclusionList.DeviceId -contains $DeviceObjectId)
}

function Get-ExclusionReason {
    param([string]$DeviceObjectId)
    if (-not $script:exclusionList) { return "N/A" }
    $entry = $script:exclusionList | Where-Object { $_.DeviceId -eq $DeviceObjectId }
    if ($entry) { return $entry.Reason }
    return "N/A"
}

function Get-DeviceOwnerName {
    param([object]$Device)
    # RegisteredOwners is expanded as a navigation property from Graph
    $owners = $Device.RegisteredOwners
    if ($owners -and $owners.Count -gt 0) {
        $ownerNames = foreach ($owner in $owners) {
            $props = $owner.AdditionalProperties
            if ($props -and $props.ContainsKey('displayName')) {
                $props['displayName']
            } elseif ($props -and $props.ContainsKey('userPrincipalName')) {
                $props['userPrincipalName']
            }
        }
        return ($ownerNames -join "; ")
    }
    return ""
}

function Export-Report {
    param([array]$Data, [string]$FileName)
    if ($Data.Count -eq 0) {
        Write-Log "No data to export for $FileName" -Level "INFO"
        return $null
    }
    $filePath = Join-Path $ReportPath "$($FileName)_$dateStamp.csv"
    $Data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($Data.Count) records to: $filePath" -Level "INFO"
    return $filePath
}

function Invoke-ReportRetention {
    <#
    .SYNOPSIS
        Cleans up report files older than the configured retention period.
    .DESCRIPTION
        Scans the report directory for CSV and JSON files older than
        $reportRetentionDays and removes them. Only runs if
        $enableReportRetention is $true.
    #>
    if (-not $enableReportRetention) {
        Write-Log "Report retention is DISABLED — skipping cleanup" -Level "INFO"
        return
    }
    if (-not (Test-Path $ReportPath)) { return }

    $cutoffDate = $today.AddDays(-$reportRetentionDays)
    $oldFiles = @(Get-ChildItem -Path $ReportPath -Include "*.csv", "*.json" -Recurse |
        Where-Object { $_.LastWriteTime -lt $cutoffDate })

    if ($oldFiles.Count -eq 0) {
        Write-Log "Report retention: No files older than $reportRetentionDays days" -Level "INFO"
        return
    }

    Write-Log "Report retention: Removing $($oldFiles.Count) file(s) older than $reportRetentionDays days" -Level "INFO"
    foreach ($file in $oldFiles) {
        try {
            Remove-Item -Path $file.FullName -Force
            Write-Log "  Removed: $($file.Name)" -Level "INFO"
        } catch {
            Write-Log "  Failed to remove $($file.Name): $($_.Exception.Message)" -Level "WARN"
        }
    }
}

function Invoke-GraphBatch {
    <#
    .SYNOPSIS
        Sends Graph API requests in JSON batches of up to $batchConfig.BatchSize.
    .DESCRIPTION
        Accepts an array of request objects (id, method, url, optional body/headers),
        splits them into configurable batches, submits each via the $batch endpoint,
        and returns per-request results with success/failure status.

        Includes retry logic for transient failures (429, 503, 504).

        Batch behavior is controlled by the $batchConfig hashtable in the
        USER CONFIGURATION section:
          - BatchSize: requests per batch (max 20)
          - MaxRetries: retry attempts for failed batches
          - PauseBetweenBatchesMs: delay between batches to prevent throttling
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Requests
    )

    $BatchSize = $batchConfig.BatchSize
    $MaxRetries = $batchConfig.MaxRetries
    $PauseBetweenBatchesMs = $batchConfig.PauseBetweenBatchesMs

    $totalBatches = [Math]::Ceiling($Requests.Count / $BatchSize)
    $allResults = [System.Collections.Generic.List[object]]::new()
    $successCount = 0
    $failCount = 0

    Write-Log "Graph Batch: $($Requests.Count) requests in $totalBatches batch(es) [size=$BatchSize, retries=$MaxRetries, pause=${PauseBetweenBatchesMs}ms]" -Level "INFO"

    for ($i = 0; $i -lt $totalBatches; $i++) {
        $start = $i * $BatchSize
        $end = [Math]::Min($start + $BatchSize - 1, $Requests.Count - 1)
        $currentBatch = $Requests[$start..$end]

        $batchBody = @{ requests = $currentBatch } | ConvertTo-Json -Depth 10 -Compress

        $attempt = 0
        $batchSuccess = $false

        while (-not $batchSuccess -and $attempt -lt $MaxRetries) {
            $attempt++
            try {
                $response = Invoke-MgGraphRequest -Method POST `
                    -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                    -Body $batchBody -ContentType "application/json" -ErrorAction Stop

                foreach ($result in $response.responses) {
                    $reqId = $result.id
                    $originalReq = $currentBatch | Where-Object { $_.id -eq $reqId }

                    if ($result.status -ge 400) {
                        $errorMsg = if ($result.body.error) { $result.body.error.message } else { "HTTP $($result.status)" }

                        if ($result.status -in @(429, 503, 504) -and $attempt -lt $MaxRetries) {
                            continue
                        }

                        $allResults.Add([PSCustomObject]@{
                            Id      = $reqId
                            Status  = $result.status
                            Success = $false
                            Error   = $errorMsg
                            Url     = $originalReq.url
                        })
                        $failCount++
                    } else {
                        $allResults.Add([PSCustomObject]@{
                            Id      = $reqId
                            Status  = $result.status
                            Success = $true
                            Error   = $null
                            Url     = $originalReq.url
                        })
                        $successCount++
                    }
                }
                $batchSuccess = $true

            } catch {
                if ($attempt -lt $MaxRetries) {
                    $retryDelay = $attempt * 2
                    Write-Log "Batch $($i+1) attempt $attempt failed: $($_.Exception.Message). Retrying in ${retryDelay}s..." -Level "WARN"
                    Start-Sleep -Seconds $retryDelay
                } else {
                    Write-Log "Batch $($i+1) FAILED after $MaxRetries attempts: $($_.Exception.Message)" -Level "ERROR"
                    foreach ($req in $currentBatch) {
                        $allResults.Add([PSCustomObject]@{
                            Id      = $req.id
                            Status  = 0
                            Success = $false
                            Error   = "Batch submission failed: $($_.Exception.Message)"
                            Url     = $req.url
                        })
                        $failCount++
                    }
                }
            }
        }

        # Pause between batches to avoid throttling
        if ($i -lt ($totalBatches - 1)) {
            Start-Sleep -Milliseconds $PauseBetweenBatchesMs
        }
    }

    Write-Log "Graph Batch complete: $successCount succeeded, $failCount failed" -Level "INFO"
    return $allResults
}

function Send-SummaryEmail {
    param([hashtable]$Summary)

    $mode = if ($Execute) { "EXECUTE" } else { "DRY-RUN" }
    $deleteStatus = if ($DeleteEnabled) { "Enabled" } else { "Disabled" }

    $html = @"
<html>
<head><style>
    body { font-family: Segoe UI, Arial, sans-serif; font-size: 14px; color: #333; }
    h2 { color: #0078D4; margin-bottom: 5px; }
    table { border-collapse: collapse; width: 100%; margin-top: 10px; }
    th { background-color: #0078D4; color: white; padding: 8px; text-align: left; }
    td { padding: 8px; border-bottom: 1px solid #ddd; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    .summary-box { background: #f0f6ff; border-left: 4px solid #0078D4; padding: 12px; margin: 10px 0; }
    .warn { color: #D83B01; font-weight: bold; }
</style></head>
<body>
<h2>Entra ID Stale Device Report</h2>
<p>Run completed: <strong>$($today.ToString('yyyy-MM-dd HH:mm:ss'))</strong> | Mode: <strong>$mode</strong> | Delete: <strong>$deleteStatus</strong></p>

<div class="summary-box">
<strong>Summary</strong><br/>
Total in-scope devices: $($Summary.TotalInScope)<br/>
Stale devices found: $($Summary.StaleFound)<br/>
Report-only (within grace): $($Summary.ReportOnly)<br/>
Eligible for disable: $($Summary.DisableEligible)<br/>
Eligible for delete: $($Summary.DeleteEligible)<br/>
Excluded (protected): $($Summary.Excluded)<br/>
Devices disabled this run: <span class="warn">$($Summary.Disabled)</span><br/>
Devices deleted this run: <span class="warn">$($Summary.Deleted)</span><br/>
Failures: $($Summary.Failures)
</div>

<h3>Parameters</h3>
<table>
<tr><th>Parameter</th><th>Value</th></tr>
<tr><td>Stale Threshold</td><td>$StaleThreshold days</td></tr>
<tr><td>Grace Period</td><td>$GracePeriod days</td></tr>
<tr><td>Disable Hold</td><td>$DisableHold days</td></tr>
<tr><td>Target OS</td><td>$($targetOS -join ', ')</td></tr>
</table>

<p><em>Full CSV reports saved to: $ReportPath</em></p>
</body></html>
"@

    $message = @{
        Message = @{
            Subject = $emailConfig.Subject
            Body    = @{ ContentType = "HTML"; Content = $html }
            ToRecipients = @(
                foreach ($r in $emailConfig.Recipients) {
                    @{ EmailAddress = @{ Address = $r } }
                }
            )
        }
        SaveToSentItems = $false
    }

    try {
        Send-MgUserMail -UserId $emailConfig.Sender -BodyParameter $message
        Write-Log "Summary email sent to: $($emailConfig.Recipients -join ', ')" -Level "INFO"
    } catch {
        # Non-fatal — email failure does NOT stop the run
        Write-Log "Failed to send email: $($_.Exception.Message)" -Level "WARN"
        Write-Log "Email is optional — core lifecycle operations completed successfully" -Level "INFO"
    }
}

#endregion

#region ===== INITIALIZATION =====

$script:runLog = @()

Write-Log "========================================" -Level "INFO"
Write-Log "Entra ID Stale Device Lifecycle — Starting" -Level "INFO"
Write-Log "========================================" -Level "INFO"
Write-Log "Mode: $(if ($Execute) { 'EXECUTE' } else { 'DRY-RUN (no changes will be made)' })" -Level "INFO"
Write-Log "Delete Enabled: $DeleteEnabled" -Level "INFO"
Write-Log "Email Enabled: $SendEmail" -Level "INFO"
Write-Log "Target OS: $($targetOS -join ', ')" -Level "INFO"
Write-Log "Trust Types: $($corporateTrustTypes -join ', ')" -Level "INFO"
Write-Log "Name Pattern Exclusions: $(if ($enableNamePatternExclusions) { 'ON' } else { 'OFF' })" -Level "INFO"
Write-Log "CSV Exclusions: $(if ($enableCsvExclusions) { 'ON' } else { 'OFF' })" -Level "INFO"
Write-Log "Stale Threshold: $StaleThreshold days (inactive since $($staleDate.ToString('yyyy-MM-dd')))" -Level "INFO"
Write-Log "Grace Period: $GracePeriod days (disable eligible since $($disableEligibleDate.ToString('yyyy-MM-dd')))" -Level "INFO"
Write-Log "Disable Hold: $DisableHold days (delete eligible since $($deleteEligibleDate.ToString('yyyy-MM-dd')))" -Level "INFO"
Write-Log "Report Path: $ReportPath" -Level "INFO"
Write-Log "Batch Config: Size=$($batchConfig.BatchSize), Retries=$($batchConfig.MaxRetries), Pause=$($batchConfig.PauseBetweenBatchesMs)ms" -Level "INFO"
Write-Log "Report Retention: $(if ($enableReportRetention) { "$reportRetentionDays days" } else { 'DISABLED' })" -Level "INFO"

# Validate flags
if ($DeleteEnabled -and -not $Execute) {
    Write-Log "-DeleteEnabled requires -Execute. Delete operations will NOT run." -Level "WARN"
    $DeleteEnabled = $false
}

# Create report directory
if (-not (Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    Write-Log "Created report directory: $ReportPath" -Level "INFO"
}

# Load exclusion list
$script:exclusionList = $null
if ($enableCsvExclusions) {
    if (Test-Path $ExclusionFile) {
        $script:exclusionList = @(Import-Csv $ExclusionFile)
        Write-Log "Loaded $($script:exclusionList.Count) exclusion(s) from CSV" -Level "INFO"
    } else {
        Write-Log "CSV exclusion file not found at $ExclusionFile — proceeding without CSV exclusions" -Level "WARN"
    }
} else {
    Write-Log "CSV exclusions disabled — skipping file load" -Level "INFO"
}

# Run report retention cleanup
Invoke-ReportRetention

#endregion

#region ===== MODULE VALIDATION =====

# Verify PowerShell 7+ is being used
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Log "This script requires PowerShell 7 or later." -Level "ERROR"
    Write-Log "Current version: $($PSVersionTable.PSVersion)" -Level "ERROR"
    Write-Log "Download PowerShell 7: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell" -Level "ERROR"
    throw "PowerShell 7+ required. Current version: $($PSVersionTable.PSVersion)"
}

# Check that Microsoft.Graph is installed and meets minimum version
$graphModule = Get-Module -ListAvailable -Name "Microsoft.Graph.Identity.DirectoryManagement" |
    Sort-Object Version -Descending | Select-Object -First 1

if (-not $graphModule) {
    Write-Log "Microsoft.Graph module not found." -Level "ERROR"
    Write-Log "Install it with: Install-Module Microsoft.Graph -Scope CurrentUser" -Level "ERROR"
    throw "Required module Microsoft.Graph is not installed."
}

if ($graphModule.Version -lt $requiredModuleVersion) {
    Write-Log "Microsoft.Graph version $($graphModule.Version) is below minimum required ($requiredModuleVersion)" -Level "ERROR"
    Write-Log "Update with: Update-Module Microsoft.Graph" -Level "ERROR"
    throw "Microsoft.Graph module version $($graphModule.Version) is too old. Minimum required: $requiredModuleVersion"
}

Write-Log "Microsoft.Graph module v$($graphModule.Version) — OK" -Level "INFO"

#endregion

#region ===== AUTHENTICATION =====

try {
    # Check for existing Graph session
    $context = Get-MgContext -ErrorAction SilentlyContinue

    if ($context -and $context.Account) {
        Write-Log "Already connected to Graph as $($context.Account) — reusing session" -Level "INFO"
    } elseif ($context -and $context.ClientId -eq $authConfig.ClientId) {
        Write-Log "Already connected to Graph (AppId: $($context.ClientId)) — reusing session" -Level "INFO"
    } elseif ($authConfig.TenantId -ne "YOUR_TENANT_ID" -and $authConfig.ClientId -ne "YOUR_APP_CLIENT_ID") {
        # Client secret auth for unattended/scheduled execution
        Write-Log "Connecting via client secret (AppId: $($authConfig.ClientId))" -Level "INFO"
        $secureSecret = ConvertTo-SecureString $authConfig.ClientSecret -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($authConfig.ClientId, $secureSecret)
        Connect-MgGraph -TenantId $authConfig.TenantId -ClientSecretCredential $credential -NoWelcome
        Write-Log "Connected to Microsoft Graph (app auth)" -Level "INFO"
    } else {
        # Interactive auth fallback for local testing — opens browser popup
        Write-Log "Auth config has placeholder values — using interactive browser auth for testing" -Level "INFO"
        $scopes = "Device.Read.All", "Device.ReadWrite.All", "Directory.Read.All"
        if ($SendEmail) { $scopes += "Mail.Send" }
        Connect-MgGraph -Scopes $scopes -NoWelcome
        Write-Log "Connected to Microsoft Graph (interactive)" -Level "INFO"
    }
} catch {
    Write-Log "Graph connection failed: $($_.Exception.Message)" -Level "ERROR"
    throw
}

#endregion

#region ===== STAGE 1: REPORT =====

Write-Log "" -Level "INFO"
Write-Log "--- STAGE 1: REPORT ---" -Level "INFO"

try {
    Write-Log "Querying all devices from Entra ID (with owner expansion)..." -Level "INFO"
    $allDevices = @(Get-MgDevice -All -ExpandProperty "RegisteredOwners" `
        -Property "Id,DeviceId,DisplayName,OperatingSystem,OperatingSystemVersion,TrustType,AccountEnabled,ApproximateLastSignInDateTime,RegisteredOwners")
    Write-Log "Retrieved $($allDevices.Count) total devices" -Level "INFO"
} catch {
    Write-Log "Failed to query devices: $($_.Exception.Message)" -Level "ERROR"
    throw
}

# Filter to in-scope devices based on OS and trust type
$inScope = @($allDevices | Where-Object {
    ($targetOS -contains $_.OperatingSystem) -and
    (-not (Test-IsServer -OperatingSystem $_.OperatingSystem -OSVersion $_.OperatingSystemVersion -DisplayName $_.DisplayName)) -and
    ($corporateTrustTypes -contains $_.TrustType)
})
Write-Log "In-scope devices after filtering: $($inScope.Count)" -Level "INFO"

# Export filtered-out devices for audit trail (shows what was caught by server filters)
$filteredOut = @($allDevices | Where-Object {
    ($targetOS -contains $_.OperatingSystem) -and
    (Test-IsServer -OperatingSystem $_.OperatingSystem -OSVersion $_.OperatingSystemVersion -DisplayName $_.DisplayName) -and
    ($corporateTrustTypes -contains $_.TrustType)
})
if ($filteredOut.Count -gt 0) {
    $filteredReport = @(foreach ($d in $filteredOut) {
        $reasons = @()
        foreach ($p in $excludedOSPatterns) { if ($d.OperatingSystem -like $p -or $d.OperatingSystemVersion -like $p) { $reasons += "OS: $p" } }
        foreach ($p in $excludedOSVersionPatterns) { if ($d.OperatingSystemVersion -like $p) { $reasons += "Build: $p" } }
        if ($enableNamePatternExclusions) {
            foreach ($p in $excludedNamePatterns) { if ($d.DisplayName -like $p) { $reasons += "Name: $p" } }
        }
        [PSCustomObject]@{
            DisplayName    = $d.DisplayName
            DeviceId       = $d.Id
            OS             = $d.OperatingSystem
            OSVersion      = $d.OperatingSystemVersion
            TrustType      = $d.TrustType
            Enabled        = $d.AccountEnabled
            FilterReason   = ($reasons -join "; ")
        }
    })
    Export-Report -Data $filteredReport -FileName "FilteredDevices"
}

# Identify stale devices (no sign-in within threshold, or never signed in)
$staleDevices = @($inScope | Where-Object {
    $lastSignIn = $_.ApproximateLastSignInDateTime
    if (-not $lastSignIn) { return $true }  # Never signed in = stale
    return ($lastSignIn -le $staleDate)
})
Write-Log "Stale devices (inactive $StaleThreshold+ days): $($staleDevices.Count)" -Level "INFO"

# Classify each stale device into lifecycle stages
$staleReport = @(foreach ($d in $staleDevices) {
    $id = $d.Id
    $lastSignIn = $d.ApproximateLastSignInDateTime
    $isExcluded = Test-IsExcluded -DeviceObjectId $id
    $isDisabled = -not $d.AccountEnabled
    $owner = Get-DeviceOwnerName -Device $d

    # Determine action classification
    if ($isExcluded) {
        $action = "Excluded"
        $reason = Get-ExclusionReason -DeviceObjectId $id
    } elseif ($lastSignIn -and $lastSignIn -le $deleteEligibleDate -and $isDisabled) {
        $action = "Delete-Eligible"
        $reason = "Disabled and inactive $($StaleThreshold + $GracePeriod + $DisableHold)+ days"
    } elseif (($lastSignIn -and $lastSignIn -le $disableEligibleDate) -or (-not $lastSignIn -and -not $isDisabled)) {
        $action = "Disable-Eligible"
        $reason = if (-not $lastSignIn) { "No sign-in ever recorded" } else { "Inactive $($StaleThreshold + $GracePeriod)+ days" }
    } else {
        $action = "Reported"
        $reason = "Inactive $StaleThreshold+ days (within grace period)"
    }

    [PSCustomObject]@{
        DisplayName       = $d.DisplayName
        DeviceId          = $id
        OperatingSystem   = $d.OperatingSystem
        OSVersion         = $d.OperatingSystemVersion
        TrustType         = $d.TrustType
        AccountEnabled    = $d.AccountEnabled
        LastSignIn        = $lastSignIn
        RegisteredOwner   = $owner
        Action            = $action
        Reason            = $reason
        RunDate           = $today.ToString("yyyy-MM-dd HH:mm:ss")
    }
})

Export-Report -Data $staleReport -FileName "StaleReport"

# Summary counts
$reportOnlyCount      = @($staleReport | Where-Object { $_.Action -eq "Reported" }).Count
$disableEligibleCount = @($staleReport | Where-Object { $_.Action -eq "Disable-Eligible" }).Count
$deleteEligibleCount  = @($staleReport | Where-Object { $_.Action -eq "Delete-Eligible" }).Count
$excludedCount        = @($staleReport | Where-Object { $_.Action -eq "Excluded" }).Count

Write-Log "  Report-only (grace period): $reportOnlyCount" -Level "INFO"
Write-Log "  Eligible for disable: $disableEligibleCount" -Level "INFO"
Write-Log "  Eligible for delete: $deleteEligibleCount" -Level "INFO"
Write-Log "  Excluded (protected): $excludedCount" -Level "INFO"

#endregion

#region ===== STAGE 2: DISABLE =====

Write-Log "" -Level "INFO"
Write-Log "--- STAGE 2: DISABLE ---" -Level "INFO"

$toDisable = @($staleReport | Where-Object { $_.Action -eq "Disable-Eligible" -and $_.AccountEnabled -eq $true })
Write-Log "Devices to disable (currently enabled): $($toDisable.Count)" -Level "INFO"

$disabledCount = 0
$disableFailures = 0

if ($toDisable.Count -gt 0) {
    # Build batch requests for disable (PATCH accountEnabled = false)
    $disableRequests = [System.Collections.Generic.List[object]]::new()
    $counter = 0
    foreach ($device in $toDisable) {
        $counter++
        $disableRequests.Add(@{
            id      = "$counter"
            method  = "PATCH"
            url     = "/devices/$($device.DeviceId)"
            headers = @{ "Content-Type" = "application/json" }
            body    = @{ accountEnabled = $false }
        })
    }

    if (-not $Execute) {
        $totalBatches = [Math]::Ceiling($disableRequests.Count / $batchConfig.BatchSize)
        Write-Log "[DRY-RUN] Would submit $($disableRequests.Count) disable requests in $totalBatches batch(es)" -Level "DRYRUN"
        Write-Log "[DRY-RUN] No devices were actually disabled" -Level "DRYRUN"
    } else {
        $disableResults = Invoke-GraphBatch -Requests $disableRequests

        $counter = 0
        foreach ($device in $toDisable) {
            $counter++
            $result = $disableResults | Where-Object { $_.Id -eq "$counter" }
            if ($result.Success) {
                Write-Log "DISABLED: $($device.DisplayName) ($($device.DeviceId))" -Level "ACTION"
                $disabledCount++
            } else {
                Write-Log "FAILED disable $($device.DisplayName): $($result.Error)" -Level "ERROR"
                $disableFailures++
            }
        }
    }
}

if ($Execute -and ($disabledCount + $disableFailures) -gt 0) {
    Export-Report -Data $toDisable -FileName "DisabledDevices"
}

#endregion

#region ===== STAGE 3: DELETE =====

Write-Log "" -Level "INFO"
Write-Log "--- STAGE 3: DELETE ---" -Level "INFO"

$toDelete = @($staleReport | Where-Object { $_.Action -eq "Delete-Eligible" })
Write-Log "Devices eligible for deletion: $($toDelete.Count)" -Level "INFO"

$deletedCount = 0
$deleteFailures = 0

if (-not $DeleteEnabled) {
    Write-Log "Delete operations DISABLED. Pass -Execute -DeleteEnabled to enable." -Level "WARN"
} else {
    if ($toDelete.Count -gt 0) {
        # Build batch requests for delete
        $deleteRequests = [System.Collections.Generic.List[object]]::new()
        $counter = 0
        foreach ($device in $toDelete) {
            $counter++
            $deleteRequests.Add(@{
                id     = "$counter"
                method = "DELETE"
                url    = "/devices/$($device.DeviceId)"
            })
        }

        if (-not $Execute) {
            $totalBatches = [Math]::Ceiling($deleteRequests.Count / $batchConfig.BatchSize)
            Write-Log "[DRY-RUN] Would submit $($deleteRequests.Count) delete requests in $totalBatches batch(es)" -Level "DRYRUN"
            Write-Log "[DRY-RUN] No devices were actually deleted" -Level "DRYRUN"
        } else {
            $deleteResults = Invoke-GraphBatch -Requests $deleteRequests

            $counter = 0
            foreach ($device in $toDelete) {
                $counter++
                $result = $deleteResults | Where-Object { $_.Id -eq "$counter" }
                if ($result.Success) {
                    Write-Log "DELETED: $($device.DisplayName) ($($device.DeviceId))" -Level "ACTION"
                    $deletedCount++
                } else {
                    Write-Log "FAILED delete $($device.DisplayName): $($result.Error)" -Level "ERROR"
                    $deleteFailures++
                }
            }
        }
    }

    if ($Execute -and ($deletedCount + $deleteFailures) -gt 0) {
        Export-Report -Data $toDelete -FileName "DeletedDevices"
    }
}

#endregion

#region ===== SUMMARY & EMAIL =====

Write-Log "" -Level "INFO"
Write-Log "========================================" -Level "INFO"
Write-Log "Run Complete" -Level "INFO"
Write-Log "========================================" -Level "INFO"
Write-Log "Mode: $(if ($Execute) { 'EXECUTE' } else { 'DRY-RUN' })" -Level "INFO"
Write-Log "In-scope devices: $($inScope.Count)" -Level "INFO"
Write-Log "Stale found: $($staleDevices.Count)" -Level "INFO"
Write-Log "Disabled this run: $disabledCount" -Level "INFO"
Write-Log "Deleted this run: $deletedCount" -Level "INFO"
Write-Log "Excluded: $excludedCount" -Level "INFO"
Write-Log "Failures: $($disableFailures + $deleteFailures)" -Level "INFO"

$summary = @{
    TotalInScope    = $inScope.Count
    StaleFound      = $staleDevices.Count
    ReportOnly      = $reportOnlyCount
    DisableEligible = $disableEligibleCount
    DeleteEligible  = $deleteEligibleCount
    Excluded        = $excludedCount
    Disabled        = $disabledCount
    Deleted         = $deletedCount
    Failures        = $disableFailures + $deleteFailures
}

# Export structured run log (JSON — useful for auditing and automation)
$runLogPath = Join-Path $ReportPath "RunLog_$dateStamp.json"
@{
    RunTimestamp    = $today.ToString("yyyy-MM-dd HH:mm:ss")
    Mode           = if ($Execute) { "Execute" } else { "DryRun" }
    DeleteEnabled  = [bool]$DeleteEnabled
    Parameters     = @{
        StaleThreshold = $StaleThreshold
        GracePeriod    = $GracePeriod
        DisableHold    = $DisableHold
        TargetOS       = $targetOS
        TrustTypes     = $corporateTrustTypes
    }
    Summary        = $summary
    LogEntries     = $script:runLog
} | ConvertTo-Json -Depth 4 | Out-File -FilePath $runLogPath -Encoding UTF8
Write-Log "Run log: $runLogPath" -Level "INFO"

# Send email if enabled (isolated — failures here don't affect the run)
if ($SendEmail) {
    Write-Log "Sending summary email..." -Level "INFO"
    Send-SummaryEmail -Summary $summary
}

# If you made it this far without errors, the raccoons didn't get in.
Write-Log "Done. Your tenant is a little cleaner today." -Level "INFO"

#endregion
