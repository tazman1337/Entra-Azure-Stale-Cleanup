# Entra ID Stale Device Lifecycle Management

Automated identification, disabling, and (optional) deletion of stale devices in Microsoft Entra ID (Azure AD). Three-stage lifecycle provides visibility, safety rails, and full audit trails before anything is ever touched.

**Author:** Mitchell Brown
**Version:** 2.0
**License:** MIT — See [Disclaimer](#disclaimer) below.
**Requires:** PowerShell 7+ | Microsoft.Graph module v2.0+

---

## Why This Exists

Every Entra ID tenant accumulates stale device objects over time. Employees leave, hardware gets replaced, laptops get reimaged — but the old device records stick around like raccoons in a dumpster. They clutter your directory, skew compliance reports, and make it impossible to tell what's actually active in your environment.

This script provides a **safe, staged approach** to cleaning them up — with enough guard rails that you'd have to actively try to break something.

---

## How It Works — The Three Stages

```
ACTIVE DEVICE (signs in regularly)
        |
        |  No sign-in for 90 days (configurable)
        v
+---------------------------------------+
|  STAGE 1: REPORTED                    |
|  Appears on stale report CSV          |
|  NO action taken — visibility only    |
+-------------------+-------------------+
                    |  30+ more days (configurable)
                    v
+---------------------------------------+
|  STAGE 2: DISABLED                    |
|  AccountEnabled = false               |
|  Device can no longer authenticate    |
|  Rollback CSV exported for safety     |
+-------------------+-------------------+
                    |  60+ more days (configurable)
                    v
+---------------------------------------+
|  STAGE 3: DELETED (opt-in only)       |
|  Device object removed from Entra ID  |
|  Final backup CSV exported            |
|  Requires BOTH -Execute AND           |
|  -DeleteEnabled flags                 |
+---------------------------------------+
```

| Milestone | Default Days Inactive | What Happens |
|-----------|----------------------|--------------|
| First appears on report | 90 | Nothing — report only |
| Eligible for disable | 120 (90 + 30) | Account disabled |
| Eligible for deletion | 180 (90 + 30 + 60) | Object deleted (opt-in) |

The default lifecycle is **180 days minimum** from first inactivity to deletion. A device must pass through every stage. There are no shortcuts.

---

## Quick Start

### 1. Install Prerequisites

**Requires PowerShell 7+** — This script uses features and module versions that require PowerShell 7 or later. Windows PowerShell 5.1 is not supported.

- [Download PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) if you don't have it already.
- Verify your version: `$PSVersionTable.PSVersion`

```powershell
# Install the Microsoft Graph PowerShell module (v2.0+ required)
Install-Module Microsoft.Graph -Scope CurrentUser
```

### 2. Configure the Script

Open `Azure_Stale_Data.ps1` and edit the **USER CONFIGURATION** section at the top. At minimum, you need:

```powershell
$authConfig = @{
    TenantId     = "contoso.onmicrosoft.com"   # Your tenant ID or domain
    ClientId     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ClientSecret = "your-secret-value-here"
}
```

### 3. Run a Dry-Run (No Changes Made)

```powershell
.\Azure_Stale_Data.ps1
```

This queries your tenant, generates reports, and shows you what WOULD happen — without touching a single device. Check the `reports/` folder for the CSV output.

### 4. Execute When Ready

```powershell
# Enable disable operations
.\Azure_Stale_Data.ps1 -Execute

# Enable disable AND delete operations
.\Azure_Stale_Data.ps1 -Execute -DeleteEnabled
```

---

## File Structure

```
Azure_Stale_Data/
├── Azure_Stale_Data.ps1      # The main script
├── exclusions.csv             # Devices to never touch (by Object ID)
├── README.md                  # You are here
└── reports/                   # Auto-created on first run
    ├── StaleReport_*.csv      # All stale devices with classifications
    ├── DisabledDevices_*.csv  # Devices disabled this run
    ├── DeletedDevices_*.csv   # Devices deleted this run (backup)
    ├── FilteredDevices_*.csv  # Devices caught by server filters (audit)
    └── RunLog_*.json          # Structured log of every decision
```

---

## Configuration Reference

Everything you need to customize lives in the `USER CONFIGURATION` region at the top of the script. The rest of the script should not need modification.

### Authentication

```powershell
$authConfig = @{
    TenantId     = "YOUR_TENANT_ID"
    ClientId     = "YOUR_APP_CLIENT_ID"
    ClientSecret = "YOUR_CLIENT_SECRET"
}
```

| Field | What Goes Here |
|-------|---------------|
| TenantId | Your Entra tenant — either the `.onmicrosoft.com` domain or the GUID |
| ClientId | The Application (client) ID from your App Registration |
| ClientSecret | The client secret value (copy it when you create it — you only see it once) |

**Fallback behavior:** If these are left as placeholders, the script falls back to interactive browser authentication. This is handy for local testing — just run `Connect-MgGraph` manually or let the script open a browser popup.

**Key Vault upgrade path:** There's a commented line in the config showing how to pull the secret from Azure Key Vault instead of hardcoding it. When you're ready, just uncomment it and remove the hardcoded value.

---

### Target Device Types

```powershell
$targetOS = @(
    "Windows"
    "macOS"
    # "Android"
    # "iOS"
    # "iPadOS"
    # "Linux"
)
```

**Only devices matching these OS values are evaluated.** Everything else is completely ignored by the script. Uncomment lines to add device types to your scope.

Common values reported by Entra ID:
- `"Windows"` — Windows desktops and laptops
- `"macOS"` — Apple Mac computers
- `"Android"` — Android phones and tablets
- `"iOS"` — iPhones (some tenants report iPads as iOS too)
- `"iPadOS"` — iPads (depends on your tenant's reporting)
- `"Linux"` — Linux workstations

---

### Device Trust Types

```powershell
$corporateTrustTypes = @(
    "AzureAd"      # Cloud-joined corporate devices
    "ServerAd"     # Hybrid-joined corporate devices
    # "Workplace"  # Personal/BYOD devices
)
```

This controls whether you're targeting corporate-managed devices, personal devices, or both.

| Trust Type | What It Means |
|-----------|--------------|
| `AzureAd` | Azure AD Joined — corporate cloud-managed devices |
| `ServerAd` | Hybrid Azure AD Joined — domain-joined + cloud-registered |
| `Workplace` | Azure AD Registered — personal/BYOD devices |

**Default is corporate only.** If you uncomment `"Workplace"`, personal devices become subject to the stale lifecycle. Make sure that's intentional — those raccoons bite back if you disable someone's personal phone.

---

### Exclusion System (Defense in Depth)

This script has **two independent exclusion mechanisms** that work together. You can use one, both, or neither.

#### Why Two Systems?

Think of it like a trash can with two locks. The name patterns catch entire *classes* of devices automatically — including new ones that get provisioned tomorrow. The CSV catches specific *individual* devices that don't fit a pattern. Together, they form a layered defense against accidentally touching something you shouldn't.

| Mechanism | Catches | Good For | Toggle |
|-----------|---------|----------|--------|
| Name Patterns | Classes of devices by naming convention | Servers, VDI, lab machines | `$enableNamePatternExclusions` |
| CSV File | Individual devices by Object ID | Conference rooms, seasonal equipment | `$enableCsvExclusions` |

#### Name Pattern Exclusions

```powershell
$enableNamePatternExclusions = $true

$excludedNamePatterns = @(
    "SRV-*"       # Servers
    "*-DC*"       # Domain controllers
    "*-SQL*"      # SQL servers
    "*-FS*"       # File servers
    "AVD-*"       # Azure Virtual Desktop
    "VDI-*"       # VDI machines
    "*-TEST*"     # Test machines
    "*-DEV*"      # Dev machines
    "*-LAB*"      # Lab machines
)
```

Uses PowerShell wildcard matching (`*` = any characters). Add patterns that match your org's naming convention. Set `$enableNamePatternExclusions = $false` to disable entirely.

#### CSV Exclusion File

Format for `exclusions.csv`:

```csv
DeviceId,DisplayName,Reason
00000000-0000-0000-0000-000000000001,CONF-ROOM-LOBBY,Conference room - seasonal use
00000000-0000-0000-0000-000000000002,WAREHOUSE-PC-04,Seasonal warehouse terminal
```

- **DeviceId** = The Object ID from Entra ID (the GUID you see in the device properties)
- **DisplayName** = Human-readable name (for your reference — not used for matching)
- **Reason** = Why it's excluded (appears in reports for audit visibility)

Set `$enableCsvExclusions = $false` to skip the CSV file entirely.

---

### Lifecycle Thresholds

```powershell
# These are script parameters — pass them at runtime or use defaults
-StaleThreshold 90    # Days inactive before appearing on report
-GracePeriod 30       # Days on report before eligible for disable
-DisableHold 60       # Days disabled before eligible for delete
```

| Parameter | Default | What It Controls |
|-----------|---------|-----------------|
| StaleThreshold | 90 days | How long a device must be inactive before it's considered stale |
| GracePeriod | 30 days | How long a stale device stays on the report before being disabled |
| DisableHold | 60 days | How long a disabled device waits before becoming eligible for deletion |

**Total lifecycle with defaults:** 180 days from last sign-in to deletion eligibility. Adjust these to match your organization's needs. More aggressive environments might use 60/14/30 (104 total). More conservative ones might use 120/60/90 (270 total).

---

### Graph API Batch Configuration

```powershell
$batchConfig = @{
    BatchSize              = 20      # Requests per batch (max 20)
    MaxRetries             = 3       # Retry attempts for failed batches
    PauseBetweenBatchesMs  = 200     # Delay between batches (ms)
}
```

The script sends disable and delete requests to the Graph API in batches rather than one-at-a-time. This is significantly faster for large environments and includes built-in retry logic for transient failures (429 throttling, 503/504 service errors).

| Setting | Tuning Guidance |
|---------|----------------|
| BatchSize | Graph API max is 20. Reduce to 10 if you're getting throttled. |
| MaxRetries | 3 is solid for most environments. Increase for unreliable connections. |
| PauseBetweenBatchesMs | Increase if you're hitting rate limits. 500ms is conservative. 100ms is aggressive. |

**Presets:**
- **Conservative** (large tenants, cautious): `BatchSize=10, Pause=500`
- **Balanced** (most environments): `BatchSize=20, Pause=200`
- **Aggressive** (small tenants, need speed): `BatchSize=20, Pause=100`

---

### Report Retention

```powershell
$enableReportRetention = $true
$reportRetentionDays = 30
```

Automatically cleans up old CSV and JSON report files to prevent the reports folder from growing forever. Runs at the beginning of each execution.

| Value | Keeps Reports For |
|-------|------------------|
| 7 | One week |
| 14 | Two weeks |
| 30 | One month (default) |
| 90 | Three months |

Set `$enableReportRetention = $false` to disable cleanup entirely (reports accumulate indefinitely — watch your disk space, or the raccoons will nest in there).

---

### Email Notification (Optional)

```powershell
$emailConfig = @{
    Sender     = "yourserviceaccount@yourdomain.com"
    Recipients = @("admin@yourdomain.com")
    Subject    = "Entra ID Stale Device Report — ..."
}
```

Pass `-SendEmail` at runtime to send an HTML summary email after each run. This feature is **completely isolated** — if it fails (wrong permissions, bad config, mail service down), it logs a warning and the rest of the script completes normally. It will never block the core lifecycle operations.

**Requirements:**
- `Mail.Send` application permission on the App Registration
- A valid sender (licensed mailbox or shared mailbox)
- Admin consent granted for Mail.Send

**If you don't need email:** Just never pass `-SendEmail`. The feature is dormant unless explicitly invoked.

---

## Parameters (Runtime Flags)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Execute` | Switch | OFF | Enable disable/delete operations. Without this, everything is dry-run. |
| `-DeleteEnabled` | Switch | OFF | Enable delete operations. Requires `-Execute` to also be set. |
| `-SendEmail` | Switch | OFF | Send HTML summary email after run completes. |
| `-StaleThreshold` | Int | 90 | Days of inactivity before a device is considered stale. |
| `-GracePeriod` | Int | 30 | Days on the stale report before eligible for disable. |
| `-DisableHold` | Int | 60 | Days a device must be disabled before eligible for deletion. |
| `-ReportPath` | String | `.\reports` | Directory where CSV/JSON output is saved. |
| `-ExclusionFile` | String | `.\exclusions.csv` | Path to the device exclusion list. |

---

## Usage Examples — How to Call the Script

> **Requires:** PowerShell 7+ (`pwsh`). Run all commands from the directory containing `Azure_Stale_Data.ps1`.

### Running the Script (Basics)

Open a PowerShell 7 terminal, navigate to the script folder, and call it:

```powershell
cd C:\Scripts\Azure_Stale_Data   # or wherever you placed it
.\Azure_Stale_Data.ps1
```

That's it. With no flags, it runs in **dry-run mode** — reads your tenant, generates reports, and shows you what it found. Nothing is changed, disabled, or deleted.

---

### Example Calls — Explained

#### Just the script, no flags (Dry-Run / Report Only)

```powershell
.\Azure_Stale_Data.ps1
```

**What it does:**
- Connects to Graph (interactive browser login if auth config has placeholders)
- Queries all devices in your Entra ID tenant
- Filters to in-scope devices based on your `$targetOS` and `$corporateTrustTypes` config
- Identifies stale devices (inactive 90+ days by default)
- Classifies each device: Reported, Disable-Eligible, Delete-Eligible, or Excluded
- Exports CSV reports to the `reports/` folder
- **Does NOT disable or delete anything**

This is the "look but don't touch" mode. Use it to validate everything looks right before flipping switches.

---

#### Enable disable operations

```powershell
.\Azure_Stale_Data.ps1 -Execute
```

**What it does:**
- Everything from the dry-run PLUS:
- Devices classified as "Disable-Eligible" (stale beyond the grace period) are **actually disabled** (`AccountEnabled = $false`)
- A `DisabledDevices_*.csv` backup is exported before any changes
- Devices classified as "Delete-Eligible" are logged but **NOT deleted** (delete requires its own flag)

This is the recommended first step after you've validated dry-run output.

---

#### Enable disable AND delete operations

```powershell
.\Azure_Stale_Data.ps1 -Execute -DeleteEnabled
```

**What it does:**
- Everything from `-Execute` PLUS:
- Devices classified as "Delete-Eligible" (disabled 60+ days, inactive 180+ total) are **permanently removed** from Entra ID
- A `DeletedDevices_*.csv` final backup is exported before deletion
- **This is destructive** — deleted devices must be re-enrolled, they cannot be restored via API

Two flags required intentionally. You can't accidentally delete devices by only passing one.

---

#### Custom lifecycle thresholds

```powershell
.\Azure_Stale_Data.ps1 -StaleThreshold 60 -GracePeriod 14 -DisableHold 30
```

**What it does:**
- Runs dry-run with more aggressive timing:
  - Stale after **60 days** inactive (instead of 90)
  - Grace period of **14 days** (instead of 30)
  - Disable hold of **30 days** (instead of 60)
  - Total lifecycle: **104 days** to deletion eligibility (instead of 180)

Useful for environments with higher device turnover or shorter compliance windows.

---

#### Send email notification

```powershell
.\Azure_Stale_Data.ps1 -SendEmail
```

**What it does:**
- Dry-run (no changes) + sends an HTML summary email after completion
- Good for testing that your email config works before combining with `-Execute`
- If email fails (permissions, bad config), it logs a warning and continues — never blocks the run

---

#### Full lifecycle with email

```powershell
.\Azure_Stale_Data.ps1 -Execute -DeleteEnabled -SendEmail
```

**What it does:**
- Disables eligible devices
- Deletes eligible devices
- Sends summary email
- The "production scheduled task" configuration for when you trust the process completely

---

#### Custom report location

```powershell
.\Azure_Stale_Data.ps1 -ReportPath "D:\Reports\StaleDevices"
```

**What it does:**
- Outputs all CSV and JSON reports to a custom directory instead of `.\reports`
- Creates the directory if it doesn't exist
- Useful when running from a scheduled task and you want reports on a specific drive

---

#### Custom exclusion file location

```powershell
.\Azure_Stale_Data.ps1 -ExclusionFile "C:\Config\my_exclusions.csv"
```

**What it does:**
- Uses a custom path for the exclusion CSV instead of `.\exclusions.csv`
- Useful if you maintain a central exclusion list across multiple scripts

---

#### Interactive testing (no App Registration needed)

```powershell
# Connect manually with your admin account first
Connect-MgGraph -Scopes "Device.Read.All","Device.ReadWrite.All","Directory.Read.All"

# Then run the script — it reuses your existing session
.\Azure_Stale_Data.ps1
```

**What it does:**
- Uses your already-authenticated Graph session instead of the App Registration
- Perfect for initial testing before you've set up the App Registration
- The script detects an existing session and skips its own auth flow

---

#### Combining everything (the kitchen sink)

```powershell
.\Azure_Stale_Data.ps1 `
    -Execute `
    -DeleteEnabled `
    -SendEmail `
    -StaleThreshold 90 `
    -GracePeriod 30 `
    -DisableHold 60 `
    -ReportPath "D:\Reports\StaleDevices" `
    -ExclusionFile "D:\Config\exclusions.csv"
```

**What it does:**
- Full lifecycle (disable + delete) with custom paths and email notification
- This is what a fully configured scheduled task might look like
- The backtick (`` ` ``) is PowerShell's line continuation character — makes long commands readable

---

## App Registration Setup

### Step 1: Create the App Registration

1. Go to **Azure Portal** > **Entra ID** > **App Registrations** > **New Registration**
2. Name: `Stale Device Lifecycle` (or whatever makes sense for your org)
3. Supported account types: **Single tenant**
4. Redirect URI: Leave blank (not needed for client credential flow)
5. Click **Register**

### Step 2: Grant API Permissions

Go to **API Permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**

| Permission | Required | Purpose |
|------------|----------|---------|
| `Device.Read.All` | Yes | Query all devices in the directory |
| `Device.ReadWrite.All` | Yes | Disable and delete device objects |
| `Directory.Read.All` | Yes | Read device ownership information |
| `Mail.Send` | Only if using -SendEmail | Send email notifications |

After adding permissions, click **Grant admin consent for [your tenant]**.

### Step 3: Create a Client Secret

1. Go to **Certificates & secrets** > **New client secret**
2. Set description: `Stale Device Lifecycle`
3. Set expiration: 12-24 months recommended
4. Click **Add**
5. **Copy the Value immediately** — you won't see it again after leaving this page

### Step 4: Update the Script

Paste your values into the `$authConfig` block:

```powershell
$authConfig = @{
    TenantId     = "contoso.onmicrosoft.com"
    ClientId     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ClientSecret = "the-secret-value-you-copied"
}
```

### Step 5 (Optional): Azure Key Vault

When you're ready to stop hardcoding the secret, replace the ClientSecret line with:

```powershell
$authConfig.ClientSecret = (Get-AzKeyVaultSecret -VaultName "YourVault" -Name "StaleDeviceSecret" -AsPlainText)
```

This requires the `Az.KeyVault` module and appropriate Key Vault access policies.

---

## Scheduling (Optional)

This script is designed to run on-demand or on a schedule — your choice. Here are common approaches:

### Windows Task Scheduler

```
Program:    powershell.exe
Arguments:  -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Azure_Stale_Data\Azure_Stale_Data.ps1" -Execute -SendEmail
Start in:   C:\Scripts\Azure_Stale_Data
```

Run as SYSTEM or a service account. Set "Run whether user is logged on or not" and "Run with highest privileges."

### Azure Automation Runbook

Upload the script as a runbook, configure the App Registration auth (or use a managed identity), and set a schedule. Adjust `-ReportPath` to a location accessible to the runbook (Azure Storage, for example).

### Manual Execution

Just run it from any machine with the Microsoft.Graph module installed. If the auth config has placeholder values, it'll open a browser for interactive login — perfect for testing.

---

## Safety Design

This script was built by someone who has seen what happens when automation goes wrong at 2 AM. Every design decision prioritizes **not breaking things**:

| Safety Feature | How It Protects You |
|---------------|-------------------|
| Dry-run default | No changes without explicitly passing `-Execute` |
| Two-flag delete | Deletion requires both `-Execute` AND `-DeleteEnabled` |
| 3-layer server filter | OS name + OS build number + device name patterns |
| Trust type scope | Only targets corporate devices by default (BYOD untouched) |
| Dual exclusion system | Name patterns (automatic) + CSV (manual) — use one or both |
| 180-day minimum lifecycle | Device must age through ALL stages sequentially |
| Pre-action CSV exports | Full backup before every disable or delete operation |
| Per-device error handling | One failure doesn't kill the whole run |
| Structured JSON logging | Every decision recorded with timestamp and reason |
| Non-fatal email | Email failures are logged, never block the core operations |
| Module version check | Warns you if your Graph module is too old |
| Interactive auth fallback | Placeholder config = safe browser login for testing |

---

## Output Files

| File | When Generated | Contents |
|------|---------------|----------|
| `StaleReport_*.csv` | Every run | All stale devices with action classification |
| `DisabledDevices_*.csv` | Execute mode, devices disabled | Pre-action backup of disabled devices |
| `DeletedDevices_*.csv` | Execute + Delete mode | Final backup before deletion (your undo data) |
| `FilteredDevices_*.csv` | Every run (if servers caught) | Audit trail of server-filter exclusions |
| `RunLog_*.json` | Every run | Structured log: parameters, summary, every decision |

### Report Columns

- **DisplayName** — Device name as shown in Entra ID
- **DeviceId** — The Object ID (GUID) of the device
- **OperatingSystem** — Windows, macOS, etc.
- **OSVersion** — Build number / version string
- **TrustType** — AzureAd, ServerAd, or Workplace
- **AccountEnabled** — Whether the device is currently enabled
- **LastSignIn** — Last approximate sign-in timestamp (from Entra)
- **RegisteredOwner** — The user registered as the device owner
- **Action** — What the script classified this device as (Reported, Disable-Eligible, Delete-Eligible, Excluded)
- **Reason** — Why it received that classification
- **RunDate** — When this report was generated

---

## Rollback

### Re-enable a disabled device

```powershell
# Single device
Update-MgDevice -DeviceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -BodyParameter @{ accountEnabled = $true }

# Bulk re-enable from the DisabledDevices CSV
$devices = Import-Csv ".\reports\DisabledDevices_20260101_120000.csv"
foreach ($d in $devices) {
    Update-MgDevice -DeviceId $d.DeviceId -BodyParameter @{ accountEnabled = $true }
}
```

### Restore a deleted device

Deleted devices cannot be restored through the API. They must be re-enrolled or re-joined to Entra ID. The `DeletedDevices_*.csv` contains all metadata for identification — use it to verify which devices need re-provisioning.

This is why the delete stage requires two explicit flags and a 60-day hold period. By the time something reaches deletion, it's been inactive for 180+ days and disabled for 60+. If someone still needs it, you'll know long before then.

---

## Recommended Deployment Workflow

1. **Test locally with dry-run** — Run without `-Execute` to see what would happen. Check the reports. Verify the numbers make sense. Make sure your exclusions are catching what they should.

2. **Validate with a small scope** — Temporarily set `$targetOS = @("macOS")` or a single trust type to limit scope on first real execution.

3. **Enable disable only** — Run with `-Execute` (no `-DeleteEnabled`). Let disabled devices accumulate for a cycle. Spot-check that nothing critical got disabled.

4. **Enable full lifecycle** — After you're confident, add `-DeleteEnabled`. The hold period means nothing gets deleted immediately — there's still the 60-day buffer.

5. **Set up scheduling** — Once you trust the process, automate it on whatever schedule works for you (daily, weekly, etc.).

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| "Module not found" error | Microsoft.Graph not installed | `Install-Module Microsoft.Graph -Scope CurrentUser` |
| "Version too old" error | Graph module below v2.0 | `Update-Module Microsoft.Graph` |
| Auth fails with 401 | Bad credentials or expired secret | Verify ClientId/Secret, regenerate if expired |
| Auth fails with 403 | Missing permissions | Check App Registration has Device.ReadWrite.All + admin consent |
| No devices returned | Wrong TenantId or no permissions | Verify TenantId, check permission grants |
| Servers appearing in stale report | Name patterns don't match your naming | Update `$excludedNamePatterns` with your convention |
| Devices you expected to be excluded aren't | Wrong DeviceId in CSV | Use the **Object ID** (not Device ID) from Entra portal |
| Email fails | Missing Mail.Send permission or bad sender | Add permission + admin consent, verify sender mailbox exists |
| Throttling (429 errors) | Batch too aggressive | Reduce `BatchSize` to 10, increase `PauseBetweenBatchesMs` to 500 |

---

## FAQ

**Q: Will this touch servers?**
A: No. The 3-layer server filter (OS name, build number, device name patterns) catches servers regardless of how they're named. Even if a server somehow matches your target OS and trust type, the name/OS filters block it. And you can add it to the exclusions CSV as a final safety net.

**Q: What about devices that come back online after being disabled?**
A: A disabled device can still be re-enabled manually (see Rollback). If a user reports their device stopped working, check the `DisabledDevices_*.csv` — if it's there, re-enable it. The device will resume normal sign-in and won't appear stale on the next run.

**Q: Can I run this for just one device type?**
A: Yes. Set `$targetOS = @("Android")` to only evaluate Android devices, for example. You can target any combination.

**Q: What happens if the script fails mid-run?**
A: Each operation is independent. If device #47 out of 200 fails to disable, the error is logged, and the script continues with device #48. Failures never cascade. The run summary tells you exactly how many succeeded and failed.

**Q: Does dry-run mode hit the API?**
A: It queries devices (read-only) to generate reports. It does NOT send any disable or delete requests. The reports show you exactly what would happen if you flipped `-Execute` on.

**Q: Is there a raccoon living in my Entra ID tenant?**
A: Statistically? Yes. Somewhere between your stale devices and abandoned guest accounts, there's a digital trash panda making itself comfortable. This script is how you evict it — humanely, with a 180-day notice period.

---

## Future Considerations

- **Intune cross-reference** — Device stale in Entra but active in Intune? Might not truly be stale.
- **Per-OS thresholds** — Mobile devices go stale faster than laptops; different thresholds per OS type.
- **Extension attribute tagging** — Stamp disabled devices with a custom attribute for portal visibility.
- **Conditional Access integration** — Use device compliance state alongside last sign-in for smarter decisions.
- **Multi-tenant support** — Loop through multiple tenants with different configs.

---

## Disclaimer

This script is provided **as-is**, without warranty of any kind, express or implied. The author is not responsible for any damage, data loss, device lockouts, confused help desk calls, or unexpected raccoon infestations resulting from the use of this script.

**Always test with dry-run mode first.** Understand what the script will do in YOUR environment before enabling execution. Review the reports. Check the exclusions. Then — and only then — flip the switch.

Use at your own risk. But honestly, the biggest risk is doing nothing and letting your stale device count grow until it achieves sentience.

---

*Built with care, caffeine, and a healthy respect for the destructive power of automation.*
*— Mitchell Brown*
