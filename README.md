# Entra ID Stale Device Lifecycle Management

Automated identification, disabling, and (optional) deletion of stale devices in Microsoft Entra ID (Azure AD). Three-stage lifecycle provides visibility, safety rails, and full audit trails before anything is ever touched.

**Author:** Mitchell Brown
**Version:** 2.1
**License:** MIT — See [Disclaimer](#disclaimer) below.
**Requires:** PowerShell 7+ | Microsoft.Graph module v2.0+

---

## Why This Exists

Every Entra ID tenant accumulates stale device objects over time. Employees leave, hardware gets replaced, laptops get reimaged — but the old device records stick around like raccoons in a dumpster. They clutter your directory, skew compliance reports, and make it impossible to tell what is actually active in your environment.

This script provides a **safe, staged approach** to cleaning them up — with enough guard rails that you would have to actively try to break something.

---

## What is New in v2.1

| Fix | What Changed |
|-----|-------------|
| **Mobile OS Support** | OS variant map auto-expands Android to include AndroidForWork, AndroidEnterprise, AOSP. Same for iOS/iPadOS. Trust type auto-adds Workplace when mobile OS is targeted. |
| **Batch Engine Rewrite** | Replaced broken retry logic with GraphBatchEngine — proper retry queues (only failed requests retry), adaptive throttling, zero silent data loss. |
| **New Device Protection** | Devices with no sign-in are now checked against CreatedDateTime — recently provisioned devices will not be disabled before they have had a chance to sign in. |
| **Re-Enable Protection** | Script stamps extensionAttribute15 when disabling. If a human re-enables the device, next run detects the stamp + enabled state and skips it — respecting the operator decision. |
| **ShouldProcess Wired** | -WhatIf now actually works (shows exact operations). -Confirm prompts before destructive batches. Previously declared but never implemented. |
| **Streaming Pagination** | Replaced Get-MgDevice -All (loads entire tenant into RAM) with paged Invoke-MgGraphRequest — filters in-flight, memory proportional to matching devices only. |

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
|  Extension attribute stamped          |
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
| Eligible for disable | 120 (90 + 30) | Account disabled + lifecycle stamp written |
| Eligible for deletion | 180 (90 + 30 + 60) | Object deleted (opt-in) |

The default lifecycle is **180 days minimum** from first inactivity to deletion. A device must pass through every stage. There are no shortcuts.

---

## Quick Start

### 1. Install Prerequisites

**Requires PowerShell 7+** — Windows PowerShell 5.1 is not supported.

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

### 2. Configure the Script

Open Azure_Stale_Data.ps1 and edit the **USER CONFIGURATION** section at the top. At minimum you need TenantId, ClientId, and ClientSecret from an App Registration.

### 3. Run a Dry-Run (No Changes Made)

```powershell
.\Azure_Stale_Data.ps1
```

### 4. Preview with -WhatIf

```powershell
.\Azure_Stale_Data.ps1 -Execute -WhatIf
.\Azure_Stale_Data.ps1 -Execute -DeleteEnabled -WhatIf
```

### 5. Execute When Ready

```powershell
.\Azure_Stale_Data.ps1 -Execute
.\Azure_Stale_Data.ps1 -Execute -DeleteEnabled
.\Azure_Stale_Data.ps1 -Execute -Confirm
```

---

## Configuration Reference

### Target Device Types and OS Variant Map

```powershell
$targetOS = @(
    "Windows"
    # "Android"
    # "iOS"
    # "iPadOS"
)
```

The script includes an **OS Variant Map** that automatically expands config values into all known Entra ID reporting variants:

| You Configure | Script Also Matches |
|--------------|--------------------|
| Android | AndroidForWork, AndroidEnterprise, AOSP |
| iOS | iPhone |
| iPadOS | iPad |
| Windows | Windows (consistent) |
| macOS | macOS (consistent) |

You do not need to know how your tenant reports OS names — the variant map handles it.

---

### Device Trust Types (Auto-Expansion for Mobile)

When mobile OS types (Android, iOS, iPadOS) are in the target list, the script **automatically adds** Workplace to the trust type scope with a logged warning. Mobile devices — even company-owned, Intune-managed ones — register as Workplace in Entra ID, not AzureAd. Without this, mobile targeting silently returns zero results. The raccoons were hiding in a trust type mismatch all along.

---

### Re-Enable Protection (New in v2.1)

```powershell
$enableReEnableProtection = $true
$lifecycleAttribute       = "extensionAttribute15"
$lifecycleStampPrefix     = "StaleLifecycle"
```

When the script disables a device, it writes a stamp to the extension attribute: StaleLifecycle|2026-07-31.

On subsequent runs:
- Device **disabled + has stamp** — Normal lifecycle continues (delete evaluation)
- Device **enabled + has stamp** — Human re-enabled it. Script **skips it** and clears the stamp.
- Device **no stamp** — Normal evaluation (first time through lifecycle)

This prevents the disable loop where a helpdesk tech re-enables a device and the next script run disables it again. The script respects intentional operator overrides.

Set enableReEnableProtection to false to disable entirely — script reverts to v2.0 behavior.

---

### Graph API Batch Configuration (GraphBatchEngine)

```powershell
$GraphBatch_BatchSize       = 10
$GraphBatch_InitialDelay    = 1       # seconds
$GraphBatch_MaxDelay        = 30      # ceiling
$GraphBatch_MaxRetryPasses  = 3       # retry rounds
```

Uses **adaptive throttling** — delay doubles when throttled, halves after clean streaks. Failed individual requests are queued for retry (not the entire batch). Nothing is ever silently dropped.

**Presets:**
- **Conservative** (large tenants): BatchSize=10, InitialDelay=2, MaxDelay=30
- **Balanced** (most environments): BatchSize=10, InitialDelay=1, MaxDelay=30
- **Aggressive** (small tenants): BatchSize=20, InitialDelay=1, MaxDelay=15

---

### Pagination

```powershell
$deviceQueryPageSize = 500
```

Pages through devices 500 at a time, filtering in-flight. Only matching devices stay in memory. A 50,000-device tenant no longer loads everything into RAM.

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -Execute | Switch | OFF | Enable disable/delete operations |
| -DeleteEnabled | Switch | OFF | Enable delete (requires -Execute) |
| -SendEmail | Switch | OFF | Send HTML summary email |
| -WhatIf | Switch | OFF | Show operations without executing |
| -Confirm | Switch | OFF | Prompt before destructive batches |
| -StaleThreshold | Int | 90 | Days inactive before stale |
| -GracePeriod | Int | 30 | Days before eligible for disable |
| -DisableHold | Int | 60 | Days disabled before eligible for delete |
| -ReportPath | String | .\reports | Output directory |
| -ExclusionFile | String | .\exclusions.csv | Exclusion list path |

### Confidence Tiers

| How You Run It | What Happens |
|---|---|
| Azure_Stale_Data.ps1 | Dry-run — report only |
| Azure_Stale_Data.ps1 -Execute -WhatIf | Shows exact API calls that WOULD be made |
| Azure_Stale_Data.ps1 -Execute -Confirm | Prompts before each batch |
| Azure_Stale_Data.ps1 -Execute | Full send — disables eligible devices |
| Azure_Stale_Data.ps1 -Execute -DeleteEnabled | Full send — disables and deletes |

---

## Safety Design

| Safety Feature | How It Protects You |
|---------------|-------------------|
| Dry-run default | No changes without -Execute |
| Two-flag delete | Requires both -Execute AND -DeleteEnabled |
| ShouldProcess | -WhatIf shows operations, -Confirm prompts |
| Re-enable protection | Respects operator overrides (v2.1) |
| New device grace | Never disables devices younger than stale threshold (v2.1) |
| 3-layer server filter | OS + build number + name patterns |
| Mobile trust auto-add | Prevents silent zero-result runs (v2.1) |
| Dual exclusion system | Name patterns + CSV |
| 180-day lifecycle | Must age through ALL stages |
| Adaptive batch retry | Nothing silently dropped (v2.1) |
| Streaming pagination | Scales to any tenant size (v2.1) |

---

## Output Files

| File | When Generated | Contents |
|------|---------------|----------|
| StaleReport_*.csv | Every run | All stale devices with action classification |
| DisabledDevices_*.csv | Execute mode | Pre-action backup of disabled devices |
| DeletedDevices_*.csv | Execute + Delete mode | Final backup before deletion |
| FilteredDevices_*.csv | Every run (if servers caught) | Audit trail of server-filter exclusions |
| RunLog_*.json | Every run | Structured log with parameters, summary, every decision |

### Report Columns (v2.1)

- **DisplayName** — Device name as shown in Entra ID
- **DeviceId** — The Object ID (GUID) of the device
- **OperatingSystem** — Windows, macOS, Android, iOS, etc.
- **OSVersion** — Build number / version string
- **TrustType** — AzureAd, ServerAd, or Workplace
- **AccountEnabled** — Whether the device is currently enabled
- **LastSignIn** — Last approximate sign-in timestamp
- **CreatedDateTime** — When the device was created in Entra ID (new in v2.1)
- **LifecycleStamp** — Re-enable protection stamp value (new in v2.1)
- **RegisteredOwner** — The user registered as device owner
- **Action** — Reported, Disable-Eligible, Delete-Eligible, Excluded, or Skipped-ReEnabled
- **Reason** — Why it received that classification
- **RunDate** — When this report was generated

---

## App Registration Setup

1. **Create** App Registration in Entra ID (single tenant)
2. **Grant** API Permissions (Application):
   - Device.Read.All (query devices)
   - Device.ReadWrite.All (disable, delete, write extension attributes)
   - Directory.Read.All (read ownership)
   - Mail.Send (optional, only for -SendEmail)
3. **Admin consent** — Grant admin consent for your tenant
4. **Client secret** — Create one, copy the value immediately
5. **Update script** — Paste TenantId, ClientId, ClientSecret into USER CONFIGURATION

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Zero mobile devices found | Fixed in v2.1 — OS variant map + trust type expansion |
| -WhatIf does nothing | Fixed in v2.1 — now fully functional |
| New devices immediately disabled | Fixed in v2.1 — CreatedDateTime guard |
| Devices re-disabled after re-enable | Fixed in v2.1 — re-enable protection |
| Throttling (429 errors) | Reduce GraphBatch_BatchSize, increase GraphBatch_InitialDelay |
| Out of memory (large tenants) | Fixed in v2.1 — streaming pagination |
| Module not found | Install-Module Microsoft.Graph -Scope CurrentUser |
| Auth 403 | Check App Registration has Device.ReadWrite.All + admin consent |

---

## FAQ

**Q: Will this touch servers?**
A: No. The 3-layer server filter catches servers regardless of naming convention.

**Q: What about devices re-enabled by humans?**
A: v2.1 detects this via the lifecycle stamp and skips the device — respecting the operator decision. Stamp is cleared, device starts fresh if it goes stale again later.

**Q: Can I run this for just one device type?**
A: Yes. Set targetOS to only include what you want. The OS variant map covers all known Entra reporting names automatically.

**Q: What if the script fails mid-run?**
A: Each operation is independent. The GraphBatchEngine retries transient failures and reports permanent failures. One bad device never kills the whole run.

**Q: Does dry-run hit the API?**
A: Read-only queries to generate reports. No disable/delete requests are sent.

**Q: Is there a raccoon in my Entra ID tenant?**
A: Statistically? Yes. Somewhere between your stale devices and abandoned guest accounts, there is a digital trash panda making itself comfortable. This script is how you evict it — humanely, with a 180-day notice period and a stamp on the door proving you were here first.

---

## Disclaimer

This script is provided **as-is**, without warranty of any kind. The author is not responsible for any damage, data loss, device lockouts, confused help desk calls, or unexpected raccoon infestations resulting from its use.

**Always test with dry-run mode first.** Use -WhatIf to preview exact operations. Then — and only then — flip the switch.

The biggest risk is doing nothing and letting your stale device count grow until it achieves sentience and starts filing its own helpdesk tickets.

---

*Built with care, caffeine, and a healthy respect for the destructive power of automation.*
*— Mitchell Brown*