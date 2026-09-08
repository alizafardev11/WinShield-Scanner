# Windows Security Read-Only Scanner

A single-file PowerShell script that audits the local security configuration of a Windows machine and produces a self-contained, dark-themed **HTML dashboard report** (`Security_Report.html`). It is a **configuration and posture auditor**, not an exploit tool, a patch scanner, or a CVE database — see [Limitations](#limitations--what-this-is-not) before treating it as a full vulnerability assessment.

---

## Safety guarantees

The script is strictly **read-only**. It never:

- Changes registry values
- Changes firewall rules
- Triggers a Defender scan
- Starts, stops, or reconfigures services
- Creates, deletes, or modifies user accounts
- Sends network probes to other hosts
- Writes any file other than the single HTML report, in the same folder as the script

Every data-gathering block is wrapped in `try/catch`; if a check fails (insufficient permission, missing module, unsupported OS feature) it is logged internally and skipped — the scan continues rather than aborting.

> **Recommended:** run from an elevated (Administrator) PowerShell session for full coverage. Several checks (BitLocker, Defender status, local users/admins, services) return partial or no data without elevation.

---

## Requirements

| Requirement | Notes |
|---|---|
| OS | Windows 10 / 11, or Windows Server 2016+ |
| PowerShell | 5.1 or later (Windows PowerShell or PowerShell 7) |
| Privileges | Administrator recommended (not strictly required, but coverage drops without it) |
| Modules used | Built-in: `NetTCPIP`, `NetSecurity`, `SmbShare`, `Defender`, `BitLocker`, `CimCmdlets`, `Microsoft.PowerShell.LocalAccounts` — all standard on modern Windows |

---

## Usage

```powershell
# From an elevated PowerShell prompt, in the folder containing the script:
.\Windows-Security-Scanner.ps1
```

If your execution policy blocks the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\Windows-Security-Scanner.ps1
```

**Output:** `Security_Report.html`, written to the same folder as the script. Open it in any browser — it is fully self-contained (no external CSS/JS/CDN dependencies), so it works offline and can be emailed or archived as-is.

---

## What the report looks like

- **Header** — scan title and a "STRICTLY READ-ONLY" badge.
- **Totals strip** — quick counts of Critical / High / Medium / Low findings.
- **Gauge dashboard** — 8 cards (Firewall, Defender, RDP, SMB, Users, Listening Ports, BitLocker, Security Events), each with an icon, a severity badge, a metric count, and a colored ring gauge summarizing that category's worst finding.
- **Detail sections** (in order): System Information, Platform & Credential Security, Password & Lockout Policy, Security Findings (searchable/filterable table), Listening Ports, Windows Firewall, Antivirus, Network Shares (SMB), Local Users, Local Administrators, Automatic Services, Installed Software, Security Events.
- **Findings table** supports live text search and severity filter buttons (client-side JS, no network calls).

---

## What it checks

### System & Platform
- OS/build/architecture, hardware, BIOS, RAM, last boot, PowerShell version
- Secure Boot state
- TPM presence and readiness
- Credential Guard running status

### Antivirus / Endpoint Protection
- Microsoft Defender: enabled, real-time protection, tamper protection, signature age
- Third-party AV registered in Security Center (product name only, since the OS doesn't expose vendor internals uniformly)

### Firewall
- Per-profile (Domain/Private/Public) enabled state
- Default inbound action (flags `Allow` as a finding)

### Network Exposure
- All TCP/UDP listening ports, with owning process, PID, and interface binding (all-interfaces / localhost-only / specific)
- Cross-references ports against a sensitive-service list (FTP, Telnet, SMB, RDP, VNC, SQL Server, Oracle, MySQL, PostgreSQL, Redis, MongoDB, WinRM, Docker API)
- LLMNR (multicast name resolution) exposure

### Remote Access
- RDP enabled/disabled
- RDP Network Level Authentication (NLA) status

### SMB / File Sharing
- SMBv1 enabled
- SMB signing required
- Enumerates all SMB shares and flags any granting the `Everyone` group access

### Access Control & Credentials
- UAC enabled/disabled
- WDigest plaintext credential caching
- PowerShell Script Block Logging enabled
- AutoRun/AutoPlay fully disabled

### Accounts
- All local users: enabled state, password-required flag, last logon
- Guest account enabled
- Accounts with the "password not required" flag set (see [accuracy note](#accuracy-notes) below)
- Local Administrators group membership (and a soft warning if unusually large)
- Password/lockout policy via `net accounts`: minimum password length, lockout threshold, maximum password age

### Patch Management
- Installed hotfix list and approximate age of the most recent one (age-based heuristic only — see Limitations)

### Disk / Storage
- BitLocker status per volume; flags system drive not fully encrypted
- Free disk space; flags volumes under 10% free

### Services, Startup & Software
- All Windows services (state, start mode); flags unquoted service paths containing spaces (local privilege-escalation vector)
- Startup commands inventory
- Installed software inventory (from registry Uninstall keys, both 32/64-bit and per-user)

### Event Logs
- Security log: failed logons and account-management events (4625, 4720, 4722, 4724–4726, 4697) from the last 7 days
- System log: service-installation events (7045) from the last 7 days

---

## Severity levels

| Severity | Meaning |
|---|---|
| **Critical** | Reserved for the most severe class of issue (defined in the rule set; none of the current checks trigger it by default) |
| **High** | Directly exploitable or a significant control gap (e.g. SMBv1 enabled, Guest account enabled, unquoted service path) |
| **Medium** | Weakens defenses but requires another condition to be exploitable (e.g. no lockout threshold, outdated signatures) |
| **Low** | Hygiene / defense-in-depth gap (e.g. LLMNR not disabled, AutoRun not fully disabled) |

The gauge dashboard also uses **Good** (green) for categories with no findings.

---

## Accuracy notes

- **"Password Not Required" finding:** this reflects the Windows `PasswordRequired` account flag (`UF_PASSWD_NOTREQD`), which controls whether the account is *permitted* to have a blank password — it does **not** mean the account currently has a blank password. An account can have a strong password today and still trigger this finding if the flag is off, because the flag can be exploited later (e.g. `net user <name> /password:""`) without Windows rejecting it. Verify with `net user <name>` (look for `Password required`) before treating it as an active compromise.
- **Patch age heuristic:** the "Windows Patch Appears Old" finding is based on the newest `InstalledOn` date returned by `Get-HotFix`, which is an imperfect proxy — it does **not** check which CVEs are actually patched. See [Limitations](#limitations--what-this-is-not).
- **Recommendation text** for every finding is a static string authored per rule, reflecting general Windows hardening practice consistent with CIS Benchmarks / Microsoft Security Baselines / DISA STIGs — it is not pulled live from any of those sources and is not version-pinned to a specific control ID.

---

## Limitations / what this is not

This script audits **configuration state**, not **vulnerability presence**. Gaps to be aware of:

- **No CVE correlation.** It cannot tell you which specific CVEs are unpatched — only that the newest installed hotfix looks old. Use WSUS/Intune/SCCM compliance data or a dedicated scanner (Nessus, OpenVAS, Qualys) for real patch-vulnerability mapping.
- **No file/folder ACL auditing** (e.g. writable paths under Program Files, weak service binary permissions).
- **No scheduled task audit** — a common persistence mechanism, not currently inventoried.
- **No certificate store review** (expired, self-signed, or unexpected root CAs).
- **No browser or Office hardening checks** (macro settings, protected view, extensions).
- **No Active Directory / domain checks** — this is a local-machine assessment only.
- **No LAPS / local admin password rotation check.**
- **No event log size/retention check** — small logs can silently roll over.

If you need a genuinely "complete" assessment, pair this with a CVE-aware scanner and, for domain-joined fleets, a GPO/AD-specific review.

---

## Customization

- **Sensitive port list** — edit the `$SensitivePorts` hashtable to add/remove ports relevant to your environment.
- **Event log lookback window** — change `(Get-Date).AddDays(-7)` in the Security/System events sections.
- **Password length / patch-age thresholds** — adjust the literal thresholds in the relevant `if` blocks (e.g. `-lt 8`, `-gt 90`).
- **Dashboard cards** — the `$DashboardCards` array near the "SUMMARY" section controls which categories appear on the gauge dashboard; add an entry with an `Icon`, `Title`, `Subtitle`, `Count`, and `Severity` (via `Get-CategorySeverity`) to add a new card.

---

## File output

| File | Description |
|---|---|
| `Security_Report.html` | The only file the script writes. Self-contained, offline-viewable, printable. |

No logs, temp files, or exports are created elsewhere on disk.
