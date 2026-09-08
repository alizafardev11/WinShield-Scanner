# ============================================================
# WINDOWS SECURITY READ-ONLY SCANNER
# HTML REPORT ONLY (GAUGE DASHBOARD EDITION)
#
# STRICTLY READ-ONLY
# - No registry changes
# - No firewall changes
# - No Defender scans
# - No service changes
# - No user changes
# - No network probing
# - No system configuration changes
#
# Output:
# Security_Report.html
#
# The report is generated in the SAME folder as this script.
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

# ------------------------------------------------------------
# SCRIPT / OUTPUT LOCATION
# ------------------------------------------------------------

$ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition

if ([string]::IsNullOrWhiteSpace($ScriptFolder)) {
    $ScriptFolder = Get-Location
}

$ReportFile = Join-Path $ScriptFolder "Security_Report.html"

$ScanStart = Get-Date

# ------------------------------------------------------------
# DATA CONTAINERS
# ------------------------------------------------------------

$Findings         = [System.Collections.Generic.List[object]]::new()
$Errors           = [System.Collections.Generic.List[object]]::new()
$ListeningPorts   = @()
$UdpPorts         = @()
$Processes        = @()
$Services         = @()
$Startup          = @()
$Software         = @()
$Users            = @()
$Administrators   = @()
$Firewall         = @()
$SecurityEvents   = @()
$SystemEvents     = @()
$HotFixes         = @()
$Antivirus        = @()
$BitLocker        = @()
$DiskInfo         = @()
$Shares           = @()
$PasswordPolicy   = [ordered]@{}
$UnquotedServices = @()
$SecureBootState  = "Unknown"
$TpmInfo          = $null
$CredGuardRunning = $false

# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Description,
        [string]$Recommendation
    )

    $Findings.Add([PSCustomObject]@{
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Description    = $Description
        Recommendation = $Recommendation
    })
}

function Add-ErrorRecord {
    param(
        [string]$Section,
        [string]$Message
    )

    $Errors.Add([PSCustomObject]@{
        Section = $Section
        Message = $Message
    })
}

function HtmlEncode {
    param([object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ProcessNameSafe {
    param([int]$ProcessId)

    try {
        return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
    }
    catch {
        return "Unknown"
    }
}

function Get-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        return Get-ItemPropertyValue `
            -Path $Path `
            -Name $Name `
            -ErrorAction Stop
    }
    catch {
        return $null
    }
}

# Returns the highest severity found among $Findings whose
# Category is in the supplied list. "Good" if none found.
function Get-CategorySeverity {
    param([string[]]$Categories)

    $Rank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }

    $Matches = $Findings | Where-Object { $Categories -contains $_.Category }

    if (-not $Matches) {
        return "Good"
    }

    $Best = $Matches |
        Sort-Object { $Rank[$_.Severity] } -Descending |
        Select-Object -First 1

    return $Best.Severity
}

function Get-SeverityMeta {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return @{ Label = "CRITICAL"; Color = "var(--critical)"; Pct = 95 } }
        "High"     { return @{ Label = "HIGH";     Color = "var(--high)";     Pct = 78 } }
        "Medium"   { return @{ Label = "MEDIUM";   Color = "var(--medium)";   Pct = 55 } }
        "Low"      { return @{ Label = "LOW";      Color = "var(--low)";      Pct = 30 } }
        default    { return @{ Label = "GOOD";     Color = "var(--good)";     Pct = 12 } }
    }
}

# ------------------------------------------------------------
# SYSTEM INFORMATION
# ------------------------------------------------------------

$SystemInfo = [PSCustomObject]@{}

try {

    $OS   = Get-CimInstance Win32_OperatingSystem
    $CS   = Get-CimInstance Win32_ComputerSystem
    $BIOS = Get-CimInstance Win32_BIOS

    $SystemInfo = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        UserName     = $env:USERNAME
        OS           = $OS.Caption
        Version      = $OS.Version
        Build        = $OS.BuildNumber
        Architecture = $OS.OSArchitecture
        Manufacturer = $CS.Manufacturer
        Model        = $CS.Model
        BIOSVersion  = $BIOS.SMBIOSBIOSVersion
        TotalRAMGB   = [math]::Round(
            $CS.TotalPhysicalMemory / 1GB, 2
        )
        LastBoot     = $OS.LastBootUpTime
        PowerShell   = $PSVersionTable.PSVersion.ToString()
    }

}
catch {
    Add-ErrorRecord "System Information" $_.Exception.Message
}

# ------------------------------------------------------------
# WINDOWS DEFENDER
# ------------------------------------------------------------

try {

    $Defender = Get-MpComputerStatus

    if ($Defender) {

        $Antivirus += [PSCustomObject]@{
            Product            = "Microsoft Defender"
            Enabled            = $Defender.AntivirusEnabled
            RealTimeProtection = $Defender.RealTimeProtectionEnabled
            BehaviorMonitoring = $Defender.BehaviorMonitorEnabled
            IOAVProtection     = $Defender.IOAVProtectionEnabled
            TamperProtection   = $Defender.IsTamperProtected
            SignatureVersion   = $Defender.AntivirusSignatureVersion
            SignatureAge       = $Defender.AntivirusSignatureAge
        }

        if (-not $Defender.AntivirusEnabled) {

            Add-Finding `
                "High" `
                "Antivirus" `
                "Microsoft Defender Disabled" `
                "Microsoft Defender antivirus protection is disabled." `
                "Verify that an approved endpoint protection product is active."

        }

        if (-not $Defender.RealTimeProtectionEnabled) {

            Add-Finding `
                "High" `
                "Antivirus" `
                "Real-Time Protection Disabled" `
                "Microsoft Defender real-time protection is disabled." `
                "Enable real-time protection or verify an approved alternative."

        }

        if (-not $Defender.IsTamperProtected) {

            Add-Finding `
                "Medium" `
                "Antivirus" `
                "Tamper Protection Disabled" `
                "Microsoft Defender Tamper Protection is not enabled, allowing security settings to be changed by malware or a local admin." `
                "Enable Tamper Protection in Windows Security settings."

        }

        if ($Defender.AntivirusSignatureAge -gt 7) {

            Add-Finding `
                "Medium" `
                "Antivirus" `
                "Outdated Antivirus Signatures" `
                "Microsoft Defender signatures are approximately $($Defender.AntivirusSignatureAge) day(s) old." `
                "Update Defender signatures or verify automatic updates are functioning."

        }
    }

}
catch {
    Add-ErrorRecord "Microsoft Defender" $_.Exception.Message
}

# ------------------------------------------------------------
# REGISTERED ANTIVIRUS
# ------------------------------------------------------------

try {

    $AVProducts = Get-CimInstance `
        -Namespace "root\SecurityCenter2" `
        -ClassName AntiVirusProduct

    foreach ($AV in $AVProducts) {

        $Antivirus += [PSCustomObject]@{
            Product            = $AV.displayName
            Enabled            = "Detected"
            RealTimeProtection = "Unknown"
            BehaviorMonitoring = "Unknown"
            IOAVProtection     = "Unknown"
            TamperProtection   = "Unknown"
            SignatureVersion   = "Unknown"
            SignatureAge       = "Unknown"
        }

    }

}
catch {
    Add-ErrorRecord "Antivirus Inventory" $_.Exception.Message
}

# ------------------------------------------------------------
# FIREWALL
# ------------------------------------------------------------

try {

    $Firewall = @(Get-NetFirewallProfile |
        Select-Object Name,
            Enabled,
            DefaultInboundAction,
            DefaultOutboundAction)

    foreach ($Profile in $Firewall) {

        if (-not $Profile.Enabled) {

            Add-Finding `
                "High" `
                "Firewall" `
                "$($Profile.Name) Firewall Disabled" `
                "The Windows Firewall profile is disabled." `
                "Enable the firewall profile according to your security baseline."

        }

        if ($Profile.DefaultInboundAction -eq "Allow") {

            Add-Finding `
                "Medium" `
                "Firewall" `
                "$($Profile.Name) Default Inbound Action Is Allow" `
                "The default inbound action for the $($Profile.Name) profile allows traffic by default." `
                "Set the default inbound action to Block unless explicitly required."

        }

    }

}
catch {
    Add-ErrorRecord "Firewall" $_.Exception.Message
}

# ------------------------------------------------------------
# WINDOWS HOTFIXES
# ------------------------------------------------------------

try {

    $HotFixes = @(Get-HotFix |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 100 `
            HotFixID,
            Description,
            InstalledOn,
            InstalledBy)

    $LatestHotFix = $HotFixes |
        Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1

    if ($LatestHotFix) {

        $PatchAge = ((Get-Date) - $LatestHotFix.InstalledOn).Days

        if ($PatchAge -gt 90) {

            Add-Finding `
                "Medium" `
                "Patch Management" `
                "Windows Patch Appears Old" `
                "The latest detected hotfix is approximately $PatchAge days old." `
                "Review Windows Update and confirm current security patches are installed."

        }

    }
    else {

        Add-Finding `
            "Low" `
            "Patch Management" `
            "No Hotfix Install Dates Found" `
            "No hotfixes with a resolvable install date were found via Get-HotFix." `
            "Confirm patch status manually via Windows Update or WSUS/Intune reporting."

    }

}
catch {
    Add-ErrorRecord "Windows Updates" $_.Exception.Message
}

# ------------------------------------------------------------
# TCP LISTENING PORTS
# ------------------------------------------------------------

try {

    $TCP = @(Get-NetTCPConnection -State Listen)

    foreach ($Connection in $TCP) {

        $ProcessName = Get-ProcessNameSafe $Connection.OwningProcess

        $Binding = "Specific Interface"

        if (
            $Connection.LocalAddress -eq "0.0.0.0" -or
            $Connection.LocalAddress -eq "::"
        ) {
            $Binding = "All Interfaces"
        }
        elseif (
            $Connection.LocalAddress -eq "127.0.0.1" -or
            $Connection.LocalAddress -eq "::1"
        ) {
            $Binding = "Localhost Only"
        }

        $ListeningPorts += [PSCustomObject]@{
            Protocol     = "TCP"
            LocalAddress = $Connection.LocalAddress
            Port         = $Connection.LocalPort
            PID          = $Connection.OwningProcess
            Process      = $ProcessName
            Binding      = $Binding
        }

    }

}
catch {
    Add-ErrorRecord "TCP Ports" $_.Exception.Message
}

# ------------------------------------------------------------
# UDP PORTS
# ------------------------------------------------------------

try {

    $UDP = @(Get-NetUDPEndpoint)

    foreach ($Connection in $UDP) {

        $ProcessName = Get-ProcessNameSafe $Connection.OwningProcess

        $Binding = "Specific Interface"

        if (
            $Connection.LocalAddress -eq "0.0.0.0" -or
            $Connection.LocalAddress -eq "::"
        ) {
            $Binding = "All Interfaces"
        }
        elseif (
            $Connection.LocalAddress -eq "127.0.0.1" -or
            $Connection.LocalAddress -eq "::1"
        ) {
            $Binding = "Localhost Only"
        }

        $UdpPorts += [PSCustomObject]@{
            Protocol     = "UDP"
            LocalAddress = $Connection.LocalAddress
            Port         = $Connection.LocalPort
            PID          = $Connection.OwningProcess
            Process      = $ProcessName
            Binding      = $Binding
        }

    }

}
catch {
    Add-ErrorRecord "UDP Ports" $_.Exception.Message
}

# ------------------------------------------------------------
# PORT SECURITY REVIEW
# ------------------------------------------------------------

$SensitivePorts = @{
    21    = "FTP"
    23    = "Telnet"
    25    = "SMTP"
    445   = "SMB"
    3389  = "RDP"
    5900  = "VNC"
    1433  = "Microsoft SQL Server"
    1521  = "Oracle"
    3306  = "MySQL"
    5432  = "PostgreSQL"
    6379  = "Redis"
    27017 = "MongoDB"
    5985  = "WinRM HTTP"
    5986  = "WinRM HTTPS"
    2375  = "Docker API"
}

foreach ($Port in $ListeningPorts) {

    $PortNumber = [int]$Port.Port

    if ($SensitivePorts.ContainsKey($PortNumber)) {

        $ServiceName = $SensitivePorts[$PortNumber]

        $Severity = "Medium"

        if ($PortNumber -in @(23,445,2375)) {
            $Severity = "High"
        }

        Add-Finding `
            $Severity `
            "Network Exposure" `
            "$ServiceName Listening" `
            "$ServiceName is listening on $($Port.LocalAddress):$PortNumber." `
            "Confirm the service is required, secured, patched and appropriately restricted."

    }

}

# ------------------------------------------------------------
# RDP
# ------------------------------------------------------------

$RDP = Get-RegistryValueSafe `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    "fDenyTSConnections"

if ($RDP -eq 0) {

    Add-Finding `
        "Medium" `
        "Remote Access" `
        "Remote Desktop Enabled" `
        "Remote Desktop is enabled on this system." `
        "Confirm RDP is required and restrict access using firewall/VPN/network controls."

    $NLA = Get-RegistryValueSafe `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        "UserAuthentication"

    if ($NLA -eq 0) {

        Add-Finding `
            "High" `
            "Remote Access" `
            "RDP Network Level Authentication Disabled" `
            "Remote Desktop is enabled without Network Level Authentication (NLA), allowing pre-authentication connection attempts." `
            "Enable NLA for all RDP connections."

    }

}

# ------------------------------------------------------------
# SMB
# ------------------------------------------------------------

try {

    $SMB = Get-SmbServerConfiguration

    if ($SMB.EnableSMB1Protocol) {

        Add-Finding `
            "High" `
            "SMB" `
            "SMBv1 Enabled" `
            "SMBv1 is enabled." `
            "Disable SMBv1 if it is not required."

    }

    if (-not $SMB.RequireSecuritySignature) {

        Add-Finding `
            "Medium" `
            "SMB" `
            "SMB Signing Not Required" `
            "SMB signing is not required." `
            "Evaluate requiring SMB signing according to your security baseline."

    }

}
catch {
    Add-ErrorRecord "SMB" $_.Exception.Message
}

# ------------------------------------------------------------
# NETWORK SHARES
# ------------------------------------------------------------

try {

    $SmbShares = @(Get-SmbShare | Where-Object { $_.Name -notin @("IPC$") })

    foreach ($Share in $SmbShares) {

        $AccessEntries = @(Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue)

        $EveryoneEntry = $AccessEntries |
            Where-Object { $_.AccountName -match "Everyone" }

        $EveryoneAccess = if ($EveryoneEntry) {
            ($EveryoneEntry | ForEach-Object { "$($_.AccessControlType):$($_.AccessRight)" }) -join ", "
        } else {
            "None"
        }

        $Shares += [PSCustomObject]@{
            Name            = $Share.Name
            Path            = $Share.Path
            Description     = $Share.Description
            EveryoneAccess  = $EveryoneAccess
        }

        if ($EveryoneEntry -and $EveryoneEntry.AccessControlType -eq "Allow") {

            Add-Finding `
                "High" `
                "File Sharing" `
                "Share '$($Share.Name)' Grants Everyone Access" `
                "The SMB share '$($Share.Name)' ($($Share.Path)) grants the 'Everyone' group $($EveryoneEntry.AccessRight) access." `
                "Restrict share permissions to specific users or groups following least privilege."

        }

    }

}
catch {
    Add-ErrorRecord "Network Shares" $_.Exception.Message
}

# ------------------------------------------------------------
# UAC
# ------------------------------------------------------------

$UAC = Get-RegistryValueSafe `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    "EnableLUA"

if ($UAC -eq 0) {

    Add-Finding `
        "High" `
        "Access Control" `
        "UAC Disabled" `
        "User Account Control is disabled." `
        "Enable UAC according to your security baseline."

}

# ------------------------------------------------------------
# CREDENTIAL / LATERAL MOVEMENT HARDENING
# ------------------------------------------------------------

$WDigest = Get-RegistryValueSafe `
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    "UseLogonCredential"

if ($WDigest -eq 1) {

    Add-Finding `
        "High" `
        "Credential Exposure" `
        "WDigest Plaintext Credential Caching Enabled" `
        "WDigest is configured to cache reversible/plaintext-recoverable credentials in LSASS memory." `
        "Set UseLogonCredential to 0 (default on modern Windows) to prevent plaintext credential caching."

}

$LLMNR = Get-RegistryValueSafe `
    "HKLM:\SOFTWARE\policies\Microsoft\Windows NT\DNSClient" `
    "EnableMulticast"

if ($LLMNR -ne 0) {

    Add-Finding `
        "Low" `
        "Network Exposure" `
        "LLMNR Not Explicitly Disabled" `
        "Link-Local Multicast Name Resolution (LLMNR) is not explicitly disabled, which can be abused for credential relay/poisoning attacks on the local network." `
        "Disable LLMNR via Group Policy (Turn off Multicast Name Resolution) if not required."

}

$ScriptBlockLogging = Get-RegistryValueSafe `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    "EnableScriptBlockLogging"

if ($ScriptBlockLogging -ne 1) {

    Add-Finding `
        "Low" `
        "Auditing" `
        "PowerShell Script Block Logging Disabled" `
        "PowerShell Script Block Logging is not enabled, reducing visibility into malicious or obfuscated PowerShell activity." `
        "Enable Script Block Logging via Group Policy for improved detection and forensics."

}

$AutoRun = Get-RegistryValueSafe `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    "NoDriveTypeAutoRun"

if ($AutoRun -ne 255) {

    Add-Finding `
        "Low" `
        "Removable Media" `
        "AutoRun Not Fully Disabled" `
        "AutoRun/AutoPlay does not appear to be fully disabled for all drive types (value: $AutoRun)." `
        "Set NoDriveTypeAutoRun to 255 (0xFF) via Group Policy to disable AutoRun on all drive types."

}

# ------------------------------------------------------------
# FIRMWARE / PLATFORM SECURITY
# ------------------------------------------------------------

try {
    $SecureBootRaw = Confirm-SecureBootUEFI -ErrorAction Stop

    $SecureBootState = if ($SecureBootRaw) { "Enabled" } else { "Disabled" }

    if (-not $SecureBootRaw) {

        Add-Finding `
            "Medium" `
            "Firmware Security" `
            "Secure Boot Disabled" `
            "Secure Boot is disabled or unsupported on this system." `
            "Enable Secure Boot in UEFI firmware settings if the hardware supports it."

    }
}
catch {
    $SecureBootState = "Unavailable (Legacy BIOS or Unsupported)"
}

try {
    $TpmInfo = Get-Tpm -ErrorAction Stop

    if ($TpmInfo -and (-not $TpmInfo.TpmPresent -or -not $TpmInfo.TpmReady)) {

        Add-Finding `
            "Low" `
            "Firmware Security" `
            "TPM Not Present or Not Ready" `
            "A Trusted Platform Module (TPM) was not detected or is not ready for use." `
            "Confirm TPM 2.0 is present, enabled in firmware, and initialized."

    }
}
catch {
    Add-ErrorRecord "TPM" $_.Exception.Message
}

try {
    $DeviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop

    if ($DeviceGuard) {
        $CredGuardRunning = $DeviceGuard.SecurityServicesRunning -contains 1
    }

    if (-not $CredGuardRunning) {

        Add-Finding `
            "Low" `
            "Credential Protection" `
            "Credential Guard Not Running" `
            "Windows Defender Credential Guard does not appear to be running on this system." `
            "Consider enabling Credential Guard on supported hardware to isolate and protect LSASS credentials."

    }
}
catch {
    Add-ErrorRecord "Credential Guard" $_.Exception.Message
}

# ------------------------------------------------------------
# LOCAL USERS
# ------------------------------------------------------------

try {

    $Users = @(Get-LocalUser |
        Select-Object Name,
            Enabled,
            PasswordRequired,
            PasswordExpires,
            LastLogon)

    foreach ($User in $Users) {

        if (
            $User.Enabled -and
            $User.PasswordRequired -eq $false
        ) {

            Add-Finding `
                "High" `
                "Account Security" `
                "Password Not Required" `
                "Enabled account '$($User.Name)' does not require a password." `
                "Review the account and require a strong password or disable the account if unnecessary."

        }

        if (
            $User.Name -eq "Guest" -and
            $User.Enabled
        ) {

            Add-Finding `
                "High" `
                "Account Security" `
                "Guest Account Enabled" `
                "The built-in Guest account is enabled." `
                "Disable the Guest account unless there is a specific, documented business requirement."

        }

    }

}
catch {
    Add-ErrorRecord "Local Users" $_.Exception.Message
}

# ------------------------------------------------------------
# PASSWORD & LOCKOUT POLICY
# ------------------------------------------------------------

try {

    $NetAccountsOutput = net accounts

    foreach ($Line in $NetAccountsOutput) {

        if ($Line -match "^(.+?):\s+(.+)$") {
            $PasswordPolicy[$Matches[1].Trim()] = $Matches[2].Trim()
        }

    }

    $MinPwLenRaw = $PasswordPolicy["Minimum password length"]
    $LockoutThresholdRaw = $PasswordPolicy["Lockout threshold"]
    $MaxPwAgeRaw = $PasswordPolicy["Maximum password age (days)"]

    if ($MinPwLenRaw -and ($MinPwLenRaw -as [int]) -ne $null -and [int]$MinPwLenRaw -lt 8) {

        Add-Finding `
            "Medium" `
            "Password Policy" `
            "Weak Minimum Password Length" `
            "The minimum password length policy is set to $MinPwLenRaw character(s)." `
            "Increase the minimum password length to at least 8-14 characters, or adopt a passphrase policy."

    }

    if ($LockoutThresholdRaw -eq "Never") {

        Add-Finding `
            "Medium" `
            "Password Policy" `
            "No Account Lockout Threshold" `
            "The account lockout threshold is not configured, allowing unlimited password guessing attempts." `
            "Configure an account lockout threshold (e.g. 5-10 attempts) to mitigate brute-force and password-spray attacks."

    }

    if ($MaxPwAgeRaw -eq "Unlimited") {

        Add-Finding `
            "Low" `
            "Password Policy" `
            "Passwords Never Expire" `
            "The maximum password age policy is set to Unlimited." `
            "Consider a documented password/passphrase rotation policy aligned with your security baseline, or compensate with MFA."

    }

}
catch {
    Add-ErrorRecord "Password Policy" $_.Exception.Message
}

# ------------------------------------------------------------
# ADMINISTRATORS
# ------------------------------------------------------------

try {

    $Administrators = @(Get-LocalGroupMember `
        -Group "Administrators" |
        Select-Object Name,
            ObjectClass,
            PrincipalSource)

    if ($Administrators.Count -gt 5) {

        Add-Finding `
            "Low" `
            "Account Security" `
            "Large Number of Local Administrators" `
            "$($Administrators.Count) members were found in the local Administrators group." `
            "Review membership and remove accounts that do not require standing administrative access."

    }

}
catch {
    Add-ErrorRecord "Administrators" $_.Exception.Message
}

# ------------------------------------------------------------
# SERVICES
# ------------------------------------------------------------

try {

    $Services = @(Get-CimInstance Win32_Service |
        Select-Object Name,
            DisplayName,
            State,
            StartMode,
            StartName,
            PathName)

    foreach ($Service in $Services) {

        if (-not $Service.PathName) { continue }

        $Path = $Service.PathName.Trim()

        if (
            $Path -notmatch '^"' -and
            $Path -match '\s' -and
            $Path -match '\.exe'
        ) {

            $ExeSegment = $Path.Substring(0, $Path.ToLower().IndexOf(".exe") + 4)

            if ($ExeSegment -match '\s') {
                $UnquotedServices += "$($Service.Name) ($($Service.DisplayName))"
            }

        }

    }

    if ($UnquotedServices.Count -gt 0) {

        $Sample = ($UnquotedServices | Select-Object -First 10) -join "; "

        Add-Finding `
            "High" `
            "Service Configuration" `
            "Unquoted Service Path(s) Detected" `
            "$($UnquotedServices.Count) service(s) have an unquoted executable path containing spaces, which can allow local privilege escalation. Examples: $Sample" `
            "Wrap the affected service ImagePath values in quotation marks."

    }

}
catch {
    Add-ErrorRecord "Services" $_.Exception.Message
}

# ------------------------------------------------------------
# STARTUP
# ------------------------------------------------------------

try {

    $Startup = @(Get-CimInstance Win32_StartupCommand |
        Select-Object Name,
            Command,
            Location,
            User)

}
catch {
    Add-ErrorRecord "Startup Programs" $_.Exception.Message
}

# ------------------------------------------------------------
# INSTALLED SOFTWARE
# ------------------------------------------------------------

try {

    $Paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $Paths) {

        $Items = Get-ItemProperty $Path

        foreach ($Item in $Items) {

            if ($Item.DisplayName) {

                $Software += [PSCustomObject]@{
                    Name      = $Item.DisplayName
                    Version   = $Item.DisplayVersion
                    Publisher = $Item.Publisher
                }

            }

        }

    }

    $Software = $Software | Sort-Object Name -Unique

}
catch {
    Add-ErrorRecord "Installed Software" $_.Exception.Message
}

# ------------------------------------------------------------
# BITLOCKER
# ------------------------------------------------------------

try {

    $BitLocker = @(Get-BitLockerVolume |
        Select-Object MountPoint,
            VolumeStatus,
            ProtectionStatus,
            EncryptionMethod)

    foreach ($Volume in $BitLocker) {

        if (
            $Volume.MountPoint -eq $env:SystemDrive -and
            $Volume.VolumeStatus -ne "FullyEncrypted"
        ) {

            Add-Finding `
                "Medium" `
                "Disk Encryption" `
                "System Drive Not Fully Encrypted" `
                "The system drive is not fully encrypted according to BitLocker." `
                "Review organizational disk encryption requirements."

        }

    }

}
catch {
    Add-ErrorRecord "BitLocker" $_.Exception.Message
}

# ------------------------------------------------------------
# RUNNING PROCESSES
# CommandLine intentionally NOT collected.
# ------------------------------------------------------------

try {

    $Processes = @(Get-CimInstance Win32_Process |
        Select-Object Name,
            ProcessId,
            ParentProcessId,
            ExecutablePath)

}
catch {
    Add-ErrorRecord "Processes" $_.Exception.Message
}

# ------------------------------------------------------------
# SECURITY EVENTS
# ------------------------------------------------------------

try {

    $SecurityEvents = @(Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625,4720,4722,4724,4725,4726,4697
        StartTime = (Get-Date).AddDays(-7)
    } -MaxEvents 300 |
        Select-Object TimeCreated,
            Id,
            LevelDisplayName,
            ProviderName,
            Message)

}
catch {
    Add-ErrorRecord "Security Events" $_.Exception.Message
}

# ------------------------------------------------------------
# SYSTEM SERVICE INSTALLATION EVENTS
# ------------------------------------------------------------

try {

    $SystemEvents = @(Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        Id        = 7045
        StartTime = (Get-Date).AddDays(-7)
    } -MaxEvents 100 |
        Select-Object TimeCreated,
            Id,
            LevelDisplayName,
            ProviderName,
            Message)

}
catch {
    Add-ErrorRecord "System Events" $_.Exception.Message
}

# ------------------------------------------------------------
# DISK SPACE
# ------------------------------------------------------------

try {

    $DiskInfo = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID,
            VolumeName,
            FileSystem,
            @{Name="SizeGB";Expression={
                if ($_.Size) {
                    [math]::Round($_.Size / 1GB, 2)
                } else { 0 }
            }},
            @{Name="FreeGB";Expression={
                if ($_.FreeSpace) {
                    [math]::Round($_.FreeSpace / 1GB, 2)
                } else { 0 }
            }})

    foreach ($Disk in $DiskInfo) {

        if ($Disk.SizeGB -gt 0) {

            $FreePercent = [math]::Round(
                ($Disk.FreeGB / $Disk.SizeGB) * 100,
                1
            )

            if ($FreePercent -lt 10) {

                Add-Finding `
                    "Medium" `
                    "Storage" `
                    "Low Disk Space" `
                    "$($Disk.DeviceID) has only $FreePercent% free space." `
                    "Free disk space and investigate unnecessary files."

            }

        }

    }

}
catch {
    Add-ErrorRecord "Disk Space" $_.Exception.Message
}

# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

$CriticalCount = @(
    $Findings | Where-Object Severity -eq "Critical"
).Count

$HighCount = @(
    $Findings | Where-Object Severity -eq "High"
).Count

$MediumCount = @(
    $Findings | Where-Object Severity -eq "Medium"
).Count

$LowCount = @(
    $Findings | Where-Object Severity -eq "Low"
).Count

$ScanEnd = Get-Date

$Duration = [math]::Round(
    ($ScanEnd - $ScanStart).TotalSeconds,
    2
)

# ------------------------------------------------------------
# DASHBOARD GAUGE CARDS
# ------------------------------------------------------------

$RdpPortCount = @($ListeningPorts | Where-Object { $_.Port -eq 3389 }).Count
$SmbPortCount = @($ListeningPorts | Where-Object { $_.Port -eq 445 }).Count

$DashboardCards = @(
    [PSCustomObject]@{
        Icon     = "&#128737;"
        Title    = "Firewall"
        Subtitle = "Profiles"
        Count    = $Firewall.Count
        Severity = Get-CategorySeverity @("Firewall")
    }
    [PSCustomObject]@{
        Icon     = "&#128272;"
        Title    = "Defender"
        Subtitle = "Products"
        Count    = $Antivirus.Count
        Severity = Get-CategorySeverity @("Antivirus")
    }
    [PSCustomObject]@{
        Icon     = "&#128421;"
        Title    = "RDP"
        Subtitle = "Port 3389"
        Count    = $RdpPortCount
        Severity = Get-CategorySeverity @("Remote Access")
    }
    [PSCustomObject]@{
        Icon     = "&#128194;"
        Title    = "SMB"
        Subtitle = "Port 445"
        Count    = $SmbPortCount
        Severity = Get-CategorySeverity @("SMB", "File Sharing")
    }
    [PSCustomObject]@{
        Icon     = "&#128101;"
        Title    = "Users"
        Subtitle = "Accounts"
        Count    = $Users.Count
        Severity = Get-CategorySeverity @("Account Security", "Password Policy")
    }
    [PSCustomObject]@{
        Icon     = "&#128246;"
        Title    = "Listening Ports"
        Subtitle = "Open Ports"
        Count    = ($ListeningPorts.Count + $UdpPorts.Count)
        Severity = Get-CategorySeverity @("Network Exposure")
    }
    [PSCustomObject]@{
        Icon     = "&#128273;"
        Title    = "BitLocker"
        Subtitle = "Volumes"
        Count    = $BitLocker.Count
        Severity = Get-CategorySeverity @("Disk Encryption")
    }
    [PSCustomObject]@{
        Icon     = "&#128203;"
        Title    = "Security Events"
        Subtitle = "Last 7 Days"
        Count    = $SecurityEvents.Count
        Severity = if ($SecurityEvents.Count -gt 50) { "Medium" }
                   elseif ($SecurityEvents.Count -gt 0) { "Low" }
                   else { "Good" }
    }
)

$DashboardCardsHtml = ""

foreach ($Card in $DashboardCards) {

    $Meta = Get-SeverityMeta $Card.Severity
    $BadgeClass = $Card.Severity.ToLower()

    $DashboardCardsHtml += @"
<div class="dcard">
    <div class="dcard-top">
        <div class="dcard-icon">$($Card.Icon)</div>
        <span class="severity $BadgeClass">$($Meta.Label)</span>
    </div>
    <div class="dcard-title">$(HtmlEncode $Card.Title)</div>
    <div class="dcard-body">
        <div class="dcard-metric">
            <div class="dcard-count">$($Card.Count)</div>
            <div class="dcard-subtitle">$(HtmlEncode $Card.Subtitle)</div>
        </div>
        <div class="gauge" style="--gpct:$($Meta.Pct); --gcolor:$($Meta.Color);">
            <div class="gauge-value">$($Meta.Pct)%</div>
        </div>
    </div>
</div>
"@

}

# ------------------------------------------------------------
# HTML GENERATION - FINDINGS
# ------------------------------------------------------------

$FindingRows = ""

foreach ($Finding in $Findings) {

    $SeverityClass = $Finding.Severity.ToLower()

    $FindingRows += @"
<tr class="finding-row" data-severity="$SeverityClass">
    <td>
        <span class="severity $SeverityClass">
            $(HtmlEncode $Finding.Severity)
        </span>
    </td>
    <td>$(HtmlEncode $Finding.Category)</td>
    <td>
        <strong>$(HtmlEncode $Finding.Title)</strong>
        <div class="description">
            $(HtmlEncode $Finding.Description)
        </div>
    </td>
    <td>$(HtmlEncode $Finding.Recommendation)</td>
</tr>
"@

}

if (!$FindingRows) {

    $FindingRows = @"
<tr>
<td colspan="4" class="empty">
    <div class="success-icon">&#10003;</div>
    <strong>No security findings detected</strong>
    <p>The checks performed by this scanner did not identify any configured findings.</p>
</td>
</tr>
"@

}

# ------------------------------------------------------------
# PORT ROWS
# ------------------------------------------------------------

$PortRows = ""

foreach ($Port in (
    $ListeningPorts + $UdpPorts |
    Sort-Object Protocol, Port
)) {

    $PortRows += @"
<tr>
    <td><span class="protocol">$(HtmlEncode $Port.Protocol)</span></td>
    <td><code>$(HtmlEncode $Port.LocalAddress)</code></td>
    <td><strong>$(HtmlEncode $Port.Port)</strong></td>
    <td>$(HtmlEncode $Port.Process)</td>
    <td>$(HtmlEncode $Port.PID)</td>
    <td>$(HtmlEncode $Port.Binding)</td>
</tr>
"@

}

if (!$PortRows) {

    $PortRows = @"
<tr>
<td colspan="6" class="empty">
    No listening ports were detected or the information was unavailable.
</td>
</tr>
"@

}

# ------------------------------------------------------------
# FIREWALL ROWS
# ------------------------------------------------------------

$FirewallRows = ""

foreach ($FW in $Firewall) {

    $Status = if ($FW.Enabled) {
        '<span class="status-good">&#9679; Enabled</span>'
    } else {
        '<span class="status-bad">&#9679; Disabled</span>'
    }

    $FirewallRows += @"
<tr>
    <td>$(HtmlEncode $FW.Name)</td>
    <td>$Status</td>
    <td>$(HtmlEncode $FW.DefaultInboundAction)</td>
    <td>$(HtmlEncode $FW.DefaultOutboundAction)</td>
</tr>
"@

}

# ------------------------------------------------------------
# ANTIVIRUS ROWS
# ------------------------------------------------------------

$AVRows = ""

foreach ($AV in $Antivirus) {

    $AVRows += @"
<tr>
    <td><strong>$(HtmlEncode $AV.Product)</strong></td>
    <td>$(HtmlEncode $AV.Enabled)</td>
    <td>$(HtmlEncode $AV.RealTimeProtection)</td>
    <td>$(HtmlEncode $AV.SignatureVersion)</td>
    <td>$(HtmlEncode $AV.SignatureAge)</td>
</tr>
"@

}

# ------------------------------------------------------------
# SYSTEM ROWS
# ------------------------------------------------------------

$SystemRows = ""

foreach ($Property in $SystemInfo.PSObject.Properties) {

    $SystemRows += @"
<div class="info-item">
    <span>$(HtmlEncode $Property.Name)</span>
    <strong>$(HtmlEncode $Property.Value)</strong>
</div>
"@

}

# ------------------------------------------------------------
# PLATFORM / CREDENTIAL SECURITY ROWS
# ------------------------------------------------------------

$PlatformRows = @"
<div class="info-item">
    <span>Secure Boot</span>
    <strong>$(HtmlEncode $SecureBootState)</strong>
</div>
<div class="info-item">
    <span>TPM Present</span>
    <strong>$(HtmlEncode ($TpmInfo.TpmPresent))</strong>
</div>
<div class="info-item">
    <span>TPM Ready</span>
    <strong>$(HtmlEncode ($TpmInfo.TpmReady))</strong>
</div>
<div class="info-item">
    <span>Credential Guard Running</span>
    <strong>$(HtmlEncode $CredGuardRunning)</strong>
</div>
<div class="info-item">
    <span>WDigest Plaintext Caching</span>
    <strong>$(HtmlEncode ($WDigest -eq 1))</strong>
</div>
<div class="info-item">
    <span>PowerShell Script Block Logging</span>
    <strong>$(HtmlEncode ($ScriptBlockLogging -eq 1))</strong>
</div>
<div class="info-item">
    <span>LLMNR Disabled</span>
    <strong>$(HtmlEncode ($LLMNR -eq 0))</strong>
</div>
<div class="info-item">
    <span>AutoRun Fully Disabled</span>
    <strong>$(HtmlEncode ($AutoRun -eq 255))</strong>
</div>
"@

# ------------------------------------------------------------
# PASSWORD POLICY ROWS
# ------------------------------------------------------------

$PasswordPolicyRows = ""

foreach ($Key in $PasswordPolicy.Keys) {

    $PasswordPolicyRows += @"
<div class="info-item">
    <span>$(HtmlEncode $Key)</span>
    <strong>$(HtmlEncode $PasswordPolicy[$Key])</strong>
</div>
"@

}

if (!$PasswordPolicyRows) {

    $PasswordPolicyRows = '<div class="info-item"><span>Status</span><strong>Unavailable</strong></div>'

}

# ------------------------------------------------------------
# NETWORK SHARE ROWS
# ------------------------------------------------------------

$ShareRows = ""

foreach ($Share in $Shares) {

    $ShareRows += @"
<tr>
    <td><strong>$(HtmlEncode $Share.Name)</strong></td>
    <td><code>$(HtmlEncode $Share.Path)</code></td>
    <td>$(HtmlEncode $Share.Description)</td>
    <td>$(HtmlEncode $Share.EveryoneAccess)</td>
</tr>
"@

}

if (!$ShareRows) {

    $ShareRows = '<tr><td colspan="4" class="empty">No SMB shares were detected.</td></tr>'

}

# ------------------------------------------------------------
# USERS
# ------------------------------------------------------------

$UserRows = ""

foreach ($User in $Users) {

    $UserStatus = if ($User.Enabled) {
        '<span class="status-good">Enabled</span>'
    } else {
        '<span class="muted">Disabled</span>'
    }

    $UserRows += @"
<tr>
    <td><strong>$(HtmlEncode $User.Name)</strong></td>
    <td>$UserStatus</td>
    <td>$(HtmlEncode $User.PasswordRequired)</td>
    <td>$(HtmlEncode $User.LastLogon)</td>
</tr>
"@

}

# ------------------------------------------------------------
# ADMINISTRATORS
# ------------------------------------------------------------

$AdminRows = ""

foreach ($Admin in $Administrators) {

    $AdminRows += @"
<tr>
    <td><strong>$(HtmlEncode $Admin.Name)</strong></td>
    <td>$(HtmlEncode $Admin.ObjectClass)</td>
    <td>$(HtmlEncode $Admin.PrincipalSource)</td>
</tr>
"@

}

# ------------------------------------------------------------
# SOFTWARE
# ------------------------------------------------------------

$SoftwareRows = ""

foreach ($App in $Software) {

    $SoftwareRows += @"
<tr>
    <td><strong>$(HtmlEncode $App.Name)</strong></td>
    <td>$(HtmlEncode $App.Version)</td>
    <td>$(HtmlEncode $App.Publisher)</td>
</tr>
"@

}

# ------------------------------------------------------------
# SERVICES
# ------------------------------------------------------------

$ServiceRows = ""

foreach ($Service in (
    $Services |
    Where-Object StartMode -eq "Auto" |
    Select-Object -First 300
)) {

    $ServiceRows += @"
<tr>
    <td><strong>$(HtmlEncode $Service.DisplayName)</strong></td>
    <td>$(HtmlEncode $Service.Name)</td>
    <td>$(HtmlEncode $Service.State)</td>
    <td>$(HtmlEncode $Service.StartMode)</td>
</tr>
"@

}

# ------------------------------------------------------------
# SECURITY EVENTS
# ------------------------------------------------------------

$EventRows = ""

foreach ($Event in (
    $SecurityEvents |
    Select-Object -First 100
)) {

    $EventRows += @"
<tr>
    <td>$(HtmlEncode $Event.TimeCreated)</td>
    <td><strong>$(HtmlEncode $Event.Id)</strong></td>
    <td>$(HtmlEncode $Event.ProviderName)</td>
    <td>$(HtmlEncode $Event.LevelDisplayName)</td>
</tr>
"@

}

# ------------------------------------------------------------
# HTML
# ------------------------------------------------------------

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Windows Security Report</title>
<style>

:root {
    --bg: #0b1020;
    --panel: #11182b;
    --panel2: #151e34;
    --border: rgba(255,255,255,.08);
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #6366f1;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
    --good: #22c55e;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: radial-gradient(circle at top right, rgba(99,102,241,.15), transparent 35%), var(--bg);
    color: var(--text);
    line-height: 1.6;
}

.container { max-width: 1500px; margin: auto; padding: 30px; }

.header {
    background: linear-gradient(135deg, rgba(99,102,241,.18), rgba(17,24,39,.9));
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 35px;
    margin-bottom: 25px;
    box-shadow: 0 20px 60px rgba(0,0,0,.25);
}

.logo { display: flex; align-items: center; gap: 15px; }

.logo-icon {
    width: 55px; height: 55px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 16px;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    font-size: 28px;
}

.header h1 { margin: 0; font-size: clamp(25px, 4vw, 38px); }
.header p { margin: 8px 0 0; color: var(--muted); }

.readonly {
    display: inline-flex; align-items: center; gap: 7px;
    margin-top: 20px; padding: 7px 13px;
    border-radius: 999px;
    background: rgba(34,197,94,.1);
    border: 1px solid rgba(34,197,94,.25);
    color: #86efac; font-size: 13px; font-weight: 700;
}

.totals-strip {
    display: flex; flex-wrap: wrap; gap: 10px;
    margin-bottom: 20px;
}

.pill {
    padding: 9px 16px; border-radius: 12px;
    background: var(--panel); border: 1px solid var(--border);
    font-size: 13px; font-weight: 700;
    display: flex; align-items: center; gap: 8px;
}

.pill .dot { width: 8px; height: 8px; border-radius: 50%; }
.pill.pcritical .dot { background: var(--critical); }
.pill.phigh .dot { background: var(--high); }
.pill.pmedium .dot { background: var(--medium); }
.pill.plow .dot { background: var(--low); }

.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0,1fr));
    gap: 16px;
    margin-bottom: 25px;
}

.dcard {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 18px;
}

.dcard-top { display: flex; align-items: center; justify-content: space-between; }

.dcard-icon {
    width: 38px; height: 38px;
    border-radius: 12px;
    background: var(--panel2);
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
}

.dcard-title { margin-top: 14px; font-weight: 700; font-size: 15px; }

.dcard-body {
    margin-top: 14px;
    display: flex; align-items: center; justify-content: space-between;
}

.dcard-count { font-size: 26px; font-weight: 800; }
.dcard-subtitle { color: var(--muted); font-size: 12px; margin-top: 2px; }

.gauge {
    width: 56px; height: 56px; border-radius: 50%;
    background: conic-gradient(var(--gcolor) calc(var(--gpct) * 1%), rgba(255,255,255,.08) 0);
    position: relative;
}

.gauge::after {
    content: '';
    position: absolute; inset: 7px;
    background: var(--panel);
    border-radius: 50%;
}

.gauge-value {
    position: absolute; inset: 0;
    display: flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 700; z-index: 1;
}

.section {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 20px;
    margin-bottom: 22px;
    overflow: hidden;
}

.section-header {
    padding: 20px 22px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    gap: 15px;
}

.section-header h2 { margin: 0; font-size: 19px; }
.section-body { padding: 22px; }

.info-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
}

.info-item {
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px;
}

.info-item span { display: block; color: var(--muted); font-size: 12px; }
.info-item strong { display: block; margin-top: 4px; word-break: break-word; }

.table-wrapper { overflow-x: auto; }

table { width: 100%; border-collapse: collapse; min-width: 700px; }

th {
    text-align: left; color: var(--muted); font-size: 12px;
    text-transform: uppercase; letter-spacing: .06em;
    background: var(--panel2); padding: 13px;
}

td { padding: 14px 13px; border-top: 1px solid var(--border); font-size: 14px; }
tr:hover td { background: rgba(255,255,255,.025); }
.description { color: var(--muted); font-size: 13px; margin-top: 4px; }

.severity {
    display: inline-flex; padding: 5px 10px; border-radius: 999px;
    font-size: 11px; font-weight: 800; text-transform: uppercase;
}

.severity.critical { color: #fecaca; background: rgba(239,68,68,.14); }
.severity.high { color: #fed7aa; background: rgba(249,115,22,.14); }
.severity.medium { color: #fef08a; background: rgba(234,179,8,.14); }
.severity.low { color: #bfdbfe; background: rgba(59,130,246,.14); }
.severity.good { color: #86efac; background: rgba(34,197,94,.14); }

.status-good { color: #86efac; font-weight: 700; }
.status-bad { color: #fca5a5; font-weight: 700; }
.muted { color: var(--muted); }
.protocol { font-weight: 700; }

.search {
    width: 100%; max-width: 350px;
    background: var(--panel2); color: var(--text);
    border: 1px solid var(--border); border-radius: 10px;
    padding: 10px 13px; outline: none;
}

.search:focus { border-color: var(--accent); }

.filters { display: flex; flex-wrap: wrap; gap: 8px; }

.filter {
    border: 1px solid var(--border); background: var(--panel2);
    color: var(--muted); border-radius: 999px; padding: 7px 12px;
    cursor: pointer; font-size: 12px;
}

.filter.active {
    background: rgba(99,102,241,.18);
    border-color: rgba(99,102,241,.4);
    color: white;
}

.empty { text-align: center; padding: 45px !important; color: var(--muted); }

.success-icon {
    width: 55px; height: 55px; margin: auto auto 12px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 50%; background: rgba(34,197,94,.12);
    color: #86efac; font-size: 27px;
}

.footer { text-align: center; color: var(--muted); font-size: 12px; padding: 20px; }

@media(max-width: 1100px) {
    .dashboard-grid { grid-template-columns: repeat(2, 1fr); }
    .info-grid { grid-template-columns: repeat(2, 1fr); }
}

@media(max-width: 700px) {
    .container { padding: 15px; }
    .header { padding: 25px; border-radius: 18px; }
    .dashboard-grid { grid-template-columns: repeat(2, 1fr); }
    .info-grid { grid-template-columns: 1fr; }
    .section-header { align-items: flex-start; flex-direction: column; }
    .search { max-width: 100%; }
}

@media(max-width: 450px) { .dashboard-grid { grid-template-columns: 1fr; } }

@media print {
    body { background: white; color: black; }
    .header, .section, .dcard { box-shadow: none; background: white; color: black; }
    .filters, .search { display: none; }
}

</style>
</head>
<body>
<div class="container">

<header class="header">
    <div class="logo">
        <div class="logo-icon">&#128737;</div>
        <div>
            <h1>Windows and Security Dashboard</h1>
            <p>Read-only security configuration assessment</p>
        </div>
    </div>
    <div class="readonly">&#9679; STRICTLY READ-ONLY</div>
</header>

<div class="totals-strip">
    <div class="pill pcritical"><span class="dot"></span>Critical: $CriticalCount</div>
    <div class="pill phigh"><span class="dot"></span>High: $HighCount</div>
    <div class="pill pmedium"><span class="dot"></span>Medium: $MediumCount</div>
    <div class="pill plow"><span class="dot"></span>Low: $LowCount</div>
</div>

<section class="dashboard-grid">
    $DashboardCardsHtml
</section>

<section class="section">
    <div class="section-header">
        <h2>System Information</h2>
        <span class="muted">Scan: $(HtmlEncode $ScanStart)</span>
    </div>
    <div class="section-body">
        <div class="info-grid">
            $SystemRows
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header">
        <h2>Platform &amp; Credential Security</h2>
    </div>
    <div class="section-body">
        <div class="info-grid">
            $PlatformRows
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header">
        <h2>Password &amp; Lockout Policy</h2>
    </div>
    <div class="section-body">
        <div class="info-grid">
            $PasswordPolicyRows
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header">
        <h2>&#128272; Security Findings</h2>
        <input id="findingSearch" class="search" type="search" placeholder="Search findings...">
    </div>
    <div class="section-body">
        <div class="filters">
            <button class="filter active" onclick="filterFindings('all',this)">All</button>
            <button class="filter" onclick="filterFindings('critical',this)">Critical</button>
            <button class="filter" onclick="filterFindings('high',this)">High</button>
            <button class="filter" onclick="filterFindings('medium',this)">Medium</button>
            <button class="filter" onclick="filterFindings('low',this)">Low</button>
        </div>
        <br>
        <div class="table-wrapper">
            <table id="findingsTable">
                <thead>
                    <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Recommendation</th></tr>
                </thead>
                <tbody>
                    $FindingRows
                </tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header">
        <h2>Listening Ports</h2>
        <span class="muted">Local enumeration only</span>
    </div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr><th>Protocol</th><th>Address</th><th>Port</th><th>Process</th><th>PID</th><th>Binding</th></tr>
                </thead>
                <tbody>
                    $PortRows
                </tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header"><h2>Windows Firewall</h2></div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>Profile</th><th>Status</th><th>Inbound</th><th>Outbound</th></tr></thead>
                <tbody>$FirewallRows</tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header"><h2>Antivirus</h2></div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>Product</th><th>Status</th><th>Real-Time</th><th>Signature</th><th>Age</th></tr></thead>
                <tbody>$AVRows</tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header"><h2>Network Shares (SMB)</h2></div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>Share</th><th>Path</th><th>Description</th><th>Everyone Access</th></tr></thead>
                <tbody>$ShareRows</tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header"><h2>Local Users</h2></div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>User</th><th>Status</th><th>Password Required</th><th>Last Logon</th></tr></thead>
                <tbody>$UserRows</tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header"><h2>Local Administrators</h2></div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>Name</th><th>Type</th><th>Source</th></tr></thead>
                <tbody>$AdminRows</tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header"><h2>Automatic Services</h2></div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>Service</th><th>Name</th><th>State</th><th>Start Mode</th></tr></thead>
                <tbody>$ServiceRows</tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header">
        <h2>Installed Software</h2>
        <span class="muted">$($Software.Count) applications</span>
    </div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>Name</th><th>Version</th><th>Publisher</th></tr></thead>
                <tbody>$SoftwareRows</tbody>
            </table>
        </div>
    </div>
</section>

<section class="section">
    <div class="section-header">
        <h2>Security Events</h2>
        <span class="muted">Last 7 days</span>
    </div>
    <div class="section-body">
        <div class="table-wrapper">
            <table>
                <thead><tr><th>Time</th><th>Event ID</th><th>Provider</th><th>Level</th></tr></thead>
                <tbody>$EventRows</tbody>
            </table>
        </div>
    </div>
</section>

<footer class="footer">
    <p>Windows Security Read-Only Assessment</p>
    <p>Completed in $Duration seconds &middot; No system configuration was modified</p>
</footer>

</div>

<script>
let currentFilter = "all";

function filterFindings(filter, button) {
    currentFilter = filter;
    document.querySelectorAll(".filter").forEach(function(btn) { btn.classList.remove("active"); });
    button.classList.add("active");
    applyFilters();
}

document.getElementById("findingSearch").addEventListener("input", function() { applyFilters(); });

function applyFilters() {
    const search = document.getElementById("findingSearch").value.toLowerCase();
    document.querySelectorAll(".finding-row").forEach(function(row) {
        const severity = row.dataset.severity;
        const text = row.innerText.toLowerCase();
        const severityMatch = currentFilter === "all" || severity === currentFilter;
        const searchMatch = text.includes(search);
        row.style.display = severityMatch && searchMatch ? "" : "none";
    });
}
</script>

</body>
</html>
"@

# ------------------------------------------------------------
# WRITE ONLY THE HTML REPORT
# ------------------------------------------------------------

try {

    $HTML | Out-File -FilePath $ReportFile -Encoding UTF8

}
catch {

    Write-Host "ERROR: Could not generate report."
    Write-Host $_.Exception.Message

    exit 1
}

# ------------------------------------------------------------
# FINAL OUTPUT
# ------------------------------------------------------------

Write-Host ""
Write-Host "=============================================="
Write-Host " WINDOWS SECURITY SCAN COMPLETED"
Write-Host "=============================================="
Write-Host ""

Write-Host "Mode              : STRICT READ-ONLY"
Write-Host "System Modified   : NO"
Write-Host "Network Probing   : NO"
Write-Host "Defender Scan     : NO"
Write-Host "Configuration     : NO CHANGES"
Write-Host ""

Write-Host "Critical Findings : $CriticalCount"
Write-Host "High Findings     : $HighCount"
Write-Host "Medium Findings   : $MediumCount"
Write-Host "Low Findings      : $LowCount"
Write-Host ""

Write-Host "HTML Report:"
Write-Host $ReportFile
Write-Host ""

Write-Host "Only one file was generated."
Write-Host ""
