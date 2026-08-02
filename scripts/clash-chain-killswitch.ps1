[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("Enable", "Disable", "Status")]
    [string]$Action,

    [string]$MihomoPath,

    [string]$StateDir = "$env:ProgramData\ClashChainKillSwitch"
)

$ErrorActionPreference = "Stop"
$RuleGroup = "Clash Chain Kill Switch"
$BackupPath = Join-Path $StateDir "firewall-before-killswitch.wfw"
$StatePath = Join-Path $StateDir "state.json"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Invoke-Netsh {
    param([string[]]$Arguments)
    & netsh.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "netsh failed: $($Arguments -join ' ')"
    }
}

function Show-Status {
    $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultOutboundAction
    $rules = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled, Action
    $profiles | Format-Table -AutoSize
    if ($rules) {
        $rules | Format-Table -AutoSize
        "Kill switch: enabled"
    } else {
        "Kill switch: disabled"
    }
}

if ($Action -eq "Status") {
    Show-Status
    return
}

Assert-Administrator

if ($Action -eq "Enable") {
    if (-not $MihomoPath) {
        throw "Enable requires -MihomoPath pointing to the mihomo executable used by Clash Verge."
    }
    $MihomoPath = (Resolve-Path -LiteralPath $MihomoPath).Path
    if (Test-Path -LiteralPath $StatePath) {
        throw "The kill switch is already enabled. Run Disable first."
    }

    if ($PSCmdlet.ShouldProcess("Windows Firewall", "Allow only mihomo, loopback, DHCP, and DNS outbound")) {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
        Invoke-Netsh @("advfirewall", "export", $BackupPath)
        try {
            Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow |
                Disable-NetFirewallRule | Out-Null
            Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block

            New-NetFirewallRule -DisplayName "Allow mihomo outbound" -Group $RuleGroup `
                -Direction Outbound -Action Allow -Program $MihomoPath -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "Allow local proxy loopback" -Group $RuleGroup `
                -Direction Outbound -Action Allow -RemoteAddress 127.0.0.0/8, ::1 -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "Allow DHCPv4" -Group $RuleGroup `
                -Direction Outbound -Action Allow -Program "$env:SystemRoot\System32\svchost.exe" `
                -Service Dhcp -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "Allow DHCPv6" -Group $RuleGroup `
                -Direction Outbound -Action Allow -Program "$env:SystemRoot\System32\svchost.exe" `
                -Service Dhcp -Protocol UDP -LocalPort 546 -RemotePort 547 -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "Allow Windows DNS client" -Group $RuleGroup `
                -Direction Outbound -Action Allow -Program "$env:SystemRoot\System32\svchost.exe" `
                -Service Dnscache -Protocol UDP -RemotePort 53 -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "Allow Windows DNS client TCP" -Group $RuleGroup `
                -Direction Outbound -Action Allow -Program "$env:SystemRoot\System32\svchost.exe" `
                -Service Dnscache -Protocol TCP -RemotePort 53 -Profile Any | Out-Null

            @{
                enabledAt = (Get-Date).ToString("o")
                mihomoPath = $MihomoPath
                backupPath = $BackupPath
            } | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding UTF8
            "Kill switch enabled. Regular applications cannot restore direct Internet access if mihomo stops."
        } catch {
            if (Test-Path -LiteralPath $BackupPath) {
                Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
                    Remove-NetFirewallRule | Out-Null
                Invoke-Netsh @("advfirewall", "import", $BackupPath)
            }
            throw
        }
    }
    return
}

if (-not (Test-Path -LiteralPath $BackupPath)) {
    throw "Firewall backup not found: $BackupPath"
}
if ($PSCmdlet.ShouldProcess("Windows Firewall", "Restore the complete pre-kill-switch policy")) {
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule | Out-Null
    Invoke-Netsh @("advfirewall", "import", $BackupPath)
    Remove-Item -LiteralPath $StateDir -Recurse -Force
    "Kill switch disabled. The original firewall policy was restored."
}
