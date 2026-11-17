# First-logon entry point. Relaunches itself as SYSTEM because driver-trust
# prompts ("Would you like to install this device software?") only appear in
# interactive sessions and would block an unattended build.
$ErrorActionPreference = 'Continue'
$log = 'C:\qa\install-tools.log'
New-Item -ItemType Directory -Force -Path C:\qa | Out-Null
function Log($m) { "$(Get-Date -Format o) $m" | Out-File -FilePath $log -Append -Encoding utf8 }

if ($env:USERNAME -ne 'SYSTEM') {
    Log "relaunching as SYSTEM"
    $self = $MyInvocation.MyCommand.Path
    schtasks /create /tn QATools /tr "powershell -NoProfile -ExecutionPolicy Bypass -File `"$self`"" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f | Out-Null
    schtasks /run /tn QATools | Out-Null
    exit 0
}

Log "running as SYSTEM from $PSScriptRoot"

foreach ($n in @('spice-guest-tools.exe', 'virtio-win-guest-tools.exe')) {
    $p = Join-Path $PSScriptRoot "tools\$n"
    if (Test-Path $p) {
        Log "installing $n"
        $pr = Start-Process $p -ArgumentList '/S' -Wait -PassThru
        Log "$n exit=$($pr.ExitCode)"
    } else {
        Log "missing $p"
    }
}

# Fallback: install every bundled virtio driver explicitly (idempotent, silent).
$inf = Join-Path $PSScriptRoot 'tools\virtio'
if (Test-Path $inf) {
    Get-ChildItem $inf -Recurse -Filter *.inf | ForEach-Object {
        $r = & pnputil.exe /add-driver $_.FullName /install 2>&1
        Log "pnputil $($_.Name): $($r[-1])"
    }
}

Get-Service QEMU-GA -ErrorAction SilentlyContinue | ForEach-Object { Log "qemu-ga status: $($_.Status)" }

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
powercfg /setactive SCHEME_MIN
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /change monitor-timeout-ac 10

Log 'done'
