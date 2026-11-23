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
$virtio = Join-Path $PSScriptRoot 'tools\virtio'
if (Test-Path $virtio) {
    Get-ChildItem $virtio -Recurse -Filter *.inf | ForEach-Object {
        $r = & pnputil.exe /add-driver $_.FullName /install 2>&1
        Log "pnputil $($_.Name): $($r[-1])"
    }
} else {
    Log "no bundled virtio driver tree"
}

# Fallback: qemu-guest-agent MSI, required for the CI deploy channel.
$ga = Join-Path $virtio 'qemu-ga-x86_64.msi'
$svc = Get-Service QEMU-GA -ErrorAction SilentlyContinue
if (-not $svc -and (Test-Path $ga)) {
    Log 'installing qemu-guest-agent msi'
    $pr = Start-Process msiexec.exe -ArgumentList '/i', "`"$ga`"", '/qn', '/norestart' -Wait -PassThru
    Log "qemu-ga msi exit=$($pr.ExitCode)"
    $svc = Get-Service QEMU-GA -ErrorAction SilentlyContinue
}
if ($svc) {
    if ($svc.Status -ne 'Running') { Start-Service QEMU-GA -ErrorAction SilentlyContinue }
    Log "qemu-ga status: $((Get-Service QEMU-GA).Status)"
} else {
    Log 'ERROR qemu-ga service missing'
}

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
powercfg /setactive SCHEME_MIN
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /change monitor-timeout-ac 10

Log 'done'
