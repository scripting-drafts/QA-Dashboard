# Runs inside the guest via qemu-guest-agent (SYSTEM context).
# Installs the per-machine MSI silently and drops a machine-readable result
# at C:\qa\deploy.json for the host to collect.
$ErrorActionPreference = 'Stop'
$log = 'C:\qa\deploy.log'
New-Item -ItemType Directory -Force -Path C:\qa | Out-Null

function Log($m) {
    $line = "$(Get-Date -Format o) $m"
    $line | Out-File -FilePath $log -Append -Encoding utf8
    Write-Output $line
}

$msi = Join-Path $PSScriptRoot 'app.msi'
if (-not (Test-Path $msi)) { Log "missing $msi"; exit 10 }

Log "installing $msi"
$args = @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', 'C:\qa\msi.log')
$proc = Start-Process -FilePath msiexec.exe -ArgumentList $args -Wait -PassThru
$code = $proc.ExitCode
Log "msiexec exit=$code"

$entry = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName -like 'QA Dashboard*' } |
    Select-Object -First 1

$result = [ordered]@{
    exit        = $code
    version     = $entry.DisplayVersion
    productcode = $entry.PSChildName
    file        = (Split-Path $msi -Leaf)
    timestamp   = (Get-Date).ToString('o')
}
$result | ConvertTo-Json | Out-File -FilePath 'C:\qa\deploy.json' -Encoding utf8
Log "version=$($entry.DisplayVersion) productcode=$($entry.PSChildName)"

# 3010 = success, reboot required
if ($code -eq 0 -or $code -eq 3010) { exit 0 } else { exit $code }
