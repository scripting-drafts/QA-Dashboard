# QA Sentinels launcher for Windows PowerShell.
$Root = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = "$Root;$env:PYTHONPATH"
& py -3 -m sentinels.cli @args
exit $LASTEXITCODE
