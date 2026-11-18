@echo off
setlocal
set "ROOT=%~dp0.."
set "PYTHONPATH=%ROOT%;%PYTHONPATH%"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 -m sentinels.cli %*
) else (
    python -m sentinels.cli %*
)
