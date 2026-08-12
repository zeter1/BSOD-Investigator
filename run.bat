@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 bsod_investigator.py
) else (
    python bsod_investigator.py
)
if errorlevel 1 pause
