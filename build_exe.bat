@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m pip install --upgrade pyinstaller
    py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name "BSOD-Investigator" bsod_investigator.py
) else (
    python -m pip install --upgrade pyinstaller
    python -m PyInstaller --noconfirm --clean --onefile --windowed --name "BSOD-Investigator" bsod_investigator.py
)
echo.
echo EXE: dist\BSOD-Investigator.exe
pause
