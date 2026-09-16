@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"

rem ============================================================================
rem BSOD Investigator - reproducible Windows EXE builder
rem What it does:
rem   1. Finds Python 3, or installs Python 3.13 for the current user via winget.
rem   2. Creates an isolated .build-venv (does not pollute your normal Python).
rem   3. Installs the pinned PyInstaller toolchain into that environment.
rem   4. Cleans stale build/dist output.
rem   5. Builds dist\BSOD-Investigator.exe.
rem   6. Runs the SAFE self-test on the packaged EXE and fails if it is broken.
rem
rem Double-click this file for a normal build.
rem CI/automation may call: build_exe.bat --ci
rem ============================================================================

set "NO_PAUSE="
if /i "%~1"=="--ci" set "NO_PAUSE=1"
if /i "%~1"=="--no-pause" set "NO_PAUSE=1"

call :find_python
if not defined BASE_PY call :install_python
if not defined BASE_PY goto :fail

set "BUILD_VENV=%CD%\.build-venv"
set "BUILD_PY=%BUILD_VENV%\Scripts\python.exe"

if not exist "%BUILD_PY%" (
    echo [1/6] Creating isolated build environment...
    "%BASE_PY%" -m venv "%BUILD_VENV%" || goto :fail
) else (
    echo [1/6] Reusing isolated build environment...
)

echo [2/6] Installing packaging toolchain...
"%BUILD_PY%" -m pip install --disable-pip-version-check --no-input --timeout 60 --retries 2 "pyinstaller==6.22.3" "pyinstaller-hooks-contrib>=2026.6" || goto :fail

echo [3/6] Compiling source before packaging...
"%BUILD_PY%" -m py_compile bsod_investigator.py || goto :fail
"%BUILD_PY%" bsod_investigator.py --self-test || goto :fail

echo [4/6] Cleaning previous build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "BSOD-Investigator.spec" del /q "BSOD-Investigator.spec"

echo [5/6] Building BSOD-Investigator.exe...
"%BUILD_PY%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --windowed ^
  --name "BSOD-Investigator" ^
  bsod_investigator.py || goto :fail

if not exist "dist\BSOD-Investigator.exe" (
    echo [ERROR] PyInstaller finished without the expected EXE.
    goto :fail
)

echo [6/6] Running packaged safe self-test...
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$p=Start-Process -FilePath '.\dist\BSOD-Investigator.exe' -ArgumentList '--self-test' -PassThru -Wait; exit $p.ExitCode" || goto :fail

echo.
echo [OK] Ready-to-run EXE created and self-tested.
echo EXE: %CD%\dist\BSOD-Investigator.exe
echo.
echo NOTE: real dump analysis uses Microsoft's Debugging Tools for Windows/CDB.
echo The EXE itself is packaged; see BUILD_EXE.md for the debugger runtime note.
goto :success

:find_python
set "BASE_PY="
for %%P in ("%LOCALAPPDATA%\Programs\Python\Python313\python.exe" "%ProgramFiles%\Python313\python.exe") do (
    if exist "%%~P" set "BASE_PY=%%~P"
)
if defined BASE_PY exit /b 0
where py >nul 2>nul && for /f "delims=" %%P in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "BASE_PY=%%P"
if defined BASE_PY exit /b 0
where python >nul 2>nul && for /f "delims=" %%P in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "BASE_PY=%%P"
exit /b 0

:install_python
echo [SETUP] Python 3 was not found. Trying automatic per-user installation...
where winget >nul 2>nul || (
    echo [ERROR] Python is missing and Windows Package Manager ^(winget^) is unavailable.
    echo Install Python 3.13 from python.org, then run this file again.
    exit /b 1
)
winget install --id Python.Python.3.13 -e --scope user --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 (
    echo [ERROR] Automatic Python installation failed.
    exit /b 1
)
call :find_python
exit /b 0

:fail
echo.
echo [ERROR] EXE build failed. Read the first error above; no broken build is reported as ready.
if not defined NO_PAUSE pause
exit /b 1

:success
if not defined NO_PAUSE pause
exit /b 0
