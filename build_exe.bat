@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
cd /d "%~dp0"

rem ============================================================================
rem BSOD Investigator - reproducible Windows EXE builder
rem What it does:
rem   1. Finds tested Python 3.13, or installs it for the current user via winget.
rem   2. Creates isolated .build-venv (your normal Python stays untouched).
rem   3. Installs pinned PyInstaller packaging tools.
rem   4. Compiles the source and runs the safe Windows self-test.
rem   5. Cleans stale output and builds dist\BSOD-Investigator.exe.
rem   6. Runs the same safe self-test on the packaged EXE.
rem
rem Windows note: build_support\sqlite_context_close.py is intentionally loaded
rem during Windows tests and as a PyInstaller runtime hook. sqlite3's native
rem context manager commits/rolls back but does not close the connection; the
rem project scopes its DB connections with "with", so explicit close prevents
rem lingering history.sqlite3 handles and makes packaged cleanup deterministic.
rem
rem Double-click this file for a normal build.
rem CI/automation may call: build_exe.bat --ci
rem Full instructions: BUILD_EXE.md
rem ============================================================================

set "NO_PAUSE="
if /i "%~1"=="--ci" set "NO_PAUSE=1"
if /i "%~1"=="--no-pause" set "NO_PAUSE=1"

call :find_python313
if not defined BASE_PY call :install_python
if not defined BASE_PY goto :fail

set "BUILD_VENV=%CD%\.build-venv"
set "BUILD_PY=%BUILD_VENV%\Scripts\python.exe"

if exist "%BUILD_PY%" (
    "%BUILD_PY%" -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 13) else 1)" >nul 2>nul
    if errorlevel 1 (
        echo [SETUP] Existing build environment uses another Python version. Recreating it...
        rmdir /s /q "%BUILD_VENV%" || goto :fail
    )
)

if not exist "%BUILD_PY%" (
    echo [1/6] Creating isolated Python 3.13 build environment...
    "%BASE_PY%" -m venv "%BUILD_VENV%" || goto :fail
) else (
    echo [1/6] Reusing isolated Python 3.13 build environment...
)

echo [2/6] Installing packaging toolchain...
"%BUILD_PY%" -m pip install --disable-pip-version-check --no-input --timeout 60 --retries 2 "pyinstaller==6.22.3" "pyinstaller-hooks-contrib>=2026.6" || goto :fail

echo [3/6] Compiling source and running safe Windows self-test...
"%BUILD_PY%" -m py_compile bsod_investigator.py build_support\sqlite_context_close.py || goto :fail
"%BUILD_PY%" -c "import runpy,sys; import build_support.sqlite_context_close; sys.argv=['bsod_investigator.py','--self-test']; runpy.run_path('bsod_investigator.py', run_name='__main__')" || goto :fail

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
  --runtime-hook "build_support\sqlite_context_close.py" ^
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

:find_python313
set "BASE_PY="
if defined pythonLocation if exist "%pythonLocation%\python.exe" (
    "%pythonLocation%\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 13) else 1)" >nul 2>nul
    if not errorlevel 1 set "BASE_PY=%pythonLocation%\python.exe"
)
if defined BASE_PY exit /b 0
where py >nul 2>nul && for /f "delims=" %%P in ('py -3.13 -c "import sys; print(sys.executable)" 2^>nul') do set "BASE_PY=%%P"
if defined BASE_PY exit /b 0
for %%P in ("%LOCALAPPDATA%\Programs\Python\Python313\python.exe" "%ProgramFiles%\Python313\python.exe") do (
    if exist "%%~P" set "BASE_PY=%%~P"
)
if defined BASE_PY exit /b 0
where python >nul 2>nul && python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 13) else 1)" >nul 2>nul && for /f "delims=" %%P in ('python -c "import sys; print(sys.executable)"') do set "BASE_PY=%%P"
exit /b 0

:install_python
echo [SETUP] Tested Python 3.13 was not found. Trying automatic per-user installation...
where winget >nul 2>nul || (
    echo [ERROR] Python 3.13 is missing and Windows Package Manager ^(winget^) is unavailable.
    echo Install Python 3.13 from python.org, then run this file again.
    exit /b 1
)
winget install --id Python.Python.3.13 -e --scope user --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 (
    echo [ERROR] Automatic Python 3.13 installation failed.
    exit /b 1
)
call :find_python313
exit /b 0

:fail
echo.
echo [ERROR] EXE build failed. Read the first error above; no broken build is reported as ready.
if not defined NO_PAUSE pause
exit /b 1

:success
if not defined NO_PAUSE pause
exit /b 0
