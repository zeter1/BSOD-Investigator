@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
cd /d "%~dp0"

rem ============================================================================
rem BSOD Investigator - ready-to-run Windows EXE builder
rem
rem Normal double-click build:
rem   * finds/installs tested Python 3.13;
rem   * creates isolated .build-venv;
rem   * installs pinned PyInstaller tooling;
rem   * ensures Microsoft's CDB/Debugging Tools are installed (UAC may appear);
rem   * runs source self-test with deterministic SQLite close semantics;
rem   * creates dist\BSOD-Investigator.exe;
rem   * runs packaged EXE self-test before reporting success.
rem
rem CI: build_exe.bat --ci
rem   The CI mode skips machine-wide Microsoft Debugging Tools installation but still
rem   builds and smoke-tests the packaged EXE. Normal user builds install CDB when it
rem   is missing so real crash-dump analysis is usable without a separate setup guide.
rem
rem Full instructions and troubleshooting: BUILD_EXE.md
rem ============================================================================

set "NO_PAUSE="
set "CI_MODE="
if /i "%~1"=="--ci" (
    set "NO_PAUSE=1"
    set "CI_MODE=1"
)
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
    echo [1/7] Creating isolated Python 3.13 build environment...
    "%BASE_PY%" -m venv "%BUILD_VENV%" || goto :fail
) else (
    echo [1/7] Reusing isolated Python 3.13 build environment...
)

echo [2/7] Installing packaging toolchain...
"%BUILD_PY%" -m pip install --disable-pip-version-check --no-input --timeout 60 --retries 2 "pyinstaller==6.22.3" "pyinstaller-hooks-contrib>=2026.6" || goto :fail

echo [3/7] Checking Microsoft Debugging Tools for Windows...
call :find_cdb
if defined CDB_EXE (
    echo [OK] CDB found: !CDB_EXE!
) else if defined CI_MODE (
    echo [CI] CDB is not required for packaging smoke-test; machine-wide SDK install is skipped.
) else (
    call :install_debugging_tools
    if errorlevel 1 goto :fail
    call :find_cdb
    if not defined CDB_EXE (
        echo [ERROR] Microsoft Debugging Tools installer finished but cdb.exe was not found.
        goto :fail
    )
    echo [OK] CDB installed: !CDB_EXE!
)

echo [4/7] Compiling source and running safe Windows self-test...
"%BUILD_PY%" -m py_compile bsod_investigator.py build_support\sqlite_context_close.py || goto :fail
"%BUILD_PY%" -c "import runpy,sys; import build_support.sqlite_context_close; sys.argv=['bsod_investigator.py','--self-test']; runpy.run_path('bsod_investigator.py', run_name='__main__')" || goto :fail

echo [5/7] Cleaning previous build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "BSOD-Investigator.spec" del /q "BSOD-Investigator.spec"

echo [6/7] Building BSOD-Investigator.exe...
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

echo [7/7] Running packaged safe self-test...
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$p=Start-Process -FilePath '.\dist\BSOD-Investigator.exe' -ArgumentList '--self-test' -PassThru -Wait; exit $p.ExitCode" || goto :fail

echo.
echo [OK] READY BUILD CREATED AND VERIFIED.
echo EXE: %CD%\dist\BSOD-Investigator.exe
if defined CDB_EXE echo CDB: !CDB_EXE!
echo.
echo You can run the EXE from dist. Normal builds also ensure CDB is installed.
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

:find_cdb
set "CDB_EXE="
for %%D in (
    "%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64\cdb.exe"
    "%ProgramFiles%\Windows Kits\10\Debuggers\x64\cdb.exe"
    "%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64\cdbX64.exe"
    "%ProgramFiles%\Windows Kits\10\Debuggers\x64\cdbX64.exe"
) do (
    if exist "%%~D" if not defined CDB_EXE set "CDB_EXE=%%~D"
)
if not defined CDB_EXE (
    where cdb.exe >nul 2>nul && for /f "delims=" %%D in ('where cdb.exe') do if not defined CDB_EXE set "CDB_EXE=%%D"
)
exit /b 0

:install_debugging_tools
echo [SETUP] CDB was not found. Installing official Microsoft Debugging Tools for Windows...
echo [SETUP] Windows may show one UAC confirmation because the debugger is a system component.
set "SDK_DIR=%TEMP%\BSODInvestigatorBuild"
set "SDK_SETUP=%SDK_DIR%\winsdksetup.exe"
if not exist "%SDK_DIR%" mkdir "%SDK_DIR%" || exit /b 1

powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri 'https://go.microsoft.com/fwlink/?linkid=2376217' -OutFile '%SDK_SETUP%'" || (
    echo [ERROR] Failed to download the official Windows SDK installer from Microsoft.
    exit /b 1
)
if not exist "%SDK_SETUP%" (
    echo [ERROR] Windows SDK installer was not downloaded.
    exit /b 1
)

powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$p=Start-Process -FilePath '%SDK_SETUP%' -ArgumentList '/features OptionId.WindowsDesktopDebuggers /quiet /norestart' -Verb RunAs -PassThru -Wait; exit $p.ExitCode"
set "SDK_EXIT=%ERRORLEVEL%"
del /q "%SDK_SETUP%" >nul 2>nul
if not "%SDK_EXIT%"=="0" (
    echo [ERROR] Microsoft Debugging Tools installation failed or UAC was cancelled. Exit code: %SDK_EXIT%
    exit /b 1
)
exit /b 0

:fail
echo.
echo [ERROR] EXE build failed. Read the first error above; no broken build is reported as ready.
if not defined NO_PAUSE pause
exit /b 1

:success
if not defined NO_PAUSE pause
exit /b 0
