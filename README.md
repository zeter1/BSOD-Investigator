# BSOD Investigator

Windows desktop utility for investigating BSOD crashes using crash dumps, Windows Event Log, driver metadata and historical correlation.

**Current version:** 1.6.0  
**Platform:** Windows 10/11  
**Language:** Python

> BSOD Investigator ranks evidence-backed driver candidates. A top suspect is a diagnostic hypothesis, not proof of fault.

## What it does

- analyzes `Minidump` and `MEMORY.DMP` files through Microsoft CDB/WinDbg;
- extracts BugCheck data, crash time, exception context, faulting module, stack evidence and failure bucket information;
- correlates dump evidence with Windows Event Log events around the actual crash time;
- distinguishes direct crash evidence from weak/passive signals;
- resolves third-party driver metadata using PE information and Windows driver-package data;
- stores analysis history in SQLite and deduplicates multiple dump files from the same crash;
- repairs legacy history records without deleting previous analyses;
- maintains pre-crash telemetry snapshots for additional context;
- monitors historically crash-related drivers separately from the general third-party driver inventory;
- generates structured AI-friendly diagnostic bundles for later troubleshooting;
- supports automatic UAC elevation and elevated startup through Windows Task Scheduler.

## Reliability and diagnostics

The project includes several safeguards intended for long-running diagnostic work:

- a shared analyzer lock prevents parallel dump analyses;
- CDB output is streamed live instead of being captured only after completion;
- configurable CDB timeout, heartbeat and stage tracking;
- cancellation with `terminate` / `kill` fallback;
- explicit symbol warnings and timing information;
- structured problem logs with JSON, Markdown and source context;
- crash fingerprinting to avoid inflating repeat confidence by analyzing the same crash twice;
- separate **culprit confidence** and **telemetry quality** scores.

## Project structure

```text
BSOD-Investigator/
├── bsod_investigator.py       # Application source
├── run.bat                    # Run from source on Windows
├── build_exe.bat              # Build a standalone EXE with PyInstaller
├── requirements.txt           # Runtime dependency notes
├── CHANGELOG.md               # Version history
├── docs/
│   ├── README_RU.md           # Detailed Russian documentation
│   └── UPGRADE_FROM_1.5.md    # Upgrade notes
└── .github/workflows/ci.yml   # Syntax + built-in self-test
```

## Requirements

- Windows 10 or Windows 11;
- Python 3.10+;
- administrator privileges for protected crash dump access;
- **Debugging Tools for Windows / `cdb.exe`** for full dump analysis.

No third-party Python package is required at runtime. The standard Windows Python installer includes Tkinter.

## Run from source

```bat
run.bat
```

or:

```bat
py -3 bsod_investigator.py
```

The application requests UAC elevation when needed.

## Self-test

The source includes a regression-style self-test covering dump parsing, event-log encoding repair, driver scoring, crash fingerprinting, duplicate-crash handling, legacy history repair and telemetry quality.

```bat
py -3 bsod_investigator.py --self-test
```

During repository preparation, the following checks were run successfully with Python 3.13.5:

```text
python -m py_compile bsod_investigator.py
python bsod_investigator.py --self-test
```

## Build EXE

```bat
build_exe.bat
```

The script installs/updates PyInstaller and creates:

```text
dist\BSOD-Investigator.exe
```

## Application data

Persistent data is stored under:

```text
%LOCALAPPDATA%\BSODInvestigator
```

This includes configuration, SQLite history, reports, snapshots and runtime logs. Problem logs prefer a visible `Логи проблем` directory next to the application when writable and fall back to LocalAppData.

These runtime artifacts are intentionally excluded from this repository.

## Privacy

Diagnostic logs can contain technical file paths, driver/process names, Windows version information and possibly the Windows profile name inside paths. Crash dumps may contain fragments of system memory and should be reviewed before sharing with third parties.

The repository does **not** include personal crash dumps, local analysis history, runtime databases or collected diagnostic logs.

## Documentation

- [Detailed Russian documentation](docs/README_RU.md)
- [Changelog](CHANGELOG.md)
- [Upgrade from 1.5](docs/UPGRADE_FROM_1.5.md)

## Development approach

This project was developed iteratively from real diagnostic logs. Later releases focused on reducing false positives, separating evidence strength from telemetry quality, improving process lifecycle handling, and making diagnostic output easier to analyze with AI-assisted tooling.
