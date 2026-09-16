**Язык / Language:** [Русский](README.md) · **English**

# BSOD Investigator

**BSOD Investigator** is a Windows diagnostic application for investigating Blue Screen of Death (BSOD) failures. It analyzes memory dumps through Microsoft CDB/WinDbg and correlates the results with Windows Event Log data, driver metadata, and previous crash history.

The project is designed as an engineering diagnostic tool rather than a single-signal guesser: it combines multiple evidence sources, estimates confidence, and preserves technical context for further analysis.

**Version:** 1.6.0  
**Platform:** Windows 10/11  
**Language:** Python

> The primary suspect is a diagnostic hypothesis based on the available evidence, not definitive proof of a root cause.

## What this project demonstrates

- Windows crash-dump analysis with WinDbg/CDB and Event Log data;
- correlation of multiple diagnostic sources instead of relying on one indicator;
- separation between evidence strength and telemetry quality;
- SQLite-backed history with protection against double-counting the same crash;
- external diagnostic-process control with timeouts, heartbeat tracking, and safe cancellation;
- compact structured reports for follow-up technical analysis;
- built-in regression/self-tests for critical parsing and scoring logic.

## Main features

- analysis of `Minidump` and `MEMORY.DMP` files through Microsoft CDB / WinDbg;
- extraction of BugCheck, exception context, stack, failure bucket, and suspect module;
- correlation with related Windows Event Log events;
- metadata analysis for third-party drivers;
- distinction between strong and indirect diagnostic signals;
- SQLite analysis history;
- crash fingerprints to prevent duplicate historical weighting;
- pre-crash telemetry and historical driver relationships;
- separate confidence and telemetry-quality indicators;
- structured JSON/Markdown diagnostics suitable for technical analysis and ChatGPT/Codex workflows;
- automatic UAC elevation when required.

## Installation

### 1. Install Python

Python 3.10 or newer for Windows is recommended.

### 2. Install Debugging Tools for Windows

Full dump analysis requires Microsoft `cdb.exe`, included with **Debugging Tools for Windows / Windows SDK**.

### 3. Download the project

Use **Code → Download ZIP** and extract the repository, or clone it with Git:

```bash
git clone https://github.com/zeter1/BSOD-Investigator.git
cd BSOD-Investigator
```

The core application does not require third-party Python packages. Tkinter is included in the standard Windows Python installation.

## Running

The simplest option:

```bat
run.bat
```

or directly:

```bat
py -3 bsod_investigator.py
```

If protected dump access requires elevation, the application will request it through UAC.

## Usage

1. Start BSOD Investigator.
2. Select a detected crash dump or choose a dump file manually.
3. Start analysis.
4. Wait for CDB/WinDbg analysis and Windows context collection to complete.
5. Review the BugCheck, stack, suspect drivers, confidence level, and telemetry quality.
6. Compare the result with previous crash history when available.
7. For difficult cases, use the generated diagnostic reports for deeper analysis.

For the most useful result, analyze the original dump file and keep application history between recurring crashes.

## Reliability and diagnostics

- a global lock prevents conflicting parallel analyses;
- CDB output is streamed while analysis runs;
- timeouts, heartbeat tracking, and explicit stages are used;
- stalled processes can be terminated safely;
- symbol problems are reported separately;
- diagnostic artifacts preserve source, context, and traceback information;
- re-analyzing the same crash should not artificially increase confidence.

## Project structure

```text
BSOD-Investigator/
├── bsod_investigator.py       # application and diagnostic pipeline
├── run.bat                    # launcher
├── build_exe.bat              # EXE build
├── requirements.txt
├── CHANGELOG.md
├── SECURITY.md
├── SUPPORT.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── README_RU.md
│   └── UPGRADE_FROM_1.5.md
└── .github/
    ├── ISSUE_TEMPLATE/
    │   └── bug_report.yml
    └── workflows/
        └── ci.yml
```

A detailed map of the pipeline, scoring, persistence, and subsystem boundaries is available in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Self-test

```bat
py -3 bsod_investigator.py --self-test
```

Syntax can also be checked with:

```bat
python -m py_compile bsod_investigator.py
```

CI runs compilation plus the safe built-in self-test. Full runtime analysis of a real dump through CDB/WinDbg requires a real Windows diagnostic environment.

## Building an EXE

```bat
build_exe.bat
```

The resulting executable is created at:

```text
dist\BSOD-Investigator.exe
```

## Application data

Runtime data is stored in:

```text
%LOCALAPPDATA%\BSODInvestigator
```

This includes configuration, SQLite history, reports, telemetry, and working logs.

## Limitations

- the tool helps build a diagnostic hypothesis but cannot prove the cause of every BSOD from a single signal;
- result quality depends on dump contents, symbol availability, and Debugging Tools for Windows;
- hardware, firmware, and some low-level failures may require diagnostics outside the application;
- CI does not replace validation of the real Windows dump-analysis pipeline.

## Privacy

Crash dumps may contain fragments of system memory. Diagnostic reports can also contain local paths, driver names, and process names. Review files before sharing them with third parties.

The repository does not contain user crash dumps, local analysis history, or runtime diagnostic data.

See [`SECURITY.md`](SECURITY.md) for safer diagnostic-data sharing guidance.

## Documentation and support

- [Architecture and pipeline](docs/ARCHITECTURE.md)
- [Detailed Russian documentation](docs/README_RU.md)
- [Changelog](CHANGELOG.md)
- [Upgrade from version 1.5](docs/UPGRADE_FROM_1.5.md)
- [Security / diagnostic data](SECURITY.md)
- [Support and diagnostic preparation](SUPPORT.md)

## License

No open-source license is currently granted. The source code is published for portfolio review, implementation study, and code review.
