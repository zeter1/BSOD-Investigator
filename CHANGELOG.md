# Changelog

## 1.6.0

- Added automatic migration/repair of legacy SQLite crash history without deleting previous analyses.
- Added `crash_history_state` and explicit legacy record statuses.
- Ambiguous legacy `MEMORY.DMP` / Minidump records no longer increase repeat confidence.
- Added manual history repair from the History tab.
- Added `history_repair.json` to AI crash logs and support ZIPs.
- Added driver metadata fallback through OEM INF, `Win32_PnPSignedDriver` and `Get-WindowsDriver`.
- Added provider, INF and device metadata to suspects.
- Improved vendor classification when PE `CompanyName` is empty.
- Fixed duplicate CDB stage markers in timing logs.
- Separated culprit confidence from telemetry quality.
- Expanded regression self-tests for migration, deduplication and provider classification.

## 1.5.0

- Forced UTF-8 for PowerShell/Event Log collection and added repair for older CP866/CP1251 mojibake.
- Added event timeline classification relative to the real crash time.
- Added Dump Health using `volmgr` 161/162 and WER 1001.
- Added WER 1019 driver correlation as weak corroborating evidence.
- Added `BUGCHECK_P1..P4`, `FAILURE_ID_HASH` and crash fingerprints.
- Added deduplication of `MEMORY.DMP` + Minidump belonging to one crash.
- Added a pre-crash ring buffer with lightweight and extended snapshots.
- Separated historically BSOD-related drivers from the general third-party inventory.
- Added `event_timeline.json`, `dump_health.json` and `precrash_timeline.json` to AI logs.
- Expanded regression self-tests.

## 1.4.0

- Removed noisy full-module CDB enumeration from culprit scoring.
- Stopped treating merely loaded `.sys` modules as evidence of fault.
- Corrected classification of third-party drivers signed by Microsoft/WHQL.
- Added faulting-module extraction and improved stack, symbol and failure-bucket parsing.
- Added crash timestamp extraction and time-aligned Windows Event Log collection.
- Limited repeat scoring to independent crashes with direct evidence.
- Added targeted metadata lookup only for evidence-backed candidates.
- Improved CDB shutdown and symbol warning diagnostics.
- Made Minidump the preferred interactive target when `MEMORY.DMP` appears to be the same crash.

## 1.3.0

- Reworked CDB execution around `subprocess.Popen` with live stdout/stderr streaming.
- Added CDB stages, heartbeat, timing and per-session AI-friendly logs.
- Added analysis cancellation and protection against parallel analyses.
- Added a shared analyzer lock for manual and background analysis.
- Added configurable CDB timeout.
- Added latest CDB session context to application error logs.

## 1.2.0

- Added AI-friendly structured problem logging.
- Added JSON + Markdown bundles for application errors and BSOD analyses.
- Added source excerpts/snapshots for program errors.
- Added telemetry self-assessment and scoring-model export.
- Added manual diagnostic snapshots and one-click support ZIP creation.
- Improved CDB discovery.
- Added automatic UAC elevation for protected Minidump access.
- Switched autorun to elevated Windows Task Scheduler instead of the legacy Run key.
