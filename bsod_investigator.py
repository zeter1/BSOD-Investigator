from __future__ import annotations

import csv
import ctypes
import datetime as dt
import hashlib
import html
import io
import json
import math
import os
import platform
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
import zipfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable, Iterable

APP_NAME = "BSOD Investigator"
APP_VERSION = "1.6.0"
AUTORUN_VALUE = "BSODInvestigator"
AUTORUN_TASK = "BSOD Investigator"
DEFAULT_POLL_SECONDS = 10
DEFAULT_SNAPSHOT_SECONDS = 60
DEFAULT_FAST_SNAPSHOT_SECONDS = 15
DEFAULT_PRECRASH_WINDOW_MINUTES = 30
DEFAULT_EVENT_SECONDS = 30

IS_WINDOWS = os.name == "nt"
WINDOWS_DIR = Path(os.environ.get("WINDIR", r"C:\Windows")) if IS_WINDOWS else Path("/tmp/Windows")
MINIDUMP_DIR = WINDOWS_DIR / "Minidump"
MEMORY_DMP = WINDOWS_DIR / "MEMORY.DMP"

LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA", Path.home())) if IS_WINDOWS else Path.home()
DATA_DIR = LOCAL_APPDATA / "BSODInvestigator"
REPORT_DIR = DATA_DIR / "reports"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
LOG_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "history.sqlite3"
CONFIG_PATH = DATA_DIR / "config.json"
APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
AI_LOG_SCHEMA_VERSION = "1.4"
SCORING_MODEL_VERSION = "1.6"

def _choose_problem_log_dir() -> Path:
    """Prefer a visible portable folder next to the program, fall back to LocalAppData."""
    candidates = [APP_DIR / "Логи проблем", DATA_DIR / "Логи проблем"]
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return candidate
        except Exception:
            continue
    return DATA_DIR / "Логи проблем"

PROBLEM_LOG_DIR = _choose_problem_log_dir()

for _p in (DATA_DIR, REPORT_DIR, SNAPSHOT_DIR, LOG_DIR, PROBLEM_LOG_DIR):
    try:
        _p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

SYSTEM_DRIVER_NAMES = {
    "ntoskrnl.exe", "ntkrnlmp.exe", "hal.dll", "win32kfull.sys", "win32kbase.sys",
    "fltmgr.sys", "ndis.sys", "tcpip.sys", "dxgkrnl.sys", "watchdog.sys", "wdf01000.sys",
    "clfs.sys", "ci.dll", "acpi.sys", "storport.sys", "classpnp.sys", "ntfs.sys",
    "afd.sys", "netio.sys", "ks.sys", "portcls.sys", "usbaudio.sys", "usbccgp.sys",
    "hidclass.sys", "hidparse.sys", "kbdclass.sys", "mouclass.sys", "partmgr.sys",
}

MICROSOFT_COMPANY_HINTS = ("microsoft corporation", "microsoft windows")
MICROSOFT_SIGNER_HINTS = ("microsoft windows hardware compatibility publisher", "microsoft windows third party component ca")

SCORING_RULES = {
    # Strong crash evidence from !analyze -v / context / stack.
    "faulting_module": 45,
    "image_name": 40,
    "module_name": 25,
    "probably_caused_by": 45,
    "symbol_name": 20,
    "failure_bucket_id": 30,
    "stack_module": 25,
    "process_affinity": 10,
    # Metadata only adjusts an already evidence-backed candidate.
    "system_driver_penalty": -50,
    "microsoft_vendor_penalty": -35,
    "third_party_bonus": 10,
    "unsigned_bonus": 5,
    "recent_driver_bonus": 3,
    # Repeat bonus is based only on independent crashes with strong evidence.
    "repeat_bonus_1": 18,
    "repeat_bonus_2": 30,
    "repeat_bonus_3": 40,
    "repeat_bonus_4_plus": 50,
    # WER 1019 is corroborating evidence from the same crash pipeline, so it gets a small weight.
    "wer_driver_correlation": 10,
}

BUGCHECK_NAMES = {
    "1a": "MEMORY_MANAGEMENT",
    "3b": "SYSTEM_SERVICE_EXCEPTION",
    "50": "PAGE_FAULT_IN_NONPAGED_AREA",
    "7e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    "7f": "UNEXPECTED_KERNEL_MODE_TRAP",
    "9f": "DRIVER_POWER_STATE_FAILURE",
    "a": "IRQL_NOT_LESS_OR_EQUAL",
    "c2": "BAD_POOL_CALLER",
    "c4": "DRIVER_VERIFIER_DETECTED_VIOLATION",
    "c5": "DRIVER_CORRUPTED_EXPOOL",
    "c6": "DRIVER_CAUGHT_MODIFYING_FREED_POOL",
    "d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    "e6": "DRIVER_VERIFIER_DMA_VIOLATION",
    "ef": "CRITICAL_PROCESS_DIED",
    "101": "CLOCK_WATCHDOG_TIMEOUT",
    "116": "VIDEO_TDR_FAILURE",
    "124": "WHEA_UNCORRECTABLE_ERROR",
    "133": "DPC_WATCHDOG_VIOLATION",
    "139": "KERNEL_SECURITY_CHECK_FAILURE",
    "13a": "KERNEL_MODE_HEAP_CORRUPTION",
    "154": "UNEXPECTED_STORE_EXCEPTION",
}


class AnalysisBusyError(RuntimeError):
    """Raised when another dump analysis is already running."""


class AnalysisCancelledError(RuntimeError):
    """Raised when the user cancels a running CDB analysis."""


@dataclass
class Config:
    poll_seconds: int = DEFAULT_POLL_SECONDS
    snapshot_seconds: int = DEFAULT_SNAPSHOT_SECONDS
    fast_snapshot_seconds: int = DEFAULT_FAST_SNAPSHOT_SECONDS
    precrash_window_minutes: int = DEFAULT_PRECRASH_WINDOW_MINUTES
    event_seconds: int = DEFAULT_EVENT_SECONDS
    cdb_path: str = ""
    auto_analyze_new_dumps: bool = True
    monitor_enabled: bool = True
    include_dump_in_support_zip: bool = True
    hide_on_startup: bool = False
    cdb_timeout_seconds: int = 600

    @classmethod
    def load(cls) -> "Config":
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            allowed = {k: raw[k] for k in cls.__annotations__ if k in raw}
            return cls(**allowed)
        except Exception:
            return cls()

    def save(self) -> None:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass
class DriverInfo:
    name: str
    path: str = ""
    company: str = ""
    version: str = ""
    signed: bool | None = None
    signer: str = ""
    start_mode: str = ""
    state: str = ""
    modified_utc: str = ""
    product: str = ""
    description: str = ""
    original_filename: str = ""
    provider: str = ""
    inf_name: str = ""
    device_name: str = ""

    @property
    def filename(self) -> str:
        return Path(self.path).name.lower() if self.path else self.name.lower()

    @property
    def microsoft(self) -> bool:
        """True only when the binary vendor itself is Microsoft.

        A Microsoft/WHQL Authenticode signer does NOT make a third-party driver a
        Microsoft driver. This distinction is critical for BSOD attribution.
        """
        # Prefer the binary CompanyName, but fall back to the driver-package provider
        # when PE version resources are empty (common for some third-party .sys files).
        c = re.sub(r"\s+", " ", (self.company or self.provider or "").strip().lower())
        return bool(c) and any(x in c for x in MICROSOFT_COMPANY_HINTS)

    @property
    def microsoft_signed_third_party(self) -> bool:
        s = (self.signer or "").lower()
        return (not self.microsoft) and any(x in s for x in MICROSOFT_SIGNER_HINTS)


@dataclass
class Suspect:
    driver: str
    score: int
    confidence: int
    level: str
    evidence: list[str] = field(default_factory=list)
    company: str = ""
    version: str = ""
    path: str = ""
    signed: bool | None = None
    signer: str = ""
    product: str = ""
    description: str = ""
    provider: str = ""
    inf_name: str = ""
    device_name: str = ""
    vendor_type: str = ""
    strong_evidence_count: int = 0


@dataclass
class CrashReport:
    dump_path: str
    dump_name: str
    analyzed_at: str
    dump_mtime: str
    sha256: str
    crash_time_utc: str = ""
    debug_session_time_raw: str = ""
    dump_size_bytes: int = 0
    dump_kind: str = ""
    symbol_warnings: list[str] = field(default_factory=list)
    bugcheck_code: str = ""
    bugcheck_name: str = ""
    exception_code: str = ""
    process_name: str = ""
    module_name: str = ""
    image_name: str = ""
    symbol_name: str = ""
    failure_bucket_id: str = ""
    failure_id_hash: str = ""
    bugcheck_parameters: list[str] = field(default_factory=list)
    crash_fingerprint: str = ""
    probable_cause_line: str = ""
    faulting_module: str = ""
    stack_modules: list[str] = field(default_factory=list)
    wer_driver_correlations: list[str] = field(default_factory=list)
    event_timeline: list[dict[str, Any]] = field(default_factory=list)
    dump_health: dict[str, Any] = field(default_factory=dict)
    suspects: list[Suspect] = field(default_factory=list)
    debugger_found: bool = False
    debugger_path: str = ""
    debugger_session_log: str = ""
    raw_debugger_output: str = ""
    nearby_events: list[dict[str, Any]] = field(default_factory=list)
    precrash_snapshot: dict[str, Any] = field(default_factory=dict)
    precrash_timeline: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def telemetry_quality(report: CrashReport) -> dict[str, Any]:
    """Independent quality score for the amount of telemetry collected.

    This is intentionally separate from culprit confidence. A dump can identify one
    driver very strongly even when no pre-crash ring exists, and vice versa.
    """
    present: list[str] = []
    missing: list[str] = []
    weighted_checks = [
        (report.debugger_found and bool(report.raw_debugger_output), "CDB/WinDbg output", 15),
        (bool(report.crash_time_utc), "crash timestamp from dump (.time)", 5),
        (bool(report.bugcheck_code), "BugCheck code", 10),
        (bool(report.faulting_module), "faulting module/context", 10),
        (bool(report.image_name), "IMAGE_NAME", 8),
        (bool(report.module_name), "MODULE_NAME", 8),
        (bool(report.symbol_name), "SYMBOL_NAME", 6),
        (bool(report.failure_bucket_id), "FAILURE_BUCKET_ID", 8),
        (bool(report.stack_modules), "crash stack modules", 10),
        (bool(report.probable_cause_line), "Probably caused by", 3),
        (bool(report.event_timeline), "classified Windows event timeline", 5),
        (bool(report.wer_driver_correlations), "WER driver correlation", 3),
        (bool(report.dump_health), "dump health summary", 3),
        (bool(report.precrash_timeline), "pre-crash ring buffer", 4),
        (bool(report.suspects), "scored suspects", 2),
    ]
    score = 0
    total = sum(w for _, _, w in weighted_checks) or 1
    for ok, name, weight in weighted_checks:
        (present if ok else missing).append(name)
        if ok:
            score += weight
    pct = max(0, min(100, round(score * 100 / total)))
    if pct >= 90:
        level = "VERY HIGH"
    elif pct >= 75:
        level = "HIGH"
    elif pct >= 55:
        level = "MEDIUM"
    elif pct >= 30:
        level = "LOW"
    else:
        level = "VERY LOW"

    guardrail = "high"
    if not report.debugger_found or not report.raw_debugger_output or not report.suspects:
        guardrail = "low"
    else:
        strong = report.suspects[0].strong_evidence_count if report.suspects else 0
        if strong <= 1:
            guardrail = "low"
        elif strong <= 3:
            guardrail = "medium"
    return {
        "present_signals": present,
        "missing_signals": missing,
        "telemetry_score": pct,
        "telemetry_level": level,
        "culprit_confidence_guardrail": guardrail,
        "recommended_confidence_cap": guardrail,
        "important_distinction": "Telemetry quality is independent from heuristic culprit confidence.",
    }


class HistoryDB:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.last_repair_stats: dict[str, Any] = {}
        self._init()
        try:
            self.last_repair_stats = self.repair_legacy_history()
        except Exception as exc:
            self.last_repair_stats = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def _init(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS crashes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dump_sha256 TEXT UNIQUE,
                    dump_path TEXT,
                    dump_name TEXT,
                    dump_mtime TEXT,
                    analyzed_at TEXT,
                    bugcheck_code TEXT,
                    bugcheck_name TEXT,
                    culprit TEXT,
                    confidence INTEGER,
                    report_json TEXT,
                    report_html TEXT
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS snapshots(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT,
                    payload_json TEXT
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS events(
                    record_key TEXT PRIMARY KEY,
                    created_at TEXT,
                    provider TEXT,
                    event_id INTEGER,
                    level TEXT,
                    message TEXT,
                    payload_json TEXT
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS crash_history_state(
                    dump_sha256 TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    canonical_sha256 TEXT,
                    reason TEXT,
                    updated_at TEXT
                )
            """)
            con.commit()

    def has_dump_hash(self, sha: str) -> bool:
        with self._connect() as con:
            row = con.execute("SELECT 1 FROM crashes WHERE dump_sha256=?", (sha,)).fetchone()
            return row is not None

    def save_crash(self, report: CrashReport, json_path: Path, html_path: Path):
        culprit = report.suspects[0].driver if report.suspects else ""
        confidence = report.suspects[0].confidence if report.suspects else 0
        payload = json.dumps(report.to_dict(), ensure_ascii=False)
        with self._lock, self._connect() as con:
            con.execute("""
                INSERT INTO crashes(dump_sha256,dump_path,dump_name,dump_mtime,analyzed_at,
                    bugcheck_code,bugcheck_name,culprit,confidence,report_json,report_html)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(dump_sha256) DO UPDATE SET
                    analyzed_at=excluded.analyzed_at,
                    bugcheck_code=excluded.bugcheck_code,
                    bugcheck_name=excluded.bugcheck_name,
                    culprit=excluded.culprit,
                    confidence=excluded.confidence,
                    report_json=excluded.report_json,
                    report_html=excluded.report_html
            """, (
                report.sha256, report.dump_path, report.dump_name, report.dump_mtime,
                report.analyzed_at, report.bugcheck_code, report.bugcheck_name, culprit,
                confidence, str(json_path), str(html_path)
            ))
            con.commit()
        # Keep migration state current after each new analysis. This is intentionally
        # outside the DB write lock because repair_legacy_history opens its own connection.
        try:
            self.last_repair_stats = self.repair_legacy_history()
        except Exception:
            pass

    def list_crashes(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute("""
                SELECT c.id,c.dump_name,c.dump_mtime,c.analyzed_at,c.bugcheck_code,c.bugcheck_name,
                       c.culprit,c.confidence,c.report_json,c.report_html,c.dump_path,c.dump_sha256,
                       COALESCE(s.status,'') AS history_status,
                       COALESCE(s.canonical_sha256,'') AS canonical_sha256,
                       COALESCE(s.reason,'') AS history_reason
                FROM crashes c
                LEFT JOIN crash_history_state s ON s.dump_sha256=c.dump_sha256
                ORDER BY c.id DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    def previous_driver_hits(self, driver: str) -> int:
        if not driver:
            return 0
        with self._connect() as con:
            rows = con.execute("SELECT report_json FROM crashes ORDER BY id DESC LIMIT 50").fetchall()
        count = 0
        target = driver.lower()
        for row in rows:
            try:
                p = Path(row[0])
                if p.exists():
                    d = json.loads(p.read_text(encoding="utf-8"))
                    names = [x.get("driver", "").lower() for x in d.get("suspects", [])[:3]]
                    if target in names:
                        count += 1
            except Exception:
                pass
        return count

    @staticmethod
    def _report_direct_drivers(d: dict[str, Any]) -> set[str]:
        direct: set[str] = set()
        img = Path(str(d.get("image_name") or "")).name.lower()
        if img.endswith('.sys'):
            direct.add(img)
        for key in ("module_name", "faulting_module"):
            mod = str(d.get(key) or "").strip()
            if mod:
                direct.add((mod if mod.lower().endswith('.sys') else mod + '.sys').lower())
        for field in ("symbol_name", "failure_bucket_id", "probable_cause_line"):
            text = str(d.get(field) or "")
            for tok in re.findall(r"(?i)([A-Za-z0-9_.-]+)(?:\.sys)?!", text):
                direct.add((tok + '.sys').lower())
            for tok in re.findall(r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b", text):
                direct.add(tok.lower())
        for tok in d.get("stack_modules", []) or []:
            t = str(tok).lower()
            direct.add(t if t.endswith('.sys') else t + '.sys')
        return direct

    @staticmethod
    def _legacy_crash_key(d: dict[str, Any]) -> str:
        """Build a dedupe key even for reports created before crash_fingerprint existed."""
        fp = str(d.get("crash_fingerprint") or "").strip()
        if fp:
            return "fp:" + fp
        crash_time = str(d.get("crash_time_utc") or d.get("dump_mtime") or "")
        try:
            t = parse_iso(crash_time).replace(microsecond=0)
            # Bucket to 10 seconds so MEMORY.DMP/minidump timestamps with tiny drift merge.
            t = t - dt.timedelta(seconds=t.second % 10)
            crash_time = t.isoformat()
        except Exception:
            pass
        bc = str(d.get("bugcheck_code") or "").lower()
        bucket = str(d.get("failure_bucket_id") or "").lower()
        failure_hash = str(d.get("failure_id_hash") or "").lower()
        params = "|".join(str(x or "").lower() for x in d.get("bugcheck_parameters", []) or [])
        return "legacy:" + hashlib.sha1(f"{crash_time}|{bc}|{params}|{failure_hash}|{bucket}".encode("utf-8", "ignore")).hexdigest()

    @staticmethod
    def _normalized_crash_signature(d: dict[str, Any]) -> dict[str, Any]:
        """Return conservative fields used to repair history created by older versions."""
        drivers = HistoryDB._report_direct_drivers(d)
        culprit = Path(str(d.get("culprit") or "")).name.lower()
        if culprit:
            if not culprit.endswith(".sys") and "." not in culprit:
                culprit += ".sys"
            drivers.add(culprit)
        return {
            "bugcheck": str(d.get("bugcheck_code") or "").strip().lower().removeprefix("0x"),
            "bucket": str(d.get("failure_bucket_id") or "").strip().lower(),
            "failure_hash": str(d.get("failure_id_hash") or "").strip().lower(),
            "params": tuple(str(x or "").strip().lower().removeprefix("0x") for x in (d.get("bugcheck_parameters") or [])),
            "drivers": drivers,
            "fingerprint": str(d.get("crash_fingerprint") or "").strip(),
            "crash_time": str(d.get("crash_time_utc") or "").strip(),
            "dump_name": str(d.get("dump_name") or "").strip(),
        }

    @staticmethod
    def _legacy_matches_canonical(legacy: dict[str, Any], canonical: dict[str, Any]) -> bool:
        """Best-effort identity test used only to suppress dubious legacy duplicates."""
        a = HistoryDB._normalized_crash_signature(legacy)
        b = HistoryDB._normalized_crash_signature(canonical)
        if a["bugcheck"] and b["bugcheck"] and a["bugcheck"] != b["bugcheck"]:
            return False
        if a["failure_hash"] and b["failure_hash"] and a["failure_hash"] == b["failure_hash"]:
            return True
        if a["params"] and b["params"] and a["params"] == b["params"] and any(a["params"]):
            return True
        same_bucket = bool(a["bucket"] and b["bucket"] and a["bucket"] == b["bucket"])
        same_driver = bool(a["drivers"] and b["drivers"] and (a["drivers"] & b["drivers"]))
        return same_bucket or same_driver

    def repair_legacy_history(self) -> dict[str, Any]:
        """Repair v1.0-v1.5 history without deleting rows.

        Legacy rows that lack a real crash fingerprint/timestamp are classified in a
        side table. Ambiguous MEMORY.DMP/minidump duplicates remain visible in History
        but are excluded from repeat bonuses until they can be proven independent.
        """
        with self._connect() as con:
            rows = con.execute("""
                SELECT id,dump_sha256,dump_name,dump_mtime,bugcheck_code,culprit,report_json
                FROM crashes ORDER BY id
            """).fetchall()

        records: list[dict[str, Any]] = []
        for row in rows:
            payload: dict[str, Any] = {}
            readable = False
            try:
                rp = Path(str(row["report_json"] or ""))
                if rp.exists():
                    payload = json.loads(rp.read_text(encoding="utf-8"))
                    readable = isinstance(payload, dict)
            except Exception:
                payload = {}
            payload.setdefault("dump_name", str(row["dump_name"] or ""))
            payload.setdefault("dump_mtime", str(row["dump_mtime"] or ""))
            payload.setdefault("bugcheck_code", str(row["bugcheck_code"] or ""))
            payload.setdefault("culprit", str(row["culprit"] or ""))
            records.append({"id": int(row["id"]), "sha": str(row["dump_sha256"] or ""), "data": payload, "readable": readable})

        canonicals = [r for r in records if str(r["data"].get("crash_fingerprint") or "").strip()]
        counts = {"canonical": 0, "legacy_unique": 0, "legacy_ambiguous_duplicate": 0, "legacy_unresolved": 0, "unreadable": 0}
        state_rows: list[tuple[str, str, str, str, str]] = []

        for rec in records:
            sha, d = rec["sha"], rec["data"]
            if not sha:
                continue
            fp = str(d.get("crash_fingerprint") or "").strip()
            if fp:
                status, canonical_sha, reason = "canonical", sha, "report contains crash_fingerprint"
            elif not rec["readable"]:
                status, canonical_sha, reason = "unreadable", "", "report_json is missing or unreadable"
            else:
                sig = self._normalized_crash_signature(d)
                matches = [c for c in canonicals if self._legacy_matches_canonical(d, c["data"])]
                near_matches: list[dict[str, Any]] = []
                legacy_time = None
                if sig["crash_time"]:
                    try:
                        legacy_time = parse_iso(sig["crash_time"])
                    except Exception:
                        legacy_time = None
                if legacy_time:
                    for c in matches:
                        ct = str(c["data"].get("crash_time_utc") or "")
                        try:
                            if ct and abs((legacy_time - parse_iso(ct)).total_seconds()) <= 600:
                                near_matches.append(c)
                        except Exception:
                            pass
                if near_matches:
                    chosen = near_matches[0]
                    status, canonical_sha = "legacy_ambiguous_duplicate", chosen["sha"]
                    reason = "matches a fingerprinted incident within 10 minutes"
                elif legacy_time:
                    status, canonical_sha = "legacy_unique", sha
                    reason = "has crash_time_utc and no nearby canonical match"
                elif matches and (str(sig["dump_name"]).lower() == "memory.dmp" or len(matches) == 1):
                    chosen = matches[0]
                    status, canonical_sha = "legacy_ambiguous_duplicate", chosen["sha"]
                    reason = "lacks crash timestamp/fingerprint and plausibly represents the same incident"
                else:
                    status, canonical_sha = "legacy_unresolved", ""
                    reason = "not enough identity data to prove an independent crash"
            counts[status] = counts.get(status, 0) + 1
            state_rows.append((sha, status, canonical_sha, reason, utc_now()))

        with self._lock, self._connect() as con:
            con.execute("DELETE FROM crash_history_state")
            con.executemany("""
                INSERT INTO crash_history_state(dump_sha256,status,canonical_sha256,reason,updated_at)
                VALUES(?,?,?,?,?)
            """, state_rows)
            con.commit()

        return {
            "status": "ok", "total_rows": len(records), **counts,
            "ignored_for_repeat_scoring": counts.get("legacy_ambiguous_duplicate", 0) + counts.get("legacy_unresolved", 0) + counts.get("unreadable", 0),
            "generated_at": utc_now(),
        }

    def history_state(self, sha: str) -> dict[str, Any]:
        if not sha:
            return {}
        with self._connect() as con:
            row = con.execute(
                "SELECT status,canonical_sha256,reason,updated_at FROM crash_history_state WHERE dump_sha256=?",
                (sha,),
            ).fetchone()
        return dict(row) if row else {}


    def previous_driver_strong_hit_details(
        self,
        driver: str,
        exclude_sha: str = "",
        crash_time_utc: str = "",
        crash_fingerprint: str = "",
    ) -> list[dict[str, Any]]:
        """Return unique prior crash incidents where *driver* had direct evidence.

        Multiple dump files (MEMORY.DMP + Minidump) and repeated analyses of the same
        incident are collapsed into one item. The returned incident list is used both
        for scoring and the Monitoring UI, so the user can see what "2 previous BSODs"
        actually means instead of trusting an opaque counter.
        """
        if not driver:
            return []
        target = Path(driver).name.lower()
        current_time = None
        try:
            current_time = parse_iso(crash_time_utc) if crash_time_utc else None
        except Exception:
            current_time = None
        current_fp = (crash_fingerprint or "").strip()
        with self._connect() as con:
            rows = con.execute("""
                SELECT c.dump_sha256,c.report_json,
                       COALESCE(s.status,'') AS history_status,
                       COALESCE(s.canonical_sha256,'') AS canonical_sha256,
                       COALESCE(s.reason,'') AS history_reason
                FROM crashes c
                LEFT JOIN crash_history_state s ON s.dump_sha256=c.dump_sha256
                ORDER BY c.id DESC LIMIT 120
            """).fetchall()
        unique: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                old_sha, report_json = row[0], row[1]
                history_status = str(row[2] or "")
                canonical_sha = str(row[3] or "")
                history_reason = str(row[4] or "")
                if history_status in {"legacy_ambiguous_duplicate", "legacy_unresolved", "unreadable"}:
                    continue
                if exclude_sha and old_sha == exclude_sha:
                    continue
                rp = Path(report_json)
                if not rp.exists():
                    continue
                d = json.loads(rp.read_text(encoding="utf-8"))
                old_fp = str(d.get("crash_fingerprint") or "").strip()
                if current_fp and old_fp and current_fp == old_fp:
                    continue
                old_time = None
                try:
                    if d.get("crash_time_utc"):
                        old_time = parse_iso(str(d.get("crash_time_utc")))
                    elif d.get("dump_mtime"):
                        old_time = parse_iso(str(d.get("dump_mtime")))
                except Exception:
                    old_time = None
                # Safety net for legacy reports that lack a fingerprint.
                if current_time and old_time and abs((current_time - old_time).total_seconds()) <= 600:
                    # Same crash can be represented by two dump files. A ten-minute
                    # proximity guard is used only when an older report lacks a fingerprint.
                    if not old_fp or not current_fp:
                        continue
                if target not in self._report_direct_drivers(d):
                    continue
                key = self._legacy_crash_key(d)
                if key in unique:
                    continue
                unique[key] = {
                    "crash_key": key,
                    "crash_fingerprint": old_fp,
                    "crash_time_utc": str(d.get("crash_time_utc") or ""),
                    "bugcheck_code": str(d.get("bugcheck_code") or ""),
                    "bugcheck_name": str(d.get("bugcheck_name") or ""),
                    "dump_name": str(d.get("dump_name") or ""),
                    "failure_bucket_id": str(d.get("failure_bucket_id") or ""),
                    "failure_id_hash": str(d.get("failure_id_hash") or ""),
                    "history_status": history_status or ("canonical" if old_fp else "legacy_unique"),
                    "canonical_sha256": canonical_sha,
                    "history_reason": history_reason,
                }
            except Exception:
                pass
        items = list(unique.values())
        items.sort(key=lambda x: x.get("crash_time_utc") or "", reverse=True)
        return items

    def previous_driver_strong_hits(
        self,
        driver: str,
        exclude_sha: str = "",
        crash_time_utc: str = "",
        crash_fingerprint: str = "",
    ) -> int:
        return len(self.previous_driver_strong_hit_details(
            driver, exclude_sha=exclude_sha, crash_time_utc=crash_time_utc,
            crash_fingerprint=crash_fingerprint,
        ))

    def save_snapshot(self, payload: dict[str, Any]):
        now = str(payload.get("created_at") or utc_now())
        with self._lock, self._connect() as con:
            con.execute("INSERT INTO snapshots(created_at,payload_json) VALUES(?,?)",
                        (now, json.dumps(payload, ensure_ascii=False)))
            # Fast snapshots can arrive every 15 seconds. Keep enough rows for roughly
            # 8 hours plus headroom, while the crash AI log exports only the requested
            # pre-crash ring window.
            con.execute("DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY id DESC LIMIT 2500)")
            con.commit()

    def precrash_timeline(self, when_iso: str, window_minutes: int = 30, limit: int = 1000) -> list[dict[str, Any]]:
        """Return only snapshots at or BEFORE the crash, never post-crash snapshots."""
        try:
            target = parse_iso(when_iso)
        except Exception:
            return []
        start = target - dt.timedelta(minutes=max(1, window_minutes))
        with self._connect() as con:
            rows = con.execute(
                "SELECT created_at,payload_json FROM snapshots WHERE created_at<=? AND created_at>=? ORDER BY created_at ASC LIMIT ?",
                (target.isoformat(), start.isoformat(), max(1, limit)),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row[1])
                t = parse_iso(row[0])
                payload.setdefault("created_at", row[0])
                payload["delta_from_crash_seconds"] = round((t - target).total_seconds(), 3)
                result.append(payload)
            except Exception:
                pass
        return result

    def nearest_snapshot(self, when_iso: str, max_age_seconds: int = 900) -> dict[str, Any]:
        """Return the newest snapshot BEFORE the target time.

        v1.4 used absolute distance and could accidentally select a post-crash snapshot
        after reboot. For causal diagnostics only pre-crash telemetry is valid here.
        """
        timeline = self.precrash_timeline(when_iso, window_minutes=max(1, math.ceil(max_age_seconds / 60)), limit=500)
        return timeline[-1] if timeline else {}

    def save_event(self, event: dict[str, Any]):
        key = str(event.get("RecordId") or event.get("record_id") or "")
        provider = str(event.get("ProviderName") or event.get("provider") or "")
        event_id = int(event.get("Id") or event.get("event_id") or 0)
        created = str(event.get("TimeCreated") or event.get("created_at") or utc_now())
        if not key:
            key = hashlib.sha1(f"{created}|{provider}|{event_id}|{event.get('Message','')}".encode("utf-8", "ignore")).hexdigest()
        payload = json.dumps(event, ensure_ascii=False)
        with self._lock, self._connect() as con:
            con.execute("""
                INSERT OR IGNORE INTO events(record_key,created_at,provider,event_id,level,message,payload_json)
                VALUES(?,?,?,?,?,?,?)
            """, (key, created, provider, event_id, str(event.get("LevelDisplayName", "")),
                  str(event.get("Message", "")), payload))
            con.commit()


class WindowsTools:
    def __init__(self, config: Config):
        self.config = config
        self._active_cdb_lock = threading.Lock()
        self._active_cdb_proc: subprocess.Popen | None = None

    def cancel_active_cdb(self) -> None:
        """Best-effort synchronous stop used when the GUI is closing."""
        with self._active_cdb_lock:
            proc = self._active_cdb_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    @staticmethod
    def run(cmd: list[str], timeout: int = 90, creationflags: int = 0) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
                              creationflags=creationflags)

    @staticmethod
    def powershell(script: str, timeout: int = 90) -> str:
        """Run Windows PowerShell with explicit UTF-8 output.

        Windows PowerShell 5.1 may otherwise inherit an OEM console code page (often
        CP866 on Russian Windows), which turns Event Log messages into mojibake when
        Python decodes them. We set both PowerShell and console output encodings and
        decode the redirected pipe as UTF-8.
        """
        if not IS_WINDOWS:
            return ""
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        prefix = (
            "$OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        )
        cp = subprocess.run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-Command", prefix + script
        ], capture_output=True, text=True, encoding="utf-8", errors="replace",
           timeout=timeout, creationflags=flags)
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or f"PowerShell exit {cp.returncode}")
        return cp.stdout.strip().lstrip("\ufeff")

    def find_cdb(self) -> str:
        candidates = []
        if self.config.cdb_path:
            candidates.append(self.config.cdb_path)
        for root in [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")]:
            if root:
                candidates.extend([
                    str(Path(root) / "Windows Kits" / "10" / "Debuggers" / "x64" / "cdb.exe"),
                    str(Path(root) / "Windows Kits" / "10" / "Debuggers" / "x64" / "cdbX64.exe"),
                    str(Path(root) / "Windows Kits" / "10" / "Debuggers" / "x86" / "cdb.exe"),
                    str(Path(root) / "Windows Kits" / "10" / "Debuggers" / "x86" / "cdbX86.exe"),
                ])
        for exe_name in ("cdb.exe", "cdbX64.exe"):
            which = shutil.which(exe_name) if IS_WINDOWS else None
            if which:
                candidates.append(which)
        for c in candidates:
            try:
                if c and Path(c).is_file():
                    return str(Path(c))
            except Exception:
                pass
        return ""

    def analyze_dump_with_cdb(
        self,
        dump: Path,
        progress: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> tuple[str, str, str]:
        """Run CDB with live output, cancellation, heartbeat and AI-friendly per-run logs."""
        cdb = self.find_cdb()
        if not cdb:
            return "", "", ""

        cancel_event = cancel_event or threading.Event()
        timeout_seconds = max(60, int(getattr(self.config, "cdb_timeout_seconds", 600) or 600))
        symbol_cache = DATA_DIR / "symbols"
        symbol_cache.mkdir(parents=True, exist_ok=True)
        sym = f"srv*{symbol_cache}*https://msdl.microsoft.com/download/symbols"

        # Keep the core CDB pass deliberately small. v1.3 used `lm t n`, which printed
        # hundreds of loaded modules, created false-positive candidates and could spend
        # minutes hitting the symbol server. !analyze -v + .bugcheck + kv contains the
        # crash evidence we actually need. Candidate file metadata is collected later.
        commands = (
            ".echo [BSODI_STAGE] SESSION_TIME; "
            ".time; "
            ".echo [BSODI_STAGE] ANALYZE; "
            "!analyze -v; "
            ".echo [BSODI_STAGE] BUGCHECK; "
            ".bugcheck; "
            ".echo [BSODI_STAGE] STACK; "
            "kv; "
            ".echo [BSODI_STAGE] COMPLETE; "
            "q"
        )
        cmd = [cdb, "-z", str(dump), "-y", sym, "-c", commands]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_dump = re.sub(r"[^0-9A-Za-z_.-]+", "_", dump.stem)[:70] or "dump"
        session_id = f"{stamp}_{safe_dump}_{uuid.uuid4().hex[:6]}"
        log_dir = PROBLEM_LOG_DIR / "CDB" / session_id
        log_dir.mkdir(parents=True, exist_ok=True)
        output_path = log_dir / "cdb_live_output.txt"
        status_path = log_dir / "cdb_status.json"
        timing_path = log_dir / "cdb_timing.json"
        command_path = log_dir / "cdb_command.txt"
        ai_path = log_dir / "AI_CDB_CONTEXT.md"

        command_path.write_text(
            "Executable: " + cdb + "\n"
            "Dump: " + str(dump) + "\n"
            "Symbol path: " + sym + "\n"
            "Timeout seconds: " + str(timeout_seconds) + "\n"
            "CDB command script:\n" + commands + "\n\n"
            "Full argv:\n" + subprocess.list2cmdline(cmd) + "\n",
            encoding="utf-8",
        )

        stage_names = {
            "SESSION_TIME": "Чтение времени аварии из dump",
            "ANALYZE": "Глубокий анализ !analyze -v / symbols по требованию",
            "BUGCHECK": "Чтение BugCheck",
            "STACK": "Чтение crash stack",
            "COMPLETE": "Завершение CDB",
        }
        state: dict[str, Any] = {
            "session_id": session_id,
            "state": "starting",
            "stage": "STARTING",
            "stage_display": "Запуск CDB",
            "started_at_utc": utc_now(),
            "pid": None,
            "dump_path": str(dump),
            "cdb_path": cdb,
            "symbol_path": sym,
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": 0,
            "last_output": "",
            "last_output_at_utc": None,
            "last_output_age_seconds": None,
            "exit_code": None,
            "end_reason": None,
            "symbol_warnings": [],
            "warning_count": 0,
            "evidence_fields_seen": [],
            "core_evidence_ready": False,
        }

        def write_status() -> None:
            try:
                tmp = status_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
                os.replace(tmp, status_path)
            except Exception:
                pass

        def emit(kind: str, **payload: Any) -> None:
            event = {"type": kind, "session_id": session_id, "log_dir": str(log_dir), **payload}
            if event_callback:
                try:
                    event_callback(event)
                except Exception:
                    pass

        if progress:
            progress(f"Запускаю CDB: {cdb}")
        emit("starting", stage="STARTING", stage_display="Запуск CDB")
        write_status()

        start_mono = time.monotonic()
        last_output_mono = start_mono
        all_lines: list[str] = []
        proc: subprocess.Popen | None = None
        end_reason = "unknown"
        timed_out = False
        cancelled = False
        current_stage = "STARTING"
        stage_started_mono = start_mono
        stage_timings: list[dict[str, Any]] = []
        last_heartbeat = 0.0

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                bufsize=1,
                creationflags=flags,
            )
            with self._active_cdb_lock:
                self._active_cdb_proc = proc
            state.update({"state": "running", "pid": proc.pid})
            emit("started", pid=proc.pid, stage=current_stage, stage_display="Запуск CDB")
            write_status()

            line_queue: queue.Queue = queue.Queue()
            reader_done = threading.Event()

            def reader() -> None:
                try:
                    if proc and proc.stdout:
                        for line in iter(proc.stdout.readline, ""):
                            if not line:
                                break
                            line_queue.put(line)
                finally:
                    reader_done.set()

            reader_thread = threading.Thread(target=reader, name=f"CDBReader-{proc.pid}", daemon=True)
            reader_thread.start()

            with output_path.open("a", encoding="utf-8", errors="replace") as out_file:
                while True:
                    now = time.monotonic()
                    elapsed = now - start_mono

                    if cancel_event.is_set() and proc.poll() is None:
                        cancelled = True
                        end_reason = "user_cancelled"
                        state.update({"state": "cancelling", "end_reason": end_reason})
                        emit("cancelling", elapsed_seconds=int(elapsed))
                        write_status()
                        try:
                            proc.terminate()
                        except Exception:
                            pass

                    if elapsed >= timeout_seconds and proc.poll() is None:
                        timed_out = True
                        end_reason = "timeout"
                        state.update({"state": "timed_out", "end_reason": end_reason})
                        emit("timeout", elapsed_seconds=int(elapsed), timeout_seconds=timeout_seconds)
                        write_status()
                        try:
                            proc.terminate()
                        except Exception:
                            pass

                    drained = False
                    while True:
                        try:
                            line = line_queue.get_nowait()
                        except queue.Empty:
                            break
                        drained = True
                        all_lines.append(line)
                        out_file.write(line)
                        out_file.flush()
                        text_line = line.rstrip("\r\n")
                        if text_line:
                            last_output_mono = now
                            state["last_output"] = text_line[-1000:]
                            state["last_output_at_utc"] = utc_now()
                            if re.search(r"(?i)(DBGHELP:.*Timeout|SYMSRV:.*(?:error|fail|timeout)|symbol.*(?:error|timeout))", text_line):
                                warnings = state.setdefault("symbol_warnings", [])
                                if text_line not in warnings and len(warnings) < 30:
                                    warnings.append(text_line)
                                    state["warning_count"] = len(warnings)
                                    emit("warning", category="symbols", message=text_line, stage=current_stage, elapsed_seconds=int(elapsed))
                            for field_name in ("BUGCHECK_CODE", "PROCESS_NAME", "IMAGE_NAME", "MODULE_NAME", "SYMBOL_NAME", "FAILURE_BUCKET_ID", "STACK_TEXT"):
                                if re.search(rf"(?i)^\s*{re.escape(field_name)}\s*:", text_line):
                                    seen = state.setdefault("evidence_fields_seen", [])
                                    if field_name not in seen:
                                        seen.append(field_name)
                            seen_set = set(state.get("evidence_fields_seen", []))
                            state["core_evidence_ready"] = bool("BUGCHECK_CODE" in seen_set and ({"IMAGE_NAME", "MODULE_NAME", "FAILURE_BUCKET_ID"} & seen_set))
                            stage_match = re.search(r"\[BSODI_STAGE\]\s*([A-Z_]+)", text_line)
                            if stage_match:
                                new_stage = stage_match.group(1)
                                # CDB may echo a marker more than once. Do not create
                                # duplicate zero-length stages in cdb_timing.json.
                                if new_stage != current_stage:
                                    stage_timings.append({
                                        "stage": current_stage,
                                        "stage_display": state.get("stage_display", current_stage),
                                        "duration_seconds": round(now - stage_started_mono, 3),
                                    })
                                    current_stage = new_stage
                                    stage_started_mono = now
                                    display = stage_names.get(new_stage, new_stage)
                                    state.update({"stage": new_stage, "stage_display": display})
                                    if progress:
                                        progress(display + "…")
                                    emit("stage", stage=new_stage, stage_display=display, elapsed_seconds=int(elapsed))
                            emit("line", line=text_line, stage=current_stage, elapsed_seconds=int(elapsed))

                    if now - last_heartbeat >= 10.0:
                        last_heartbeat = now
                        state["elapsed_seconds"] = int(elapsed)
                        state["last_output_age_seconds"] = int(max(0.0, now - last_output_mono))
                        write_status()
                        emit(
                            "heartbeat",
                            pid=proc.pid,
                            state=state.get("state"),
                            stage=current_stage,
                            stage_display=state.get("stage_display"),
                            elapsed_seconds=int(elapsed),
                            last_output_age_seconds=state["last_output_age_seconds"],
                            last_output=state.get("last_output", ""),
                            core_evidence_ready=state.get("core_evidence_ready", False),
                            evidence_fields_seen=state.get("evidence_fields_seen", []),
                        )

                    rc = proc.poll()
                    if rc is not None and reader_done.is_set() and line_queue.empty():
                        break

                    if (cancelled or timed_out) and proc.poll() is None:
                        # Give CDB a short grace period, then force-kill it.
                        grace_start = time.monotonic()
                        while proc.poll() is None and time.monotonic() - grace_start < 2.0:
                            time.sleep(0.05)
                        if proc.poll() is None:
                            try:
                                proc.kill()
                            except Exception:
                                pass

                    if not drained:
                        time.sleep(0.05)

            rc = proc.wait(timeout=5)
            elapsed = time.monotonic() - start_mono
            stage_timings.append({
                "stage": current_stage,
                "stage_display": state.get("stage_display", current_stage),
                "duration_seconds": round(time.monotonic() - stage_started_mono, 3),
            })
            if cancelled:
                end_reason = "user_cancelled"
                state_name = "cancelled"
            elif timed_out:
                end_reason = "timeout"
                state_name = "timed_out"
            elif rc == 0:
                end_reason = "normal_exit"
                state_name = "completed"
            else:
                end_reason = "cdb_nonzero_exit"
                state_name = "failed"

            state.update({
                "state": state_name,
                "elapsed_seconds": round(elapsed, 3),
                "last_output_age_seconds": round(max(0.0, time.monotonic() - last_output_mono), 3),
                "exit_code": rc,
                "end_reason": end_reason,
                "finished_at_utc": utc_now(),
            })
            write_status()
            timing = {
                "session_id": session_id,
                "started_at_utc": state["started_at_utc"],
                "finished_at_utc": state["finished_at_utc"],
                "elapsed_seconds": state["elapsed_seconds"],
                "end_reason": end_reason,
                "exit_code": rc,
                "stages": stage_timings,
                "symbol_warnings": state.get("symbol_warnings", []),
                "core_evidence_ready": state.get("core_evidence_ready", False),
                "evidence_fields_seen": state.get("evidence_fields_seen", []),
            }
            timing_path.write_text(json.dumps(timing, ensure_ascii=False, indent=2), encoding="utf-8")
            ai_path.write_text(
                "# AI CDB SESSION CONTEXT\n\n"
                f"- App version: `{APP_VERSION}`\n"
                f"- Dump: `{dump}`\n"
                f"- CDB: `{cdb}`\n"
                f"- PID: `{proc.pid}`\n"
                f"- End reason: `{end_reason}`\n"
                f"- Exit code: `{rc}`\n"
                f"- Elapsed: `{state['elapsed_seconds']} s`\n"
                f"- Final stage: `{current_stage}`\n"
                f"- Symbol cache: `{symbol_cache}`\n"
                f"- Symbol warnings: `{len(state.get('symbol_warnings', []))}`\n"
                f"- Core crash evidence ready: `{state.get('core_evidence_ready', False)}`\n"
                f"- Evidence fields seen: `{', '.join(state.get('evidence_fields_seen', []))}`\n\n"
                "## Files\n\n"
                "- `cdb_live_output.txt` — полный stdout/stderr CDB по мере выполнения.\n"
                "- `cdb_status.json` — последнее состояние/heartbeat.\n"
                "- `cdb_timing.json` — длительность стадий.\n"
                "- `cdb_command.txt` — точная команда и symbol path.\n\n"
                "## AI task\n\n"
                "Определи, действительно ли CDB завис, либо долго загружал symbols/выполнял анализ. "
                "Укажи стадию, последний полезный вывод, время без вывода и предложи минимальное улучшение программы/логирования. "
                "Отдельно оцени symbol_warnings. В v1.4 полный `lm t n` намеренно исключён: сам факт загрузки модуля не является доказательством виновности.\n",
                encoding="utf-8",
            )
            emit("finished", state=state_name, end_reason=end_reason, exit_code=rc,
                 elapsed_seconds=state["elapsed_seconds"], stage=current_stage, log_dir=str(log_dir))

            if cancelled:
                raise AnalysisCancelledError(f"Анализ отменён пользователем. CDB-лог: {log_dir}")
            if timed_out:
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout_seconds, output="".join(all_lines))
            if rc != 0 and not all_lines:
                raise RuntimeError(f"CDB завершился с кодом {rc}. Лог: {log_dir}")
            return "".join(all_lines), cdb, str(log_dir)
        except Exception:
            # Preserve useful state even if Popen/read itself fails.
            elapsed = round(time.monotonic() - start_mono, 3)
            if state.get("state") not in {"cancelled", "timed_out", "completed", "failed"}:
                state.update({
                    "state": "failed",
                    "elapsed_seconds": elapsed,
                    "end_reason": end_reason if end_reason != "unknown" else "exception",
                    "finished_at_utc": utc_now(),
                    "exit_code": proc.poll() if proc else None,
                })
                write_status()
            if not ai_path.exists():
                try:
                    ai_path.write_text(
                        "# AI CDB SESSION CONTEXT\n\n"
                        f"CDB session failed before normal completion.\n\nLog directory: `{log_dir}`\n",
                        encoding="utf-8",
                    )
                except Exception:
                    pass
            raise
        finally:
            with self._active_cdb_lock:
                if self._active_cdb_proc is proc:
                    self._active_cdb_proc = None

    def running_drivers(self) -> list[DriverInfo]:
        if not IS_WINDOWS:
            return []
        script = r'''
$ErrorActionPreference='SilentlyContinue'
$items = Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | ForEach-Object {
  $raw = [string]$_.PathName
  $path = $raw.Trim('"')
  if ($path -match '^\\SystemRoot\\') { $path = $path -replace '^\\SystemRoot', $env:SystemRoot }
  elseif ($path -match '^System32\\') { $path = Join-Path $env:SystemRoot $path }
  $company=''; $version=''; $signed=$null; $signer=''; $modified=''; $product=''; $description=''; $original=''
  if (Test-Path -LiteralPath $path) {
    $f=Get-Item -LiteralPath $path
    $company=[string]$f.VersionInfo.CompanyName
    $version=[string]$f.VersionInfo.FileVersion
    $product=[string]$f.VersionInfo.ProductName
    $description=[string]$f.VersionInfo.FileDescription
    $original=[string]$f.VersionInfo.OriginalFilename
    $modified=$f.LastWriteTimeUtc.ToString('o')
    $sig=Get-AuthenticodeSignature -LiteralPath $path
    $signed=($sig.Status -eq 'Valid')
    if ($sig.SignerCertificate) { $signer=[string]$sig.SignerCertificate.Subject }
  }
  [PSCustomObject]@{
    name=[string]$_.Name; path=$path; company=$company; version=$version; signed=$signed;
    signer=$signer; start_mode=[string]$_.StartMode; state=[string]$_.State; modified_utc=$modified;
    product=$product; description=$description; original_filename=$original; provider=''; inf_name=''; device_name=''
  }
}
$items | ConvertTo-Json -Compress -Depth 4
'''
        try:
            out = self.powershell(script, timeout=120)
            if not out:
                return []
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return [DriverInfo(**{k: x.get(k) for k in DriverInfo.__annotations__}) for x in data]
        except Exception:
            return []

    def driver_inventory_map(self) -> dict[str, DriverInfo]:
        return {d.filename: d for d in self.running_drivers() if d.filename}

    def inspect_driver_files(self, names: Iterable[str]) -> dict[str, DriverInfo]:
        """Inspect only evidence-backed candidate drivers and enrich missing PE metadata.

        Some third-party .sys files expose little or no VersionInfo. In that case v1.6
        searches the installed OEM INF package and Win32_PnPSignedDriver so reports can
        still show provider, package version, INF and related device without treating a
        Microsoft WHQL signer as the driver vendor.
        """
        wanted = sorted({Path(str(n)).name.lower() for n in names if str(n).lower().endswith('.sys')})[:24]
        if not IS_WINDOWS or not wanted:
            return {}
        arr = ",".join("'" + n.replace("'", "''") + "'" for n in wanted)
        script = rf'''
$ErrorActionPreference='SilentlyContinue'
$names=@({arr})
$services=Get-CimInstance Win32_SystemDriver
$pnpDrivers=@(Get-CimInstance Win32_PnPSignedDriver)
$infFiles=@(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'INF') -Filter 'oem*.inf' -File -ErrorAction SilentlyContinue)
$result=@()

foreach($name in $names) {{
  $svc=$null; $path=''
  foreach($s in $services) {{
    $raw=[string]$s.PathName
    $candidate=$raw.Trim('"')
    if($candidate -match '^\\SystemRoot\\') {{ $candidate=$candidate -replace '^\\SystemRoot',$env:SystemRoot }}
    elseif($candidate -match '^System32\\') {{ $candidate=Join-Path $env:SystemRoot $candidate }}
    try {{ if([IO.Path]::GetFileName($candidate) -ieq $name) {{ $svc=$s; $path=$candidate; break }} }} catch {{}}
  }}
  if(-not $path) {{ $path=Join-Path $env:SystemRoot ('System32\\drivers\\'+$name) }}

  $company=''; $version=''; $signed=$null; $signer=''; $modified=''
  $product=''; $description=''; $original=''; $provider=''; $infName=''; $deviceName=''
  if(Test-Path -LiteralPath $path) {{
    $f=Get-Item -LiteralPath $path
    $company=[string]$f.VersionInfo.CompanyName
    $version=[string]$f.VersionInfo.FileVersion
    $product=[string]$f.VersionInfo.ProductName
    $description=[string]$f.VersionInfo.FileDescription
    $original=[string]$f.VersionInfo.OriginalFilename
    $modified=$f.LastWriteTimeUtc.ToString('o')
    $sig=Get-AuthenticodeSignature -LiteralPath $path
    $signed=($sig.Status -eq 'Valid')
    if($sig.SignerCertificate) {{ $signer=[string]$sig.SignerCertificate.Subject }}
  }}

  if(-not $company -or -not $version -or -not $product -or -not $description) {{
    foreach($inf in $infFiles) {{
      try {{
        if(Select-String -LiteralPath $inf.FullName -Pattern $name -SimpleMatch -Quiet) {{
          $infName=[string]$inf.Name
          break
        }}
      }} catch {{}}
    }}
  }}

  if($infName) {{
    $pnp=$pnpDrivers | Where-Object {{ [string]$_.InfName -ieq $infName }} | Select-Object -First 1
    if($pnp) {{
      $provider=[string]$pnp.DriverProviderName
      if(-not $provider) {{ $provider=[string]$pnp.Manufacturer }}
      if(-not $version) {{ $version=[string]$pnp.DriverVersion }}
      $deviceName=[string]$pnp.DeviceName
      if(-not $product) {{ $product=$deviceName }}
      if(-not $description) {{ $description=$deviceName }}
      if(-not $company) {{ $company=$provider }}
      if($null -eq $signed -and $null -ne $pnp.IsSigned) {{ $signed=[bool]$pnp.IsSigned }}
    }}
    if(-not $provider -or -not $version) {{
      try {{
        $wd=Get-WindowsDriver -Online -Driver $infName -ErrorAction SilentlyContinue
        if($wd) {{
          if(-not $provider) {{ $provider=[string]$wd.ProviderName }}
          if(-not $version) {{ $version=[string]$wd.Version }}
          if(-not $company) {{ $company=$provider }}
        }}
      }} catch {{}}
    }}
  }}

  $svcName=if($svc){{[string]$svc.Name}}else{{$name}}
  $startMode=if($svc){{[string]$svc.StartMode}}else{{''}}
  $svcState=if($svc){{[string]$svc.State}}else{{''}}
  if(-not $description -and $svc) {{ $description=[string]$svc.DisplayName }}

  $result += [PSCustomObject]@{{
    name=$svcName; path=$path; company=$company; version=$version; signed=$signed;
    signer=$signer; start_mode=$startMode; state=$svcState; modified_utc=$modified;
    product=$product; description=$description; original_filename=$original;
    provider=$provider; inf_name=$infName; device_name=$deviceName
  }}
}}
$result | ConvertTo-Json -Compress -Depth 5
'''
        try:
            out = self.powershell(script, timeout=120)
            if not out:
                return {}
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            result: dict[str, DriverInfo] = {}
            for x in data:
                info = DriverInfo(**{k: x.get(k) for k in DriverInfo.__annotations__})
                if info.filename:
                    result[info.filename] = info
            return result
        except Exception:
            return {}
    def events_between(self, start_utc: dt.datetime, end_utc: dt.datetime, limit: int = 500) -> list[dict[str, Any]]:
        """Query focused Windows events for an exact historical crash window."""
        if not IS_WINDOWS:
            return []
        start_utc = start_utc.astimezone(dt.timezone.utc)
        end_utc = end_utc.astimezone(dt.timezone.utc)
        start_iso = start_utc.isoformat().replace('+00:00', 'Z')
        end_iso = end_utc.isoformat().replace('+00:00', 'Z')
        script = rf'''
$start=[DateTime]::Parse({_ps_quote(start_iso)}).ToLocalTime()
$end=[DateTime]::Parse({_ps_quote(end_iso)}).ToLocalTime()
$providers=@('Microsoft-Windows-WER-SystemErrorReporting','volmgr','Microsoft-Windows-Kernel-Power','Microsoft-Windows-WHEA-Logger','Display','Microsoft-Windows-DriverFrameworks-UserMode')
$scmIds=@(7000,7001,7009,7011,7023,7024,7031,7034)
$events=Get-WinEvent -FilterHashtable @{{LogName='System'; StartTime=$start; EndTime=$end}} -ErrorAction SilentlyContinue |
  Where-Object {{ $_.ProviderName -in $providers -or ($_.ProviderName -eq 'Service Control Manager' -and $_.Id -in $scmIds) -or $_.Id -in 41,1001,161,162,219,4101 }} |
  Select-Object -First {int(limit)} @{{n='TimeCreated';e={{$_.TimeCreated.ToUniversalTime().ToString('o')}}}},RecordId,ProviderName,Id,LevelDisplayName,Message
$events | ConvertTo-Json -Compress -Depth 4
'''
        try:
            out = self.powershell(script, timeout=90)
            if not out:
                return []
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return normalize_windows_events(data)
        except Exception:
            return []

    def recent_events(self, minutes: int = 15) -> list[dict[str, Any]]:
        if not IS_WINDOWS:
            return []
        ms = max(1, minutes) * 60 * 1000
        # Keep this deliberately focused: crash/dump/hardware/driver/service/display signals.
        script = rf'''
$start=(Get-Date).AddMilliseconds(-{ms})
$providers=@('Microsoft-Windows-WER-SystemErrorReporting','volmgr','Microsoft-Windows-Kernel-Power','Microsoft-Windows-WHEA-Logger','Display','Microsoft-Windows-DriverFrameworks-UserMode')
$scmIds=@(7000,7001,7009,7011,7023,7024,7031,7034)
$events=Get-WinEvent -FilterHashtable @{{LogName='System'; StartTime=$start}} -ErrorAction SilentlyContinue |
  Where-Object {{ $_.ProviderName -in $providers -or ($_.ProviderName -eq 'Service Control Manager' -and $_.Id -in $scmIds) -or $_.Id -in 41,1001,161,162,219,4101 }} |
  Select-Object -First 300 @{{n='TimeCreated';e={{$_.TimeCreated.ToUniversalTime().ToString('o')}}}},RecordId,ProviderName,Id,LevelDisplayName,Message
$events | ConvertTo-Json -Compress -Depth 4
'''
        try:
            out = self.powershell(script, timeout=90)
            if not out:
                return []
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return normalize_windows_events(data)
        except Exception:
            return []

    def processes_snapshot(self) -> list[dict[str, str]]:
        if not IS_WINDOWS:
            return []
        script = r'''
Get-Process -ErrorAction SilentlyContinue | Select-Object -First 500 Name,Id,@{n='Path';e={$_.Path}} | ConvertTo-Json -Compress -Depth 3
'''
        try:
            out = self.powershell(script, timeout=45)
            data = json.loads(out) if out else []
            if isinstance(data, dict): data=[data]
            return [{"name": str(x.get("Name","")), "pid": str(x.get("Id","")), "path": str(x.get("Path","") or "")} for x in data]
        except Exception:
            return []

    def dump_readiness(self) -> dict[str, Any]:
        if not IS_WINDOWS:
            return {}
        script = r'''
$cc='HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$c=Get-ItemProperty -Path $cc -ErrorAction SilentlyContinue
$page=Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage
[PSCustomObject]@{
  CrashDumpEnabled=$c.CrashDumpEnabled
  MinidumpDir=[string]$c.MinidumpDir
  DumpFile=[string]$c.DumpFile
  AutoReboot=$c.AutoReboot
  AlwaysKeepMemoryDump=$c.AlwaysKeepMemoryDump
  PageFiles=$page
} | ConvertTo-Json -Compress -Depth 5
'''
        try:
            out = self.powershell(script)
            return json.loads(out) if out else {}
        except Exception:
            return {}

    def collect_support_commands(self) -> dict[str, str]:
        result: dict[str, str] = {}
        if not IS_WINDOWS:
            return result
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        commands = {
            "systeminfo.txt": ["systeminfo"],
            "driverquery.csv": ["driverquery", "/v", "/fo", "csv"],
            "pnputil.txt": ["pnputil", "/enum-drivers"],
            "verifier_status.txt": ["verifier", "/querysettings"],
        }
        for name, cmd in commands.items():
            try:
                cp = self.run(cmd, timeout=90, creationflags=flags)
                result[name] = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
            except Exception as e:
                result[name] = f"ERROR: {e}"
        try:
            result["dump_readiness.json"] = json.dumps(self.dump_readiness(), ensure_ascii=False, indent=2)
        except Exception as e:
            result["dump_readiness.json"] = f'{{"error": {json.dumps(str(e))}}}'
        try:
            result["running_drivers.json"] = json.dumps([asdict(x) for x in self.running_drivers()], ensure_ascii=False, indent=2)
        except Exception as e:
            result["running_drivers.json"] = f'{{"error": {json.dumps(str(e))}}}'
        return result


class ProblemLogger:
    """AI-friendly diagnostics for application failures and Windows crash investigations."""

    def __init__(self, config: Config, tools: WindowsTools, db: HistoryDB | None = None):
        self.config = config
        self.tools = tools
        self.db = db
        self.root = PROBLEM_LOG_DIR
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.session_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
        self.activity_jsonl = self.root / "00_activity.jsonl"
        self.activity_txt = self.root / "00_activity.log"
        self._last_risk_fingerprint = ""
        self._write_root_docs()
        self.activity("INFO", "startup", f"Запущен {APP_NAME} {APP_VERSION}", {
            "session_id": self.session_id,
            "admin": self._safe_is_admin(),
            "problem_log_dir": str(self.root),
            "cdb_path": self.tools.find_cdb(),
        })

    def _safe_is_admin(self) -> bool:
        try:
            return is_admin()
        except Exception:
            return False

    @staticmethod
    def _safe_name(value: str, max_len: int = 80) -> str:
        value = re.sub(r"[^0-9A-Za-zА-Яа-яЁё_.-]+", "_", value or "event").strip("_.")
        return (value or "event")[:max_len]

    def _write_root_docs(self) -> None:
        guide = self.root / "КАК_ПЕРЕДАТЬ_ЛОГИ_НЕЙРОСЕТИ.md"
        schema = self.root / "AI_LOG_SCHEMA.md"
        guide_text = f"""# Логи проблем — {APP_NAME}

Эта папка создана программой автоматически. Она предназначена для диагностики двух разных классов проблем:

1. **Ошибки самой программы** — папка `Ошибки программы`.
2. **Падения Windows / BSOD** — папка `Падения Windows`.
3. **Ручные диагностические снимки** — папка `Диагностика`.
4. **Сеансы CDB** — папка `CDB`: live stdout/stderr, heartbeat, стадия, PID, timeout/cancel и точная команда.

## Что отправлять нейросети

Лучший вариант — нажать в программе **«Собрать ZIP логов для нейросети»** и загрузить полученный ZIP.
Если ZIP не нужен, можно отправить последнюю папку события целиком. Главный файл внутри — `AI_CONTEXT.md` или `AI_CRASH_ANALYSIS.md`.

## Что должна сделать нейросеть

Нейросеть должна:

- определить наиболее вероятную причину ошибки программы или BSOD;
- отделять **прямые доказательства** от эвристик и совпадений;
- назвать уровень уверенности и альтернативные гипотезы;
- предложить конкретный патч к программе, если проблема в коде;
- указать, каких данных не хватает для уверенного вывода;
- предложить, **какие дополнительные логи стоит собирать в будущих версиях**;
- проверить, не обвиняет ли алгоритм системный модуль Windows, который лишь обнаружил повреждение памяти;
- при анализе BSOD учитывать CDB/WinDbg, события Windows, историю **уникальных** повторений и pre-crash ring-buffer вместе, а не по одному полю;
- использовать `crash_fingerprint`, чтобы MEMORY.DMP и Minidump одного события не считались разными падениями;
- разделять Event Log на PRE_CRASH / CRASH_WINDOW / REBOOT_DUMP / POST_CRASH и не принимать последствия перезагрузки за причину;
- проверять `dump_health.json` (volmgr 161/162 + WER) отдельно от поиска виновника;
- не считать драйвер виновником только потому, что он был загружен в момент dump;
- не путать Microsoft/WHQL-подпись стороннего драйвера с Microsoft-производителем бинарного файла.

## Конфиденциальность

Логи содержат технические пути, имена драйверов, процессов, версии Windows и иногда имя профиля Windows в путях. Сам `.dmp` в эту папку автоматически не копируется. Crash dump может содержать фрагменты памяти — перед отправкой сторонним лицам проверяйте его отдельно.

Версия программы: **{APP_VERSION}**  
Версия схемы логов: **{AI_LOG_SCHEMA_VERSION}**  
Версия модели оценки виновников: **{SCORING_MODEL_VERSION}**
"""
        schema_text = f"""# AI Log Schema {AI_LOG_SCHEMA_VERSION}

Каждое событие имеет машиночитаемый JSON и человекочитаемый Markdown.

## Обязательные смысловые блоки

- `identity` — версия программы, schema/model version, ID события.
- `problem` — стадия, наблюдаемое поведение, исключение/тип сбоя.
- `environment` — Windows/Python/права/CDB/пути данных.
- `evidence` — только факты, собранные программой.
- `hypotheses` — предположения программы, которые нельзя считать доказательством.
- `telemetry_quality` — какие сигналы есть, каких не хватает, какие сборщики дали ошибку.
- `ai_task` — что нейросеть должна проверить и как улучшить программу/логи.

## Правило для BSOD

Поле `top_suspect` — это **кандидат**, а не юридически точный виновник. Нейросеть должна сверять его с `FAULTING_MODULE`, `IMAGE_NAME`, `MODULE_NAME`, `SYMBOL_NAME`, `Probably caused by`, непосредственным crash stack, `FAILURE_BUCKET_ID`, метаданными производителя, повторяемостью уникальных `crash_fingerprint`, `event_timeline.json`, `dump_health.json` и `precrash_timeline.json`. Само присутствие в списке загруженных модулей не является crash evidence. Microsoft/WHQL signer не равен Microsoft vendor.

Scoring model: `{SCORING_MODEL_VERSION}`. Актуальные веса сохраняются в `scoring_model.json` рядом с каждым BSOD-логом.
"""
        for path, text in ((guide, guide_text), (schema, schema_text)):
            try:
                if not path.exists() or path.read_text(encoding="utf-8", errors="ignore") != text:
                    path.write_text(text, encoding="utf-8")
            except Exception:
                pass

    def activity(self, level: str, category: str, message: str, context: dict[str, Any] | None = None) -> None:
        entry = {
            "time_utc": utc_now(),
            "session_id": self.session_id,
            "app_version": APP_VERSION,
            "level": level,
            "category": category,
            "message": message,
            "context": context or {},
        }
        line_json = json.dumps(entry, ensure_ascii=False, default=str)
        line_txt = f"{entry['time_utc']} [{level}] [{category}] {message}"
        if context:
            line_txt += " | " + json.dumps(context, ensure_ascii=False, default=str)
        with self._lock:
            try:
                with self.activity_jsonl.open("a", encoding="utf-8") as f:
                    f.write(line_json + "\n")
            except Exception:
                pass
            try:
                with self.activity_txt.open("a", encoding="utf-8") as f:
                    f.write(line_txt + "\n")
            except Exception:
                pass

    def _environment(self) -> dict[str, Any]:
        return {
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "ai_log_schema_version": AI_LOG_SCHEMA_VERSION,
            "scoring_model_version": SCORING_MODEL_VERSION,
            "session_id": self.session_id,
            "time_utc": utc_now(),
            "time_local": dt.datetime.now().astimezone().isoformat(),
            "is_windows": IS_WINDOWS,
            "windows_version": platform.platform(),
            "python_version": sys.version,
            "python_executable": sys.executable,
            "frozen_exe": bool(getattr(sys, "frozen", False)),
            "is_admin": self._safe_is_admin(),
            "app_dir": str(APP_DIR),
            "data_dir": str(DATA_DIR),
            "problem_log_dir": str(self.root),
            "cdb_detected": self.tools.find_cdb(),
        }

    def _config_snapshot(self) -> dict[str, Any]:
        d = asdict(self.config)
        # No secrets are stored today, but keep this explicit if config grows later.
        return d

    def _dump_diagnostics(self, dump_path: str | Path | None) -> dict[str, Any]:
        if not dump_path:
            return {}
        p = Path(dump_path)
        out: dict[str, Any] = {"path": str(p), "exists": False, "read_test": False}
        try:
            out["exists"] = p.exists()
            if p.exists():
                st = p.stat()
                out.update({
                    "size_bytes": st.st_size,
                    "modified_utc": dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(),
                    "os_access_read": os.access(p, os.R_OK),
                })
                try:
                    with p.open("rb") as f:
                        out["first_16_bytes_hex"] = f.read(16).hex()
                    out["read_test"] = True
                except Exception as e:
                    out["read_error"] = {"type": type(e).__name__, "message": str(e)}
        except Exception as e:
            out["metadata_error"] = {"type": type(e).__name__, "message": str(e)}
        if IS_WINDOWS and p.exists():
            try:
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                cp = subprocess.run(["icacls", str(p)], capture_output=True, text=True, errors="replace",
                                    timeout=15, creationflags=flags)
                out["acl"] = (cp.stdout or cp.stderr or "").strip()[:12000]
            except Exception as e:
                out["acl_error"] = str(e)
        return out

    def _latest_cdb_session(self) -> dict[str, Any]:
        """Return a compact snapshot of the newest CDB session for AI diagnostics."""
        base = self.root / "CDB"
        if not base.exists():
            return {}
        try:
            folders = sorted((x for x in base.iterdir() if x.is_dir()), key=lambda x: x.stat().st_mtime, reverse=True)
        except Exception:
            return {}
        if not folders:
            return {}
        folder = folders[0]
        out: dict[str, Any] = {"folder": str(folder)}
        for name in ("cdb_status.json", "cdb_timing.json"):
            fp = folder / name
            if fp.exists():
                try:
                    out[name] = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                except Exception as e:
                    out[name + "_error"] = str(e)
        live = folder / "cdb_live_output.txt"
        if live.exists():
            try:
                text = live.read_text(encoding="utf-8", errors="replace")
                out["live_output_tail"] = text[-12000:]
                out["live_output_size_bytes"] = live.stat().st_size
            except Exception as e:
                out["live_output_error"] = str(e)
        return out

    @staticmethod
    def _exception_hints(exc: BaseException) -> tuple[list[str], list[str]]:
        hypotheses: list[str] = []
        actions: list[str] = []
        if isinstance(exc, PermissionError):
            hypotheses.append("Недостаточно прав процесса для чтения защищённого системного crash dump или другого файла Windows.")
            actions.extend([
                "Проверить, запущена ли программа с правами администратора.",
                "Не менять ACL системной папки Minidump без необходимости; безопаснее запускать анализатор elevated.",
                "Проверить, доступен ли файл после UAC-перезапуска и может ли CDB открыть его.",
            ])
        elif isinstance(exc, FileNotFoundError):
            hypotheses.append("Ожидаемый файл или внешний инструмент отсутствует/перемещён.")
            actions.append("Проверить путь, наличие CDB и существование dump-файла перед запуском анализа.")
        elif isinstance(exc, subprocess.TimeoutExpired):
            hypotheses.append("Внешний диагностический процесс завис или слишком долго загружал symbols.")
            actions.extend(["Логировать stdout/stderr процесса до таймаута.", "Разделить timeout для загрузки symbols и анализа dump."])
        else:
            hypotheses.append("Причину необходимо вывести из traceback, контекста действия и диагностических файлов.")
        return hypotheses, actions

    @staticmethod
    def _source_excerpt(exc: BaseException, radius: int = 12) -> str:
        chunks: list[str] = []
        try:
            frames = traceback.extract_tb(exc.__traceback__)
            seen: set[tuple[str, int]] = set()
            for frame in frames[-8:]:
                key = (frame.filename, frame.lineno)
                if key in seen:
                    continue
                seen.add(key)
                fp = Path(frame.filename)
                if not fp.exists() or not fp.is_file():
                    continue
                try:
                    lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
                except Exception:
                    continue
                start = max(1, frame.lineno - radius)
                end = min(len(lines), frame.lineno + radius)
                chunks.append(f"FILE: {fp}\nFUNCTION: {frame.name}\nERROR_LINE: {frame.lineno}\n")
                for lineno in range(start, end + 1):
                    prefix = ">>>" if lineno == frame.lineno else "   "
                    chunks.append(f"{prefix} {lineno:5d}: {lines[lineno-1]}\n")
                chunks.append("\n")
        except Exception:
            return ""
        return "".join(chunks)

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    def _write_manifest(self, folder: Path) -> None:
        files = []
        for f in sorted(folder.iterdir(), key=lambda x: x.name.lower()):
            if not f.is_file() or f.name == "MANIFEST.json":
                continue
            item: dict[str, Any] = {"name": f.name, "size_bytes": f.stat().st_size}
            try:
                item["sha256"] = sha256_file(f)
            except Exception:
                item["sha256"] = ""
            files.append(item)
        self._write_json(folder / "MANIFEST.json", {
            "schema_version": AI_LOG_SCHEMA_VERSION,
            "generated_at": utc_now(),
            "files": files,
        })

    def capture_exception(self, exc: BaseException, stage: str,
                          context: dict[str, Any] | None = None,
                          severity: str = "error") -> Path:
        context = dict(context or {})
        event_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
        folder = self.root / "Ошибки программы" / f"{event_id}_{self._safe_name(stage)}"
        folder.mkdir(parents=True, exist_ok=True)
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        hypotheses, corrective_actions = self._exception_hints(exc)
        dump_path = context.get("dump_path")
        diagnostics: dict[str, Any] = {
            "dump_access": self._dump_diagnostics(dump_path),
            "cdb_path": self.tools.find_cdb(),
            "latest_cdb_session": self._latest_cdb_session(),
        }
        try:
            diagnostics["dump_readiness"] = self.tools.dump_readiness()
        except Exception as e:
            diagnostics["dump_readiness_error"] = str(e)
        try:
            diagnostics["recent_windows_events"] = self.tools.recent_events(minutes=15)[:100]
        except Exception as e:
            diagnostics["recent_windows_events_error"] = str(e)

        payload = {
            "identity": {
                "event_id": event_id,
                "kind": "application_problem",
                "schema_version": AI_LOG_SCHEMA_VERSION,
                "app_version": APP_VERSION,
                "scoring_model_version": SCORING_MODEL_VERSION,
            },
            "problem": {
                "severity": severity,
                "stage": stage,
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
                "traceback": tb,
                "context": context,
            },
            "environment": self._environment(),
            "configuration": self._config_snapshot(),
            "evidence": diagnostics,
            "hypotheses": hypotheses,
            "corrective_actions_to_validate": corrective_actions,
            "telemetry_quality": {
                "present": ["full_traceback", "source_excerpt", "environment", "config", "CDB_detection", "dump_access_test", "recent_Windows_events", "latest_CDB_session_heartbeat_and_output_tail"],
                "potentially_missing": ["screen_recording", "kernel_state_if_dump_is_unreadable", "network_packet_trace_if_symbol_server_is_unreachable"],
                "instruction": "Предложи дополнительные поля логирования только если они реально повышают диагностическую ценность.",
            },
            "ai_task": [
                "Определи непосредственную причину ошибки программы и корневую причину, если они отличаются.",
                "Укажи точный файл/функцию/строку кода, требующую изменения.",
                "Предложи минимальный безопасный патч и отдельно архитектурное улучшение, если оно нужно.",
                "Проверь, можно ли было обработать ошибку без падения пользовательского сценария.",
                "Оцени качество этого лога: какие данные лишние, какие отсутствуют, какие поля нужно добавить в следующую версию.",
                "Если проблема связана с анализом BSOD, не делай вывод о виновном драйвере без dump/WinDbg evidence.",
            ],
        }
        self._write_json(folder / "problem.json", payload)
        (folder / "traceback.txt").write_text(tb, encoding="utf-8", errors="replace")
        excerpt = self._source_excerpt(exc)
        (folder / "source_excerpt.txt").write_text(excerpt or "Source excerpt unavailable.", encoding="utf-8")
        try:
            source = Path(__file__).resolve()
            if source.exists():
                shutil.copy2(source, folder / "program_source_snapshot.py")
        except Exception:
            pass
        md = self._exception_markdown(payload)
        (folder / "AI_CONTEXT.md").write_text(md, encoding="utf-8")
        self._write_manifest(folder)
        self.activity("ERROR", stage, str(exc), {"event_folder": str(folder), **context})
        return folder

    def _exception_markdown(self, payload: dict[str, Any]) -> str:
        p = payload["problem"]
        env = payload["environment"]
        evidence = payload["evidence"]
        hyp = "\n".join(f"- {x}" for x in payload["hypotheses"])
        acts = "\n".join(f"- {x}" for x in payload["corrective_actions_to_validate"]) or "- Нет заранее заданных действий; вывести из traceback."
        ai = "\n".join(f"{i+1}. {x}" for i, x in enumerate(payload["ai_task"]))
        dump_diag = json.dumps(evidence.get("dump_access", {}), ensure_ascii=False, indent=2, default=str)
        return f"""# AI CONTEXT — ошибка BSOD Investigator

## Кратко

- **Версия:** {APP_VERSION}
- **Стадия:** `{p['stage']}`
- **Исключение:** `{p['exception_type']}`
- **Сообщение:** `{p['exception_message']}`
- **Администратор:** {env['is_admin']}
- **CDB:** `{env['cdb_detected'] or 'НЕ НАЙДЕН'}`

## Контекст действия

```json
{json.dumps(p.get('context', {}), ensure_ascii=False, indent=2, default=str)}
```

## Прямые факты

Полный traceback находится в `traceback.txt`, а участок исходного кода — в `source_excerpt.txt`. Снимок текущего исходника — `program_source_snapshot.py`.

### Диагностика доступа к dump

```json
{dump_diag}
```

## Рабочие гипотезы программы — НЕ считать доказательством

{hyp}

## Действия, которые стоит проверить

{acts}

## Задание нейросети

{ai}

## Как улучшить логирование

Проверь `problem.json` и `MANIFEST.json`. Отдельно перечисли:

- какие поля помогли установить причину;
- какие поля не дали пользы;
- каких данных не хватило;
- какие новые логи стоит добавить **до следующего воспроизведения проблемы**;
- как сделать лог компактнее, не потеряв диагностическую ценность.
"""

    def _crash_quality(self, report: CrashReport) -> dict[str, Any]:
        return telemetry_quality(report)

    def capture_crash_report(self, report: CrashReport) -> Path:
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        top = report.suspects[0] if report.suspects else None
        suffix = self._safe_name(f"{Path(report.dump_name).stem}_0x{report.bugcheck_code or 'unknown'}")
        folder = self.root / "Падения Windows" / f"{stamp}_{suffix}"
        folder.mkdir(parents=True, exist_ok=True)
        quality = self._crash_quality(report)
        crash_payload = report.to_dict()
        envelope = {
            "identity": {
                "kind": "windows_crash_analysis",
                "schema_version": AI_LOG_SCHEMA_VERSION,
                "app_version": APP_VERSION,
                "scoring_model_version": SCORING_MODEL_VERSION,
                "generated_at": utc_now(),
            },
            "top_suspect": asdict(top) if top else None,
            "crash_report": crash_payload,
            "telemetry_quality": quality,
            "history_repair": self.db.last_repair_stats if self.db else {},
            "important_rule": "top_suspect is a hypothesis. Validate against raw debugger evidence and alternative causes.",
        }
        self._write_json(folder / "crash_report.json", envelope)
        self._write_json(folder / "scoring_model.json", {
            "version": SCORING_MODEL_VERSION,
            "rules": SCORING_RULES,
            "meaning": "Positive points raise a driver's priority; penalties lower it. Confidence is a nonlinear transformation of total score.",
        })
        self._write_json(folder / "events_near_crash.json", report.nearby_events)
        self._write_json(folder / "event_timeline.json", report.event_timeline)
        self._write_json(folder / "dump_health.json", report.dump_health)
        self._write_json(folder / "precrash_snapshot.json", report.precrash_snapshot)
        self._write_json(folder / "precrash_timeline.json", report.precrash_timeline)
        self._write_json(folder / "history_repair.json", self.db.last_repair_stats if self.db else {})
        (folder / "debugger_raw.txt").write_text(report.raw_debugger_output or "Debugger output unavailable.", encoding="utf-8", errors="replace")
        if report.debugger_session_log:
            try:
                src = Path(report.debugger_session_log)
                if src.exists() and src.is_dir():
                    shutil.copytree(src, folder / "CDB_session", dirs_exist_ok=True)
            except Exception as e:
                (folder / "cdb_session_copy_error.txt").write_text(str(e), encoding="utf-8")
        (folder / "AI_CRASH_ANALYSIS.md").write_text(self._crash_markdown(report, quality), encoding="utf-8")
        try:
            source = Path(__file__).resolve()
            if source.exists():
                shutil.copy2(source, folder / "program_source_snapshot.py")
        except Exception:
            pass
        self._write_manifest(folder)
        self.activity("INFO", "windows_crash_analysis", f"Сохранён AI-лог падения {report.dump_name}", {
            "folder": str(folder), "top_suspect": top.driver if top else "", "confidence": top.confidence if top else 0,
        })
        return folder

    def _crash_markdown(self, report: CrashReport, quality: dict[str, Any]) -> str:
        top = report.suspects[0] if report.suspects else None
        candidates = []
        for i, s in enumerate(report.suspects[:8], 1):
            candidates.append(f"### {i}. `{s.driver}` — {s.confidence}% / {s.level} / score {s.score} / strong evidence {s.strong_evidence_count}\n")
            candidates.extend(f"- {e}\n" for e in s.evidence)
            if s.company:
                candidates.append(f"- Компания: {s.company}\n")
            if s.product:
                candidates.append(f"- Продукт: {s.product}\n")
            if s.version:
                candidates.append(f"- Версия: {s.version}\n")
            if s.provider:
                candidates.append(f"- Provider пакета: {s.provider}\n")
            if s.inf_name:
                candidates.append(f"- INF: {s.inf_name}\n")
            if s.device_name:
                candidates.append(f"- Связанное устройство: {s.device_name}\n")
            if s.signer:
                candidates.append(f"- Подписант: {s.signer}\n")
            if s.vendor_type:
                candidates.append(f"- Классификация vendor: {s.vendor_type}\n")
        if not candidates:
            candidates = ["Конкретный сторонний драйвер не выделен.\n"]
        present = "\n".join(f"- ✅ {x}" for x in quality["present_signals"])
        missing = "\n".join(f"- ❌ {x}" for x in quality["missing_signals"]) or "- Нет очевидных пробелов"
        return f"""# AI CRASH ANALYSIS — Windows BSOD

## Главный вывод программы

- **Dump:** `{report.dump_name}` / `{report.dump_kind}` / `{report.dump_size_bytes}` bytes
- **Crash time UTC:** `{report.crash_time_utc or '—'}`
- **Debug session time raw:** `{report.debug_session_time_raw or '—'}`
- **BugCheck:** `0x{report.bugcheck_code or '?'} {report.bugcheck_name}`
- **Exception:** `{report.exception_code or '—'}`
- **Process:** `{report.process_name or '—'}`
- **FAULTING_MODULE:** `{report.faulting_module or '—'}`
- **IMAGE_NAME:** `{report.image_name or '—'}`
- **MODULE_NAME:** `{report.module_name or '—'}`
- **FAILURE_BUCKET_ID:** `{report.failure_bucket_id or '—'}`
- **FAILURE_ID_HASH:** `{report.failure_id_hash or '—'}`
- **Crash fingerprint:** `{report.crash_fingerprint or '—'}`
- **BugCheck parameters:** `{', '.join(report.bugcheck_parameters) or '—'}`
- **WER driver correlations:** `{', '.join(report.wer_driver_correlations) or '—'}`
- **Dump Health:** `{(report.dump_health or {}).get('status','unknown')} — {(report.dump_health or {}).get('summary','')}`
- **Pre-crash ring snapshots:** `{len(report.precrash_timeline)}`
- **Probably caused by:** `{report.probable_cause_line or '—'}`
- **Stack modules:** `{', '.join(report.stack_modules) or '—'}`
- **Symbol warnings:** `{len(report.symbol_warnings)}`
- **CDB session log:** `{report.debugger_session_log or '—'}`
- **Топ-кандидат:** `{top.driver if top else 'НЕ ОПРЕДЕЛЁН'}`
- **Эвристическая уверенность:** `{str(top.confidence) + '%' if top else 'недостаточно данных'}`

> ВАЖНО: топ-кандидат — не доказательство. Повреждение памяти могло произойти раньше, чем Windows обнаружила сбой.

## Кандидаты и основания

{''.join(candidates)}

## Качество телеметрии

### Есть
{present}

### Не хватает
{missing}

- **Качество телеметрии:** `{quality['telemetry_score']}% / {quality['telemetry_level']}`
- **Уверенность в виновнике:** рассчитывается отдельно по crash evidence и не уменьшается автоматически из-за отсутствия pre-crash ring.
- **AI guardrail для неполных данных:** `{quality['culprit_confidence_guardrail']}`

Важно: качество телеметрии и вероятность виновника — разные метрики.

## Файлы с прямыми доказательствами

- `debugger_raw.txt` — полный вывод CDB/WinDbg.
- `crash_report.json` — структурированные поля и все кандидаты.
- `events_near_crash.json` — исходные релевантные события Windows вокруг сбоя.
- `event_timeline.json` — те же события с delta/phase/role относительно crash time.
- `dump_health.json` — агрегат volmgr/WER о качестве записи dump.
- `precrash_snapshot.json` — последний snapshot ДО падения.
- `precrash_timeline.json` — ring-buffer snapshot'ов за заданное окно ДО падения; post-crash данные сюда не попадают.
- `history_repair.json` — состояние миграции старых записей; неоднозначные legacy-дубли не должны повышать repeat score.
- `scoring_model.json` — текущие веса алгоритма, чтобы можно было проверить и улучшить логику ранжирования.
- `program_source_snapshot.py` — исходник именно той версии программы, которая создала этот лог.

## Задание нейросети

1. Независимо перепроверь виновника по `debugger_raw.txt`, а не только по score.
2. Раздели **прямые доказательства**, **косвенные признаки** и **альтернативные причины**.
3. Проверь, не является ли `ntoskrnl.exe`/другой Microsoft-модуль лишь местом обнаружения повреждения.
4. Не считай Microsoft/WHQL-подпись доказательством того, что драйвер принадлежит Microsoft: сравни именно CompanyName/vendor.
5. Игнорируй драйверы, которые только были загружены, но отсутствуют в faulting context/IMAGE/MODULE/SYMBOL/bucket/crash stack.
6. Для memory-corruption BugCheck оцени возможность того, что память испортил другой драйвер раньше.
7. Сопоставь кандидатов с предаварийным snapshot и историей **независимых** повторных BSOD; не считай повторный анализ того же dump отдельным падением.
8. Предложи изменения в scoring model только с объяснением, какие ложные срабатывания они уменьшают.
9. Используй `event_timeline.json`: отличай PRE_CRASH от REBOOT_DUMP/POST_CRASH и не путай последствия перезагрузки с причиной падения.
10. Проверь `dump_health.json`: volmgr 161 + последующий 162 означает проблему/предупреждение записи с последующим успехом, а не автоматически потерянный dump.
11. Проверь `crash_fingerprint`: MEMORY.DMP и Minidump одного события не должны считаться разными BSOD.
12. Укажи, каких дополнительных данных нужно собирать в реальном времени, чтобы следующий BSOD диагностировался лучше.
13. Предложи улучшения формата логов: что добавить, удалить, агрегировать или сохранять в другом виде.

## Примечания программы

{chr(10).join('- ' + n for n in report.notes) if report.notes else '- Нет дополнительных примечаний.'}
"""

    def log_risk_snapshot(self, risks: list[dict[str, Any]]) -> None:
        compact = [{
            "driver": r.get("driver"), "priority": r.get("priority"), "version": r.get("version"),
            "signed": r.get("signed"), "path": r.get("path"), "category": r.get("category"),
            "historical_count": r.get("historical_count"), "reasons": r.get("reasons", [])
        } for r in risks[:20]]
        fingerprint = hashlib.sha1(json.dumps(compact, sort_keys=True, ensure_ascii=False).encode("utf-8", "ignore")).hexdigest()
        if fingerprint == self._last_risk_fingerprint:
            return
        self._last_risk_fingerprint = fingerprint
        path = self.root / "01_monitor_risk.jsonl"
        entry = {
            "time_utc": utc_now(), "session_id": self.session_id,
            "meaning": "historical_bsod rows have crash evidence; third_party rows are inventory only, not risk",
            "watch_items": risks[:60],
        }
        try:
            with self._lock, path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    def log_driver_changes(self, loaded: list[DriverInfo], unloaded: list[str]) -> None:
        if not loaded and not unloaded:
            return
        path = self.root / "02_driver_changes.jsonl"
        entry = {
            "time_utc": utc_now(),
            "session_id": self.session_id,
            "loaded": [asdict(x) for x in loaded],
            "unloaded": unloaded,
            "why_it_matters": "A driver loaded shortly before a BSOD is correlation evidence only; validate it against the crash dump.",
        }
        try:
            with self._lock, path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass
        self.activity("INFO", "driver_set_changed", "Изменился набор активных kernel-драйверов", {
            "loaded": [x.filename for x in loaded], "unloaded": unloaded,
        })

    def capture_manual_diagnostic(self) -> Path:
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = self.root / "Диагностика" / f"{stamp}_manual_snapshot"
        folder.mkdir(parents=True, exist_ok=True)
        data: dict[str, Any] = {
            "identity": {"kind": "manual_diagnostic", "schema_version": AI_LOG_SCHEMA_VERSION, "app_version": APP_VERSION},
            "environment": self._environment(),
            "configuration": self._config_snapshot(),
            "cdb_path": self.tools.find_cdb(),
            "dump_readiness": {},
            "latest_dumps": [],
            "running_drivers": [],
            "recent_events": [],
            "processes": [],
            "history": self.db.list_crashes(limit=25) if self.db else [],
            "scoring_model": {"version": SCORING_MODEL_VERSION, "rules": SCORING_RULES},
        }
        try: data["dump_readiness"] = self.tools.dump_readiness()
        except Exception as e: data["dump_readiness_error"] = str(e)
        for d in list_dump_files()[:10]:
            data["latest_dumps"].append(self._dump_diagnostics(d))
        try: data["running_drivers"] = [asdict(x) for x in self.tools.running_drivers()]
        except Exception as e: data["running_drivers_error"] = str(e)
        try: data["recent_events"] = self.tools.recent_events(minutes=60)[:300]
        except Exception as e: data["recent_events_error"] = str(e)
        try: data["processes"] = self.tools.processes_snapshot()[:500]
        except Exception as e: data["processes_error"] = str(e)
        self._write_json(folder / "diagnostic_snapshot.json", data)
        md = f"""# Диагностический снимок для нейросети

Создан: `{utc_now()}`  
Версия: `{APP_VERSION}`  
Администратор: `{data['environment']['is_admin']}`  
CDB: `{data['cdb_path'] or 'НЕ НАЙДЕН'}`

## Цель

Используй `diagnostic_snapshot.json`, чтобы оценить состояние сборщиков телеметрии, доступ к dump-файлам, активные драйверы и последние события Windows.

## Что проверить

1. Все ли важные источники телеметрии реально заполняются.
2. Есть ли PermissionError/ошибки CDB/symbols/Event Log.
3. Какие поля нужно добавить, чтобы лучше выявлять виновников будущих BSOD.
4. Какие активные сторонние драйверы требуют наблюдения, **не называя их виновниками без crash evidence**.
5. Не слишком ли много шума в логах; что стоит агрегировать.
"""
        (folder / "AI_CONTEXT.md").write_text(md, encoding="utf-8")
        try:
            source = Path(__file__).resolve()
            if source.exists():
                shutil.copy2(source, folder / "program_source_snapshot.py")
        except Exception:
            pass
        self._write_manifest(folder)
        self.activity("INFO", "manual_diagnostic", "Создан диагностический снимок для нейросети", {"folder": str(folder)})
        return folder

    def export_logs_zip(self, destination: Path) -> Path:
        destination = destination.resolve()
        if destination.suffix.lower() != ".zip":
            destination = destination.with_suffix(".zip")
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for f in self.root.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    if f.resolve() == destination:
                        continue
                except Exception:
                    pass
                zf.write(f, Path("Логи проблем") / f.relative_to(self.root))
        self.activity("INFO", "export_ai_logs", "Собран ZIP логов для нейросети", {"destination": str(destination)})
        return destination


class DumpParser:
    FIELD_PATTERNS = {
        "bugcheck_code": [r"BUGCHECK_CODE:\s+([0-9a-fA-Fx]+)", r"BugCheck\s+([0-9a-fA-F]+)"],
        "exception_code": [r"EXCEPTION_CODE:\s*\([^)]*\)\s*([0-9a-fA-Fx]+)", r"ExceptionCode:\s*([0-9a-fA-Fx]+)"],
        "process_name": [r"PROCESS_NAME:\s+([^\s]+)"],
        "module_name": [r"MODULE_NAME:\s+([^\s]+)"],
        "image_name": [r"IMAGE_NAME:\s+([^\s]+)"],
        "symbol_name": [r"SYMBOL_NAME:\s+([^\r\n]+)"],
        "failure_bucket_id": [r"FAILURE_BUCKET_ID:\s+([^\r\n]+)"],
        "failure_id_hash": [r"FAILURE_ID_HASH:\s+([^\r\n]+)", r"Key\s*:\s*Failure\.Hash\s*\r?\n\s*Value\s*:\s*([^\r\n]+)"],
        "probable_cause_line": [r"Probably caused by\s*:\s*([^\r\n]+)"],
        "debug_session_time_raw": [r"Debug session time:\s*([^\r\n]+)"],
    }

    KERNEL_ALIASES = {"nt", "ntoskrnl", "ntkrnlmp", "hal"}

    @staticmethod
    def normalize_code(code: str) -> str:
        if not code:
            return ""
        s = code.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        s = s.lstrip("0") or "0"
        return s

    @classmethod
    def module_to_driver(cls, module: str) -> str:
        module = Path(str(module or "").strip().strip("[](),")).name
        if not module:
            return ""
        low = module.lower()
        if low in cls.KERNEL_ALIASES or low.endswith((".dll", ".exe")):
            return ""
        return low if low.endswith(".sys") else low + ".sys"

    @staticmethod
    def parse_debug_session_time(raw: str) -> str:
        """Convert WinDbg `.time` output to UTC ISO when the UTC offset is present."""
        if not raw:
            return ""
        m = re.search(
            r"(?P<stamp>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d{4})\s+\(UTC\s*(?P<sign>[+-])\s*(?P<h>\d{1,2}):(?P<m>\d{2})\)",
            raw,
            re.IGNORECASE,
        )
        if not m:
            return ""
        stamp = re.sub(r"\s+", " ", m.group("stamp").strip())
        parsed = None
        for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                parsed = dt.datetime.strptime(stamp, fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            return ""
        off = dt.timedelta(hours=int(m.group("h")), minutes=int(m.group("m")))
        if m.group("sign") == "-":
            off = -off
        aware = parsed.replace(tzinfo=dt.timezone(off))
        return aware.astimezone(dt.timezone.utc).isoformat()

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for field_name, pats in self.FIELD_PATTERNS.items():
            val = ""
            for pattern in pats:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    val = m.group(1).strip()
                    break
            out[field_name] = val
        out["bugcheck_code"] = self.normalize_code(out.get("bugcheck_code", ""))
        out["bugcheck_name"] = BUGCHECK_NAMES.get(out["bugcheck_code"], "")
        params: list[str] = []
        for idx in range(1, 5):
            m = re.search(rf"(?im)^BUGCHECK_P{idx}:\s*([0-9a-fA-Fx`]+)", text)
            if not m:
                m = re.search(rf"(?im)^Arg{idx}:\s*([0-9a-fA-Fx`]+)", text)
            params.append(m.group(1).replace("`", "").strip() if m else "")
        out["bugcheck_parameters"] = params
        if not out.get("exception_code") and out["bugcheck_code"] in {"3b", "7e", "8e", "1000007e"} and params:
            out["exception_code"] = params[0]
        out["crash_time_utc"] = self.parse_debug_session_time(out.get("debug_session_time_raw", ""))
        out["stack_block"] = self.extract_stack(text)
        out["stack_modules"] = self.extract_stack_modules(out["stack_block"])
        out["faulting_module"] = self.extract_faulting_module(text)
        out["symbol_warnings"] = self.extract_symbol_warnings(text)
        out["crash_fingerprint"] = make_crash_fingerprint(out)
        # Kept only for diagnostics/AI log quality checks. It is NOT used for culprit scoring.
        out["sys_tokens"] = self.extract_sys_tokens(text)
        return out

    @staticmethod
    def extract_sys_tokens(text: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for token in re.findall(r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b", text):
            k = token.lower()
            counts[k] = counts.get(k, 0) + 1
        return counts

    @staticmethod
    def extract_stack(text: str) -> str:
        m = re.search(r"STACK_TEXT:\s*(.*?)(?:\n\n|SYMBOL_NAME:|MODULE_NAME:|IMAGE_NAME:)", text,
                      re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ""

    @classmethod
    def extract_stack_modules(cls, stack: str) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for module in re.findall(r":\s+([A-Za-z0-9_.-]+)(?:!|\+0x[0-9a-fA-F]+)", stack or ""):
            drv = cls.module_to_driver(module)
            if drv and drv not in seen:
                seen.add(drv)
                found.append(drv)
        for token in re.findall(r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b", stack or ""):
            drv = token.lower()
            if drv not in seen:
                seen.add(drv)
                found.append(drv)
        return found

    @classmethod
    def extract_faulting_module(cls, text: str) -> str:
        patterns = [
            r"(?m)^([A-Za-z0-9_.-]+)\+0x[0-9a-fA-F]+:\s*$",
            r"FAULTING_IP:\s*\r?\n\s*([A-Za-z0-9_.-]+)(?:!|\+0x)",
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if m:
                return cls.module_to_driver(m.group(1))
        return ""

    @staticmethod
    def extract_symbol_warnings(text: str) -> list[str]:
        warnings: list[str] = []
        for line in (text or "").splitlines():
            if re.search(r"(?i)(DBGHELP:.*Timeout|SYMSRV:.*(?:error|fail|timeout)|symbol.*(?:error|timeout))", line):
                clean = line.strip()
                if clean and clean not in warnings:
                    warnings.append(clean)
        return warnings[:30]

    def candidate_names(self, parsed: dict[str, Any]) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()

        def add(value: str) -> None:
            drv = self.module_to_driver(value)
            if drv and drv not in seen:
                seen.add(drv)
                names.append(drv)

        add(parsed.get("image_name", ""))
        add(parsed.get("module_name", ""))
        add(parsed.get("faulting_module", ""))
        for text in (parsed.get("symbol_name", ""), parsed.get("probable_cause_line", "")):
            for token in re.findall(r"(?i)([A-Za-z0-9_.-]+)(?:\.sys)?!", str(text)):
                add(token)
            for token in re.findall(r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b", str(text)):
                add(token)
        bucket = str(parsed.get("failure_bucket_id", ""))
        known_mod = str(parsed.get("module_name", "") or "")
        known_img = Path(str(parsed.get("image_name", "") or "")).stem
        if known_mod and re.search(re.escape(known_mod), bucket, re.IGNORECASE):
            add(known_mod)
        elif known_img and re.search(re.escape(known_img), bucket, re.IGNORECASE):
            add(known_img)
        else:
            for token in re.findall(r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b", bucket):
                add(token)
        for token in parsed.get("stack_modules", []) or []:
            add(str(token))
        return names


class ScoringEngine:
    def __init__(self, db: HistoryDB):
        self.db = db

    @staticmethod
    def _level(conf: int) -> str:
        if conf >= 90: return "VERY HIGH"
        if conf >= 75: return "HIGH"
        if conf >= 50: return "LIKELY"
        if conf >= 30: return "POSSIBLE"
        return "LOW"

    @staticmethod
    def _confidence(score: int) -> int:
        # More conservative than v1.3. Direct evidence can still reach 90%+, while
        # weak metadata/stack-only hints do not look falsely precise.
        return max(1, min(98, round(100 * (1 - math.exp(-max(score, 0) / 65.0)))))

    @staticmethod
    def _process_affinity(process_name: str, driver: str) -> bool:
        def core(value: str) -> str:
            value = Path(value or "").stem.lower()
            value = re.sub(r"[^a-z0-9]", "", value)
            for suffix in ("services", "service", "driver", "drv", "sys", "exe"):
                if value.endswith(suffix) and len(value) - len(suffix) >= 5:
                    value = value[:-len(suffix)]
            return value
        p = core(process_name)
        d = core(driver)
        return len(p) >= 5 and len(d) >= 5 and (p.startswith(d) or d.startswith(p) or p[:7] == d[:7])

    @staticmethod
    def _repeat_bonus(hits: int) -> int:
        if hits <= 0: return 0
        if hits == 1: return SCORING_RULES["repeat_bonus_1"]
        if hits == 2: return SCORING_RULES["repeat_bonus_2"]
        if hits == 3: return SCORING_RULES["repeat_bonus_3"]
        return SCORING_RULES["repeat_bonus_4_plus"]

    def score(
        self,
        parsed: dict[str, Any],
        inventory: dict[str, DriverInfo],
        current_sha: str = "",
        crash_time_utc: str = "",
        crash_fingerprint: str = "",
    ) -> list[Suspect]:
        candidates: dict[str, dict[str, Any]] = {}

        def add(name: str, points: int, reason: str, evidence_key: str, strong: bool = True):
            n = DumpParser.module_to_driver(name)
            if not n:
                return
            ent = candidates.setdefault(n, {"score": 0, "evidence": [], "strong_keys": set()})
            if evidence_key not in ent.setdefault("point_keys", set()):
                ent["score"] += points
                ent["point_keys"].add(evidence_key)
            if reason not in ent["evidence"]:
                ent["evidence"].append(reason)
            if strong:
                ent["strong_keys"].add(evidence_key)

        image = parsed.get("image_name", "")
        module = parsed.get("module_name", "")
        symbol = parsed.get("symbol_name", "")
        bucket = parsed.get("failure_bucket_id", "")
        probable = parsed.get("probable_cause_line", "")
        faulting = parsed.get("faulting_module", "")
        process = parsed.get("process_name", "")

        add(faulting, SCORING_RULES["faulting_module"], "Адрес исключения разрешается непосредственно в этот драйвер", "faulting_module")
        add(image, SCORING_RULES["image_name"], "IMAGE_NAME указывает на этот драйвер", "image_name")
        add(module, SCORING_RULES["module_name"], "MODULE_NAME совпадает с модулем драйвера", "module_name")

        for token in re.findall(r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b", probable):
            add(token, SCORING_RULES["probably_caused_by"], "WinDbg: Probably caused by", "probably_caused_by")
        for token in re.findall(r"(?i)([A-Za-z0-9_.-]+)(?:\.sys)?!", probable):
            add(token, SCORING_RULES["probably_caused_by"], "WinDbg: Probably caused by", "probably_caused_by")

        for token in re.findall(r"(?i)^\s*([A-Za-z0-9_.-]+)(?:\.sys)?(?:!|\+)", symbol):
            add(token, SCORING_RULES["symbol_name"], "SYMBOL_NAME связан с этим драйвером", "symbol_name")
        bucket_target = ""
        if module and re.search(re.escape(str(module)), bucket, re.IGNORECASE):
            bucket_target = str(module)
        elif image and re.search(re.escape(Path(str(image)).stem), bucket, re.IGNORECASE):
            bucket_target = str(image)
        if bucket_target:
            add(bucket_target, SCORING_RULES["failure_bucket_id"], "FAILURE_BUCKET_ID непосредственно содержит этот модуль", "failure_bucket_id")
        else:
            for token in re.findall(r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b", bucket):
                add(token, SCORING_RULES["failure_bucket_id"], "FAILURE_BUCKET_ID непосредственно содержит драйвер", "failure_bucket_id")

        for token in parsed.get("stack_modules", []) or []:
            add(str(token), SCORING_RULES["stack_module"], "Драйвер присутствует в непосредственном crash stack", "stack_module:" + str(token).lower())

        # WER 1019 is a useful corroboration, but not fully independent from the dump
        # analysis that produced the WER report. Keep the weight deliberately small.
        for token in parsed.get("wer_driver_correlations", []) or []:
            add(str(token), SCORING_RULES["wer_driver_correlation"],
                "Windows WER отдельно указал этот драйвер как возможно связанный со сбоем",
                "wer_driver_correlation:" + str(token).lower(), strong=False)

        # NOTE: sys_tokens from the full debugger output are intentionally NOT scored.
        # `lm`/loaded-module presence only means the driver was loaded, not that it crashed.

        suspects: list[Suspect] = []
        for driver, ent in candidates.items():
            strong_count = len(ent.get("strong_keys", set()))
            if strong_count <= 0:
                continue
            score = int(ent["score"])
            evidence = list(ent["evidence"])
            info = inventory.get(driver)
            vendor_type = "unknown"

            if process and self._process_affinity(process, driver):
                score += SCORING_RULES["process_affinity"]
                evidence.append(f"Связанный процесс `{process}` имеет явную продуктовую связь с модулем")

            if driver in SYSTEM_DRIVER_NAMES:
                score += SCORING_RULES["system_driver_penalty"]
                evidence.append("Системный модуль Windows: чаще место обнаружения сбоя, чем первопричина")
                vendor_type = "windows_system"

            if info:
                if info.microsoft:
                    score += SCORING_RULES["microsoft_vendor_penalty"]
                    evidence.append("Производитель бинарного файла — Microsoft; понижаю приоритет")
                    vendor_type = "microsoft"
                else:
                    score += SCORING_RULES["third_party_bonus"]
                    vendor_type = "third_party"
                    if info.microsoft_signed_third_party:
                        evidence.append("Сторонний драйвер с Microsoft/WHQL-подписью; подпись НЕ означает, что драйвер разработан Microsoft")
                    else:
                        evidence.append("Сторонний kernel-драйвер — умеренно повышаю приоритет")
                if info.signed is False:
                    score += SCORING_RULES["unsigned_bonus"]
                    evidence.append("Цифровая подпись не подтверждена (слабый дополнительный сигнал)")
                if info.modified_utc:
                    try:
                        age = (dt.datetime.now(dt.timezone.utc) - parse_iso(info.modified_utc)).days
                        if age <= 30:
                            score += SCORING_RULES["recent_driver_bonus"]
                            evidence.append("Файл драйвера изменён/установлен недавно (≤30 дней; слабый сигнал)")
                    except Exception:
                        pass

            previous = self.db.previous_driver_strong_hits(
                driver, exclude_sha=current_sha, crash_time_utc=crash_time_utc,
                crash_fingerprint=crash_fingerprint,
            )
            bonus = self._repeat_bonus(previous)
            if bonus:
                score += bonus
                evidence.append(f"Повторяется с прямыми доказательствами ещё в {previous} независимых предыдущих падениях")

            if score <= 0:
                continue
            conf = self._confidence(score)
            # Evidence gates prevent a single stack frame from looking like certainty.
            strong_source_names = {k.split(':', 1)[0] for k in ent.get("strong_keys", set())}
            if strong_source_names == {"stack_module"}:
                conf = min(conf, 45)
            elif len(strong_source_names) == 1:
                conf = min(conf, 65)
            if parsed.get("bugcheck_code") == "124" and len(strong_source_names) < 3:
                conf = min(conf, 40)

            suspects.append(Suspect(
                driver=driver,
                score=score,
                confidence=conf,
                level=self._level(conf),
                evidence=evidence,
                company=info.company if info else "",
                version=info.version if info else "",
                path=info.path if info else "",
                signed=info.signed if info else None,
                signer=info.signer if info else "",
                product=info.product if info else "",
                description=info.description if info else "",
                provider=info.provider if info else "",
                inf_name=info.inf_name if info else "",
                device_name=info.device_name if info else "",
                vendor_type=vendor_type,
                strong_evidence_count=len(strong_source_names),
            ))

        suspects.sort(key=lambda x: (x.score, x.strong_evidence_count, x.confidence), reverse=True)
        meaningful = [s for s in suspects if s.confidence >= 20]
        return (meaningful or suspects)[:8]


class ReportBuilder:

    @staticmethod
    def save(report: CrashReport) -> tuple[Path, Path]:
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(report.dump_name).stem)
        outdir = REPORT_DIR / f"{stamp}_{stem}"
        outdir.mkdir(parents=True, exist_ok=True)
        json_path = outdir / "report.json"
        html_path = outdir / "report.html"
        raw_path = outdir / "debugger_raw.txt"
        json_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        raw_path.write_text(report.raw_debugger_output or "CDB/WinDbg command-line debugger was not available.", encoding="utf-8", errors="replace")
        html_path.write_text(ReportBuilder.html(report), encoding="utf-8")
        return json_path, html_path

    @staticmethod
    def html(report: CrashReport) -> str:
        top = report.suspects[0] if report.suspects else None
        suspect_cards = []
        for i, s in enumerate(report.suspects[:5], 1):
            ev = "".join(f"<li>{html.escape(x)}</li>" for x in s.evidence)
            meta = " · ".join(x for x in [s.company or s.provider, s.product or s.device_name, s.version, s.inf_name, s.path] if x)
            suspect_cards.append(f"""
            <section class='card'>
              <h3>#{i} {html.escape(s.driver)} <span class='badge'>{s.confidence}% · {html.escape(s.level)}</span></h3>
              <p>{html.escape(meta)}</p>
              <p><b>Сильных источников crash evidence:</b> {s.strong_evidence_count} · <b>Класс:</b> {html.escape(s.vendor_type or 'unknown')}</p>
              <p><b>Provider/INF/устройство:</b> {html.escape(s.provider or '—')} · {html.escape(s.inf_name or '—')} · {html.escape(s.device_name or '—')}</p>
              <p><b>Подписант:</b> {html.escape(s.signer or '—')}</p>
              <ul>{ev}</ul>
            </section>""")
        events = "".join(
            f"<tr><td>{html.escape(str(e.get('TimeCreated','')))}</td><td>{html.escape(str(e.get('delta_from_crash_seconds','')))}</td>"
            f"<td>{html.escape(str(e.get('phase','')))}</td><td>{html.escape(str(e.get('role','')))}</td>"
            f"<td>{html.escape(str(e.get('ProviderName','')))}</td><td>{html.escape(str(e.get('Id','')))}</td>"
            f"<td>{html.escape(str(e.get('Message',''))[:1200])}</td></tr>"
            for e in report.event_timeline[:80]
        )
        dump_health = report.dump_health or {}
        quality = telemetry_quality(report)
        notes = "".join(f"<li>{html.escape(n)}</li>" for n in report.notes)
        return f"""<!doctype html>
<html lang='ru'><head><meta charset='utf-8'><title>BSOD Investigator Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:32px;background:#0f1115;color:#e8eaf0}}
main{{max-width:1100px;margin:auto}} .card{{background:#181c24;border:1px solid #2b3240;border-radius:14px;padding:18px;margin:14px 0}}
.badge{{font-size:.8em;background:#2b3240;border-radius:999px;padding:5px 10px;float:right}} code{{background:#242a35;padding:2px 5px;border-radius:5px}}
table{{width:100%;border-collapse:collapse}} td,th{{border-bottom:1px solid #2b3240;padding:8px;text-align:left;vertical-align:top}}
.good{{color:#81d4a8}} .warn{{color:#ffd166}} .bad{{color:#ff7b7b}}
</style></head><body><main>
<h1>BSOD Investigator</h1>
<section class='card'>
<h2>Краткий вывод</h2>
<p><b>Dump:</b> {html.escape(report.dump_name)} · {html.escape(report.dump_kind or 'тип неизвестен')} · {report.dump_size_bytes / (1024*1024):.1f} MB</p>
<p><b>Время аварии UTC:</b> {html.escape(report.crash_time_utc or 'не извлечено')}</p>
<p><b>BugCheck:</b> <code>0x{html.escape(report.bugcheck_code or '?')}</code> {html.escape(report.bugcheck_name)} · <b>Параметры:</b> {html.escape(', '.join(report.bugcheck_parameters) or '—')}</p>
<p><b>Crash fingerprint:</b> <code>{html.escape(report.crash_fingerprint or '—')}</code> · <b>Failure ID:</b> {html.escape(report.failure_id_hash or '—')}</p>
<p><b>Вероятный виновник:</b> {html.escape(top.driver if top else 'не определён')}</p>
<p><b>Уверенность в виновнике:</b> {f'{top.confidence}% ({html.escape(top.level)})' if top else 'недостаточно данных'}</p>
<p><b>Качество телеметрии:</b> {quality['telemetry_score']}% ({html.escape(quality['telemetry_level'])})</p>
<p><b>Процесс:</b> {html.escape(report.process_name or '—')} · <b>Exception:</b> {html.escape(report.exception_code or '—')}</p>
</section>
<section class='card'><h2>Dump Health и подтверждения Windows</h2>
<p><b>Статус:</b> {html.escape(str(dump_health.get('status','unknown')))} — {html.escape(str(dump_health.get('summary','')))}</p>
<p><b>WER driver correlation:</b> {html.escape(', '.join(report.wer_driver_correlations) or '—')}</p>
<p><b>Pre-crash ring:</b> {len(report.precrash_timeline)} snapshot(ов)</p>
</section>
<h2>Кандидаты</h2>{''.join(suspect_cards) or '<section class="card">Недостаточно данных для выделения конкретного стороннего драйвера.</section>'}
<section class='card'><h2>Ключевые поля WinDbg/CDB</h2>
<table><tr><th>Поле</th><th>Значение</th></tr>
<tr><td>FAULTING_MODULE</td><td>{html.escape(report.faulting_module)}</td></tr>
<tr><td>IMAGE_NAME</td><td>{html.escape(report.image_name)}</td></tr>
<tr><td>MODULE_NAME</td><td>{html.escape(report.module_name)}</td></tr>
<tr><td>SYMBOL_NAME</td><td>{html.escape(report.symbol_name)}</td></tr>
<tr><td>FAILURE_BUCKET_ID</td><td>{html.escape(report.failure_bucket_id)}</td></tr>
<tr><td>Probably caused by</td><td>{html.escape(report.probable_cause_line)}</td></tr>
<tr><td>Stack modules</td><td>{html.escape(', '.join(report.stack_modules))}</td></tr>
<tr><td>Symbol warnings</td><td>{html.escape(' | '.join(report.symbol_warnings))}</td></tr></table></section>
<section class='card'><h2>Timeline событий Windows</h2><table><tr><th>UTC</th><th>Δ, сек</th><th>Фаза</th><th>Роль</th><th>Источник</th><th>ID</th><th>Сообщение</th></tr>{events}</table></section>
<section class='card'><h2>Примечания</h2><ul>{notes}</ul></section>
<section class='card'><small>Generated by {APP_NAME} {APP_VERSION}. Оценка вероятности — диагностическая эвристика, а не математическое доказательство.</small></section>
</main></body></html>"""


class Analyzer:
    def __init__(self, config: Config, db: HistoryDB, tools: WindowsTools, problem_logger: ProblemLogger | None = None):
        self.config = config
        self.db = db
        self.tools = tools
        self.problem_logger = problem_logger
        self.parser = DumpParser()
        self.scoring = ScoringEngine(db)
        self._analysis_lock = threading.Lock()

    def analyze(
        self,
        dump: Path,
        progress: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
        cdb_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> tuple[CrashReport, Path, Path]:
        if not self._analysis_lock.acquire(blocking=False):
            raise AnalysisBusyError("Другой анализ dump уже выполняется. Дождитесь его завершения или отмените его.")
        try:
            return self._analyze_locked(dump, progress, cancel_event, cdb_event)
        finally:
            self._analysis_lock.release()

    def _analyze_locked(
        self,
        dump: Path,
        progress: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
        cdb_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> tuple[CrashReport, Path, Path]:
        dump = dump.expanduser().resolve()
        if not dump.exists():
            raise FileNotFoundError(dump)
        if progress: progress(f"Хеширую {dump.name}…")
        sha = sha256_file(dump)
        mtime_dt = dt.datetime.fromtimestamp(dump.stat().st_mtime, dt.timezone.utc)
        mtime = mtime_dt.isoformat()

        if progress: progress("Собираю список активных kernel-драйверов…")
        inventory = self.tools.driver_inventory_map()

        raw, debugger_path, debugger_session_log = self.tools.analyze_dump_with_cdb(
            dump, progress, cancel_event=cancel_event, event_callback=cdb_event
        )
        parsed = self.parser.parse(raw) if raw else {
            "bugcheck_code": "", "bugcheck_name": "", "exception_code": "", "process_name": "",
            "module_name": "", "image_name": "", "symbol_name": "", "failure_bucket_id": "",
            "failure_id_hash": "", "bugcheck_parameters": [], "crash_fingerprint": "",
            "probable_cause_line": "", "faulting_module": "", "stack_modules": [],
            "debug_session_time_raw": "", "crash_time_utc": "", "symbol_warnings": [],
            "wer_driver_correlations": [], "sys_tokens": {}, "stack_block": ""
        }

        # Enrich only evidence-backed candidates. This replaces v1.3's huge `lm t n`
        # enumeration, which was slow and caused false positives from merely loaded drivers.
        candidate_names = self.parser.candidate_names(parsed)
        if progress and candidate_names:
            progress(f"Проверяю метаданные {len(candidate_names)} кандидатов…")
        targeted = self.tools.inspect_driver_files(candidate_names)
        inventory.update(targeted)

        crash_time_utc = parsed.get("crash_time_utc", "")
        event_target = mtime_dt
        if crash_time_utc:
            try:
                event_target = parse_iso(crash_time_utc)
            except Exception:
                event_target = mtime_dt

        # Event Log is queried BEFORE scoring because WER 1019 can corroborate a
        # driver already named by the dump. It gets only a small score weight.
        if progress: progress("Читаю и классифицирую события Windows вокруг реального времени сбоя…")
        window = dt.timedelta(minutes=20)
        raw_events = self.tools.events_between(event_target - window, event_target + window)
        nearby = classify_event_timeline(raw_events, event_target)
        wer_correlations = extract_wer_driver_correlations(nearby)
        parsed["wer_driver_correlations"] = wer_correlations
        dump_health = summarize_dump_health(nearby)

        if progress: progress("Сопоставляю кандидатов и независимые прошлые падения…")
        suspects = self.scoring.score(
            parsed, inventory, current_sha=sha, crash_time_utc=crash_time_utc,
            crash_fingerprint=str(parsed.get("crash_fingerprint") or ""),
        )

        # Export a real pre-crash ring, never a post-reboot snapshot. The newest item
        # becomes the compact `precrash_snapshot`, while the full ring is available to AI.
        precrash_timeline = self.db.precrash_timeline(
            event_target.isoformat(), window_minutes=max(5, int(getattr(self.config, "precrash_window_minutes", 30) or 30))
        )
        snapshot = precrash_timeline[-1] if precrash_timeline else {}

        notes: list[str] = []
        if not debugger_path:
            notes.append("CDB (Debugging Tools for Windows) не найден: глубокий анализ dump-файла недоступен. Установите Debugging Tools for Windows и укажите cdb.exe в настройках.")
        if parsed.get("bugcheck_code") == "124":
            notes.append("0x124/WHEA часто указывает на аппаратную/прошивочную причину; один драйвер нельзя объявлять виновником без WHEA-данных.")
        if parsed.get("bugcheck_code") in {"1a", "50", "7f", "139", "13a"} and not suspects:
            notes.append("Тип ошибки совместим с повреждением памяти; возможны RAM/разгон/драйвер, который испортил память раньше. Конкретный виновник не доказан.")
        if snapshot:
            notes.append(f"Найден предаварийный ring-buffer: {len(precrash_timeline)} snapshot(ов) до аварии; post-crash snapshots не используются.")
        if wer_correlations:
            notes.append("Windows WER указал возможно связанный драйвер: " + ", ".join(wer_correlations) + ". Это подтверждающий, но не полностью независимый сигнал.")
        if dump_health.get("status") == "success_after_warning":
            notes.append("Dump Health: volmgr сначала зарегистрировал ошибку записи dump (161), затем успешное создание (162).")
        elif dump_health.get("status") == "failed_or_incomplete":
            notes.append("Dump Health: обнаружена ошибка volmgr 161 без подтверждения успешной записи 162 в выбранном окне.")
        if parsed.get("symbol_warnings"):
            notes.append(f"CDB сообщил о проблемах/таймаутах symbols: {len(parsed.get('symbol_warnings', []))}. Основные crash-поля всё равно оцениваются отдельно.")
        if not nearby:
            source = "времени аварии из dump (.time)" if crash_time_utc else "времени изменения dump-файла"
            notes.append(f"Не найдено релевантных событий Windows в ±20 минут от {source}.")

        dump_kind = "MEMORY.DMP (kernel/automatic/complete dump)" if dump.name.lower() == "memory.dmp" else "Minidump"
        report = CrashReport(
            dump_path=str(dump), dump_name=dump.name, analyzed_at=utc_now(), dump_mtime=mtime,
            sha256=sha, crash_time_utc=crash_time_utc,
            debug_session_time_raw=parsed.get("debug_session_time_raw", ""),
            dump_size_bytes=dump.stat().st_size, dump_kind=dump_kind,
            symbol_warnings=parsed.get("symbol_warnings", []),
            bugcheck_code=parsed.get("bugcheck_code", ""), bugcheck_name=parsed.get("bugcheck_name", ""),
            exception_code=parsed.get("exception_code", ""), process_name=parsed.get("process_name", ""),
            module_name=parsed.get("module_name", ""), image_name=parsed.get("image_name", ""),
            symbol_name=parsed.get("symbol_name", ""), failure_bucket_id=parsed.get("failure_bucket_id", ""),
            failure_id_hash=parsed.get("failure_id_hash", ""), bugcheck_parameters=parsed.get("bugcheck_parameters", []),
            crash_fingerprint=parsed.get("crash_fingerprint", ""),
            probable_cause_line=parsed.get("probable_cause_line", ""),
            faulting_module=parsed.get("faulting_module", ""), stack_modules=parsed.get("stack_modules", []),
            wer_driver_correlations=wer_correlations, event_timeline=nearby, dump_health=dump_health,
            suspects=suspects,
            debugger_found=bool(debugger_path), debugger_path=debugger_path, debugger_session_log=debugger_session_log,
            raw_debugger_output=raw, nearby_events=nearby, precrash_snapshot=snapshot,
            precrash_timeline=precrash_timeline, notes=notes,
        )
        json_path, html_path = ReportBuilder.save(report)
        self.db.save_crash(report, json_path, html_path)
        if self.problem_logger:
            try:
                self.problem_logger.capture_crash_report(report)
            except Exception as log_exc:
                self.problem_logger.activity("WARNING", "crash_log_write", f"Не удалось сохранить AI-лог BSOD: {log_exc}")
        if progress: progress("Готово.")
        return report, json_path, html_path

    def export_support_package(self, report: CrashReport, destination: Path, progress: Callable[[str], None] | None = None) -> Path:
        destination = destination.resolve()
        if destination.suffix.lower() != ".zip":
            destination = destination.with_suffix(".zip")
        if progress: progress("Собираю системные сведения для support package…")
        support = self.tools.collect_support_commands()
        with tempfile.TemporaryDirectory(prefix="bsodinvestigator_") as td:
            root = Path(td)
            (root / "report.json").write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
            (root / "report.html").write_text(ReportBuilder.html(report), encoding="utf-8")
            (root / "debugger_raw.txt").write_text(report.raw_debugger_output or "Debugger output unavailable.", encoding="utf-8", errors="replace")
            (root / "events_near_crash.json").write_text(json.dumps(report.nearby_events, ensure_ascii=False, indent=2), encoding="utf-8")
            (root / "event_timeline.json").write_text(json.dumps(report.event_timeline, ensure_ascii=False, indent=2), encoding="utf-8")
            (root / "dump_health.json").write_text(json.dumps(report.dump_health, ensure_ascii=False, indent=2), encoding="utf-8")
            (root / "precrash_snapshot.json").write_text(json.dumps(report.precrash_snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
            (root / "precrash_timeline.json").write_text(json.dumps(report.precrash_timeline, ensure_ascii=False, indent=2), encoding="utf-8")
            (root / "history_repair.json").write_text(json.dumps(self.db.last_repair_stats, ensure_ascii=False, indent=2), encoding="utf-8")
            for name, content in support.items():
                (root / name).write_text(content, encoding="utf-8", errors="replace")
            privacy = (
                "PRIVACY NOTICE\n\n"
                "Crash dumps and diagnostics can contain technical information about the system and, depending on dump type, fragments of memory. "
                "Review the package before sending it to a third party.\n"
            )
            (root / "PRIVACY_README.txt").write_text(privacy, encoding="utf-8")
            dump = Path(report.dump_path)
            if self.config.include_dump_in_support_zip and dump.exists():
                try:
                    shutil.copy2(dump, root / dump.name)
                except Exception as e:
                    (root / "dump_copy_error.txt").write_text(str(e), encoding="utf-8")
            if progress: progress("Упаковываю ZIP…")
            with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                for f in root.rglob("*"):
                    if f.is_file():
                        zf.write(f, f.relative_to(root))
        if progress: progress(f"Support package создан: {destination}")
        return destination


class PassiveMonitor(threading.Thread):
    """Passive monitoring only. It does NOT enable Driver Verifier or hook kernel memory."""
    daemon = True

    def __init__(self, config: Config, db: HistoryDB, tools: WindowsTools, analyzer: Analyzer,
                 on_status: Callable[[str], None], on_new_report: Callable[[CrashReport, Path], None],
                 on_risk: Callable[[list[dict[str, Any]]], None], problem_logger: ProblemLogger | None = None):
        super().__init__(name="BSODPassiveMonitor")
        self.config = config
        self.db = db
        self.tools = tools
        self.analyzer = analyzer
        self.on_status = on_status
        self.on_new_report = on_new_report
        self.on_risk = on_risk
        self.problem_logger = problem_logger
        self.stop_event = threading.Event()
        self._known_dumps: dict[str, float] = {}
        self._last_fast_snapshot = 0.0
        self._last_heavy_snapshot = 0.0
        self._last_events = 0.0
        self._analysis_lock = threading.Lock()
        self._last_driver_map: dict[str, DriverInfo] = {}
        self._historical_metadata_cache: dict[str, DriverInfo] = {}

    def stop(self):
        self.stop_event.set()

    def scan_existing(self):
        # Mark only already-processed dumps as known. If Windows created a dump during
        # the previous crash before this app started, _check_dumps() will still see it
        # as new after logon and analyze it automatically.
        for d in list_dump_files():
            try:
                sha = sha256_file(d)
                if self.db.has_dump_hash(sha):
                    self._known_dumps[str(d)] = d.stat().st_mtime
            except Exception:
                pass

    def run(self):
        self.scan_existing()
        self.on_status("Мониторинг активен")
        while not self.stop_event.is_set():
            try:
                self._check_dumps()
                now = time.time()
                if now - self._last_heavy_snapshot >= max(30, self.config.snapshot_seconds):
                    self._snapshot()
                    self._last_heavy_snapshot = now
                if now - self._last_fast_snapshot >= max(10, int(getattr(self.config, "fast_snapshot_seconds", 15) or 15)):
                    self._fast_snapshot()
                    self._last_fast_snapshot = now
                if now - self._last_events >= max(15, self.config.event_seconds):
                    self._poll_events()
                    self._last_events = now
            except Exception as e:
                self.on_status(f"Ошибка мониторинга: {e}")
                if self.problem_logger:
                    try:
                        self.problem_logger.capture_exception(e, "monitor_loop", {"trigger": "background_monitor"})
                    except Exception:
                        pass
            self.stop_event.wait(max(2, self.config.poll_seconds))
        self.on_status("Мониторинг остановлен")

    def _check_dumps(self):
        for d in list_dump_files():
            try:
                mtime = d.stat().st_mtime
            except OSError:
                continue
            key = str(d)
            old = self._known_dumps.get(key)
            if old is None or mtime > old + 0.001:
                self._known_dumps[key] = mtime
                if self.config.auto_analyze_new_dumps:
                    # Wait briefly so Windows has time to finish the file.
                    time.sleep(2)
                    self.on_status(f"Найден новый dump: {d.name}. Анализирую…")
                    try:
                        with self._analysis_lock:
                            sha = sha256_file(d)
                            if self.db.has_dump_hash(sha):
                                continue
                            report, _, html_path = self.analyzer.analyze(d, self.on_status)
                            self.on_new_report(report, html_path)
                    except AnalysisBusyError:
                        self.on_status(f"Новый dump {d.name} ожидает: другой анализ уже выполняется")
                        # Remove from known list so the monitor retries on the next pass.
                        self._known_dumps.pop(key, None)
                    except AnalysisCancelledError:
                        self.on_status(f"Автоанализ {d.name} отменён")
                        self._known_dumps.pop(key, None)
                    except Exception as e:
                        self.on_status(f"Не удалось проанализировать {d.name}: {e}")
                        if self.problem_logger:
                            try:
                                self.problem_logger.capture_exception(e, "auto_analyze_dump", {"dump_path": str(d), "trigger": "background_monitor"})
                            except Exception:
                                pass

    def _fast_snapshot(self):
        """Lightweight 10-15 second ring sample persisted before a possible crash."""
        raw_processes = self.tools.processes_snapshot()
        processes = [{"name": p.get("name", ""), "pid": p.get("pid", "")} for p in raw_processes]
        payload = {
            "kind": "fast",
            "created_at": utc_now(),
            "system": system_runtime_snapshot(),
            "process_count": len(processes),
            "processes": processes,
            # Full driver metadata is expensive; reuse the last heavy driver's active set.
            "active_driver_names": sorted(self._last_driver_map.keys()),
        }
        self.db.save_snapshot(payload)

    def _snapshot(self):
        """Heavier ~60 second sample with signatures/version metadata and driver changes."""
        drivers = self.tools.running_drivers()
        processes = self.tools.processes_snapshot()
        payload = {
            "kind": "heavy",
            "created_at": utc_now(),
            "system": system_runtime_snapshot(),
            "drivers": [asdict(d) for d in drivers],
            "processes": processes,
        }
        self.db.save_snapshot(payload)

        current_map = {d.filename: d for d in drivers if d.filename}
        if self._last_driver_map:
            loaded_names = sorted(set(current_map) - set(self._last_driver_map))
            unloaded_names = sorted(set(self._last_driver_map) - set(current_map))
            if self.problem_logger and (loaded_names or unloaded_names):
                self.problem_logger.log_driver_changes([current_map[n] for n in loaded_names], unloaded_names)
        self._last_driver_map = current_map

        risks = self.rank_passive_risks(drivers)
        if self.problem_logger:
            self.problem_logger.log_risk_snapshot(risks)
        self.on_risk(risks)

    def _poll_events(self):
        events = self.tools.recent_events(minutes=5)
        for e in events:
            self.db.save_event(e)

    def rank_passive_risks(self, drivers: list[DriverInfo]) -> list[dict[str, Any]]:
        """Build two concepts: historical BSOD linkage and ordinary third-party inventory.

        The UI no longer calls the ordinary list "risk". A third-party/AMD/Kaspersky
        driver being loaded is normal and is not evidence of a crash.
        """
        ranked: list[dict[str, Any]] = []
        for d in drivers:
            if d.microsoft:
                continue
            details = self.db.previous_driver_strong_hit_details(d.filename)
            historical_count = len(details)
            if historical_count and (not d.company or not d.version or not d.provider):
                enriched = self._historical_metadata_cache.get(d.filename)
                if enriched is None:
                    enriched = self.tools.inspect_driver_files([d.filename]).get(d.filename)
                    if enriched:
                        self._historical_metadata_cache[d.filename] = enriched
                if enriched:
                    # Keep runtime state/path if the targeted package lookup lacks it.
                    for field_name in DriverInfo.__annotations__:
                        if not getattr(enriched, field_name, None) and getattr(d, field_name, None):
                            setattr(enriched, field_name, getattr(d, field_name))
                    d = enriched
            priority = 0
            reasons: list[str] = []
            category = "third_party"
            if historical_count:
                category = "historical_bsod"
                priority = min(100, 35 + historical_count * 20)
                reasons.append(f"прямые crash-признаки в {historical_count} уникальных предыдущих BSOD")
            if d.microsoft_signed_third_party:
                reasons.append("Microsoft/WHQL-подпись; производитель файла при этом сторонний")
            elif d.signed is False:
                reasons.append("подпись не подтверждена (только косвенный признак для наблюдения)")
            if d.modified_utc:
                try:
                    age = (dt.datetime.now(dt.timezone.utc) - parse_iso(d.modified_utc)).days
                    if age <= 14:
                        reasons.append("файл недавно изменён/установлен ≤14 дней (косвенный признак)")
                except Exception:
                    pass
            if not reasons:
                reasons.append("активный сторонний kernel-драйвер; сам факт загрузки не является crash evidence")
            ranked.append({
                "driver": d.filename, "score": priority, "priority": priority,
                "company": d.company, "version": d.version, "signed": d.signed, "path": d.path,
                "reasons": reasons, "category": category, "historical_count": historical_count,
                "historical_crashes": details,
            })
        ranked.sort(key=lambda x: (x["category"] != "historical_bsod", -int(x["priority"]), x["driver"]))
        return ranked[:60]


# ---------------- GUI ----------------

def launch_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    if not IS_WINDOWS:
        raise RuntimeError("BSOD Investigator предназначен для Windows 10/11.")

    config = Config.load()
    db = HistoryDB()
    tools = WindowsTools(config)
    problem_logger = ProblemLogger(config, tools, db)
    if db.last_repair_stats:
        try:
            problem_logger.activity("INFO", "history_repair_startup", "Проверена/мигрирована история предыдущих анализов", db.last_repair_stats)
        except Exception:
            pass
    analyzer = Analyzer(config, db, tools, problem_logger)
    ui_queue: queue.Queue = queue.Queue()

    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}")
    root.geometry("1120x760")
    root.minsize(950, 650)

    def _thread_exception_hook(args):
        try:
            folder = problem_logger.capture_exception(args.exc_value, "uncaught_thread_exception", {"thread": getattr(args.thread, "name", "")})
            ui_queue.put(("error", f"Необработанная ошибка фонового потока: {args.exc_value}\n\nЛог: {folder}"))
            ui_queue.put(("refresh_logs",))
        except Exception:
            pass
    threading.excepthook = _thread_exception_hook

    def _tk_callback_exception(exc_type, exc_value, exc_tb):
        try:
            exc_value = exc_value or exc_type("Tkinter callback error")
            exc_value.__traceback__ = exc_tb
            folder = problem_logger.capture_exception(exc_value, "tkinter_callback")
            messagebox.showerror(APP_NAME, f"Ошибка интерфейса: {exc_value}\n\nЛог: {folder}")
        except Exception:
            traceback.print_exception(exc_type, exc_value, exc_tb)
    root.report_callback_exception = _tk_callback_exception

    style = ttk.Style(root)
    try:
        style.theme_use("vista")
    except Exception:
        pass

    status_var = tk.StringVar(value="Готово")
    startup_var = tk.BooleanVar(value=is_autorun_enabled())
    monitor_var = tk.BooleanVar(value=config.monitor_enabled)
    include_dump_var = tk.BooleanVar(value=config.include_dump_in_support_zip)
    auto_analyze_var = tk.BooleanVar(value=config.auto_analyze_new_dumps)
    fast_snapshot_var = tk.IntVar(value=max(10, int(getattr(config, "fast_snapshot_seconds", 15) or 15)))
    heavy_snapshot_var = tk.IntVar(value=max(30, int(getattr(config, "snapshot_seconds", 60) or 60)))
    precrash_window_var = tk.IntVar(value=max(10, int(getattr(config, "precrash_window_minutes", 30) or 30)))
    cdb_var = tk.StringVar(value=config.cdb_path or tools.find_cdb())

    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    ttk.Label(top, text="BSOD Investigator", font=("Segoe UI", 18, "bold")).pack(side="left")
    ttk.Label(top, textvariable=status_var).pack(side="right")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    tab_main = ttk.Frame(notebook, padding=12)
    tab_live = ttk.Frame(notebook, padding=12)
    tab_history = ttk.Frame(notebook, padding=12)
    tab_logs = ttk.Frame(notebook, padding=12)
    tab_settings = ttk.Frame(notebook, padding=12)
    notebook.add(tab_main, text="Анализ")
    notebook.add(tab_live, text="Мониторинг")
    notebook.add(tab_history, text="История")
    notebook.add(tab_logs, text="Логи проблем")
    notebook.add(tab_settings, text="Настройки")

    # Main tab
    actions = ttk.Frame(tab_main)
    actions.pack(fill="x")

    analysis_state: dict[str, Any] = {
        "running": False,
        "cancel_event": None,
        "started_mono": 0.0,
        "last_output": "",
        "stage": "Готово",
        "cdb_log_dir": "",
        "worker_thread": None,
    }
    analysis_stage_var = tk.StringVar(value="Готово")
    analysis_elapsed_var = tk.StringVar(value="00:00")
    analysis_last_var = tk.StringVar(value="—")

    cdb_progress_box = ttk.LabelFrame(tab_main, text="Ход анализа CDB", padding=8)
    cdb_progress_box.pack(fill="x", pady=(8, 0))
    cdb_info = ttk.Frame(cdb_progress_box)
    cdb_info.pack(fill="x")
    ttk.Label(cdb_info, text="Этап:").grid(row=0, column=0, sticky="w")
    ttk.Label(cdb_info, textvariable=analysis_stage_var, font=("Segoe UI", 9, "bold")).grid(row=0, column=1, sticky="w", padx=(6, 20))
    ttk.Label(cdb_info, text="Время:").grid(row=0, column=2, sticky="w")
    ttk.Label(cdb_info, textvariable=analysis_elapsed_var).grid(row=0, column=3, sticky="w", padx=(6, 20))
    ttk.Label(cdb_info, text="Последний вывод:").grid(row=1, column=0, sticky="nw", pady=(4, 0))
    ttk.Label(cdb_info, textvariable=analysis_last_var, wraplength=820).grid(row=1, column=1, columnspan=3, sticky="w", padx=(6, 0), pady=(4, 0))
    cdb_info.columnconfigure(1, weight=1)

    cdb_live_text = tk.Text(cdb_progress_box, wrap="none", font=("Consolas", 9), height=7)
    cdb_live_text.pack(fill="x", pady=(6, 0))
    cdb_live_text.insert("1.0", "CDB ещё не запускался.\n")
    cdb_live_text.configure(state="disabled")

    result_text = tk.Text(tab_main, wrap="word", font=("Consolas", 10), height=22)
    result_text.pack(fill="both", expand=True, pady=10)
    result_text.insert("1.0", "Выберите .dmp или нажмите «Анализировать последний dump».\n")
    current_report: dict[str, Any] = {"report": None, "html": None}

    def ui_status(msg: str):
        ui_queue.put(("status", msg))

    def open_path(path: Path | str):
        p = str(path)
        try:
            os.startfile(p)  # type: ignore[attr-defined]
        except Exception as e:
            try:
                folder = problem_logger.capture_exception(e, "open_path", {"path": p})
                messagebox.showerror(APP_NAME, f"{e}\n\nЛог: {folder}")
            except Exception:
                messagebox.showerror(APP_NAME, str(e))

    def show_report(report: CrashReport, html_path: Path | None = None):
        current_report["report"] = report
        current_report["html"] = html_path
        top_s = report.suspects[0] if report.suspects else None
        quality = problem_logger._crash_quality(report)
        lines = [
            f"Dump: {report.dump_name} ({report.dump_kind or 'тип неизвестен'}, {report.dump_size_bytes / (1024*1024):.1f} MB)",
            f"Время аварии (UTC): {report.crash_time_utc or 'не извлечено; используется время файла'}",
            f"BugCheck: 0x{report.bugcheck_code or '?'} {report.bugcheck_name}",
            f"Параметры BugCheck: {', '.join(report.bugcheck_parameters) or '—'}",
            f"Exception: {report.exception_code or '—'}",
            f"Crash fingerprint: {report.crash_fingerprint or '—'}",
            f"Process: {report.process_name or '—'}",
            f"FAULTING_MODULE: {report.faulting_module or '—'}",
            f"IMAGE_NAME: {report.image_name or '—'}",
            f"MODULE_NAME: {report.module_name or '—'}",
            f"SYMBOL_NAME: {report.symbol_name or '—'}",
            f"FAILURE_BUCKET_ID: {report.failure_bucket_id or '—'}",
            f"FAILURE_ID_HASH: {report.failure_id_hash or '—'}",
            f"WER driver correlation: {', '.join(report.wer_driver_correlations) or '—'}",
            f"Dump Health: {(report.dump_health or {}).get('status','unknown')} — {(report.dump_health or {}).get('summary','')}",
            f"Pre-crash ring: {len(report.precrash_timeline)} snapshot(ов)",
            "",
            f"ВЕРОЯТНЫЙ ВИНОВНИК: {top_s.driver if top_s else 'НЕ ОПРЕДЕЛЁН'}",
            f"Уверенность в виновнике: {str(top_s.confidence) + '% / ' + top_s.level if top_s else 'недостаточно данных'}",
            f"Качество телеметрии: {quality['telemetry_score']}% / {quality['telemetry_level']}",
            "",
            "Кандидаты (только по crash evidence; просто загруженные модули больше не оцениваются):",
        ]
        for i, s in enumerate(report.suspects[:5], 1):
            lines.append(f"{i}. {s.driver} — {s.confidence}% ({s.level}), score={s.score}, сильных источников={s.strong_evidence_count}")
            if s.company: lines.append(f"   Производитель файла: {s.company}")
            if s.product: lines.append(f"   Продукт: {s.product}")
            if s.version: lines.append(f"   Версия: {s.version}")
            if s.provider: lines.append(f"   Provider пакета: {s.provider}")
            if s.inf_name: lines.append(f"   INF: {s.inf_name}")
            if s.device_name: lines.append(f"   Связанное устройство: {s.device_name}")
            if s.signer: lines.append(f"   Подписант: {s.signer}")
            if s.vendor_type: lines.append(f"   Классификация: {s.vendor_type}")
            for ev in s.evidence[:10]: lines.append(f"   • {ev}")
        if report.notes:
            lines.extend(["", "Примечания:"] + [f"• {n}" for n in report.notes])
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "\n".join(lines))

    def _format_elapsed(seconds: float) -> str:
        seconds = max(0, int(seconds))
        return f"{seconds // 60:02d}:{seconds % 60:02d}"

    def _append_cdb_live(line: str):
        if not line:
            return
        cdb_live_text.configure(state="normal")
        if cdb_live_text.get("1.0", "end-1c") == "CDB ещё не запускался.":
            cdb_live_text.delete("1.0", "end")
        cdb_live_text.insert("end", line.rstrip("\r\n") + "\n")
        # Bound UI memory; full output is always preserved in Логи проблем\CDB\...\cdb_live_output.txt.
        try:
            line_count = int(cdb_live_text.index("end-1c").split(".")[0])
            if line_count > 320:
                cdb_live_text.delete("1.0", f"{line_count - 250}.0")
        except Exception:
            pass
        cdb_live_text.see("end")
        cdb_live_text.configure(state="disabled")

    def _set_analysis_controls(running: bool):
        analysis_state["running"] = running
        state = "disabled" if running else "normal"
        try:
            choose_dump_btn.configure(state=state)
            analyze_latest_btn.configure(state=state)
        except Exception:
            pass
        try:
            cancel_analysis_btn.configure(state="normal" if running else "disabled")
        except Exception:
            pass
        if not running:
            analysis_state["cancel_event"] = None
            analysis_state["worker_thread"] = None

    def _cdb_event_to_ui(event: dict[str, Any]):
        if event.get("log_dir"):
            analysis_state["cdb_log_dir"] = event.get("log_dir")
        if event.get("stage_display"):
            analysis_state["stage"] = event.get("stage_display")
        if event.get("line"):
            analysis_state["last_output"] = str(event.get("line"))
        ui_queue.put(("cdb_event", event))

    def analyze_file(path: Path, trigger: str = "manual"):
        if analysis_state.get("running"):
            messagebox.showinfo(APP_NAME, "Анализ уже выполняется. Дождитесь завершения или нажмите «Отменить анализ».")
            return
        cancel_event = threading.Event()
        analysis_state.update({
            "running": True,
            "cancel_event": cancel_event,
            "started_mono": time.monotonic(),
            "last_output": "",
            "stage": "Подготовка dump",
            "cdb_log_dir": "",
        })
        _set_analysis_controls(True)
        analysis_stage_var.set("Подготовка dump")
        analysis_elapsed_var.set("00:00")
        analysis_last_var.set("—")
        cdb_live_text.configure(state="normal")
        cdb_live_text.delete("1.0", "end")
        cdb_live_text.insert("1.0", f"Начат анализ: {path}\n")
        cdb_live_text.configure(state="disabled")

        def worker():
            try:
                problem_logger.activity("INFO", "analyze_dump", f"Начат анализ {path.name}", {
                    "dump_path": str(path), "trigger": trigger, "analysis_singleton": True
                })
                report, _, html_path = analyzer.analyze(
                    path, ui_status, cancel_event=cancel_event, cdb_event=_cdb_event_to_ui
                )
                ui_queue.put(("report", report, html_path))
                ui_queue.put(("refresh_history",))
                ui_queue.put(("refresh_logs",))
                problem_logger.activity("INFO", "analyze_dump", f"Анализ завершён {path.name}", {
                    "dump_path": str(path), "trigger": trigger, "cdb_log": report.debugger_session_log
                })
            except AnalysisCancelledError as e:
                problem_logger.activity("INFO", "analyze_dump_cancelled", str(e), {
                    "dump_path": str(path), "trigger": trigger, "cdb_log": analysis_state.get("cdb_log_dir", "")
                })
                ui_queue.put(("analysis_cancelled", str(e)))
                ui_queue.put(("refresh_logs",))
            except AnalysisBusyError as e:
                ui_queue.put(("info", str(e)))
            except Exception as e:
                try:
                    log_folder = problem_logger.capture_exception(e, "analyze_dump", {
                        "dump_path": str(path), "trigger": trigger,
                        "cdb_log": analysis_state.get("cdb_log_dir", ""),
                        "analysis_elapsed_seconds": round(time.monotonic() - analysis_state.get("started_mono", time.monotonic()), 2),
                        "analysis_stage": analysis_state.get("stage", ""),
                        "analysis_last_output": analysis_state.get("last_output", ""),
                    })
                except Exception:
                    log_folder = PROBLEM_LOG_DIR
                friendly = f"{type(e).__name__}: {e}\n\nДиагностический лог сохранён в:\n{log_folder}"
                if isinstance(e, PermissionError):
                    friendly += "\n\nПрограмма должна работать с правами администратора. Перезапустите её и разрешите UAC."
                if isinstance(e, subprocess.TimeoutExpired):
                    friendly += "\n\nCDB превысил лимит времени. Полный live-лог и heartbeat находятся в папке Логи проблем\\CDB."
                ui_queue.put(("error", friendly))
                ui_queue.put(("refresh_logs",))
            finally:
                ui_queue.put(("analysis_done",))
        worker_thread = threading.Thread(target=worker, name=f"ManualDumpAnalysis-{path.name}", daemon=True)
        analysis_state["worker_thread"] = worker_thread
        worker_thread.start()

    def choose_dump():
        if analysis_state.get("running"):
            return
        p = filedialog.askopenfilename(title="Выберите Windows crash dump", filetypes=[("Crash dump", "*.dmp"), ("All files", "*.*")], initialdir=str(MINIDUMP_DIR))
        if p:
            analyze_file(Path(p), "file_picker")

    def analyze_latest():
        if analysis_state.get("running"):
            return
        latest = select_latest_dump()
        if not latest:
            messagebox.showinfo(APP_NAME, f"Dump-файлы не найдены в {MINIDUMP_DIR} и {MEMORY_DMP}.")
            return
        analyze_file(latest, "latest_dump_button")

    def cancel_analysis():
        ev = analysis_state.get("cancel_event")
        if not analysis_state.get("running") or not isinstance(ev, threading.Event):
            return
        analysis_stage_var.set("Отмена анализа…")
        status_var.set("Отменяю CDB…")
        try:
            ev.set()
            problem_logger.activity("INFO", "analyze_dump_cancel_request", "Пользователь запросил отмену анализа", {
                "cdb_log": analysis_state.get("cdb_log_dir", ""),
                "elapsed_seconds": round(time.monotonic() - analysis_state.get("started_mono", time.monotonic()), 2),
            })
        except Exception:
            pass

    choose_dump_btn = ttk.Button(actions, text="Выбрать .dmp…", command=choose_dump)
    choose_dump_btn.pack(side="left", padx=(0, 6))
    analyze_latest_btn = ttk.Button(actions, text="Анализировать последний dump", command=analyze_latest)
    analyze_latest_btn.pack(side="left", padx=6)
    cancel_analysis_btn = ttk.Button(actions, text="Отменить анализ", command=cancel_analysis, state="disabled")
    cancel_analysis_btn.pack(side="left", padx=6)

    def export_current():
        report = current_report.get("report")
        if not report:
            messagebox.showinfo(APP_NAME, "Сначала выполните анализ dump-файла.")
            return
        p = filedialog.asksaveasfilename(title="Сохранить support package", defaultextension=".zip",
                                         filetypes=[("ZIP", "*.zip")], initialfile=f"BSOD_Support_{Path(report.dump_name).stem}.zip")
        if not p:
            return
        def worker():
            try:
                analyzer.export_support_package(report, Path(p), ui_status)
                ui_queue.put(("info", f"Support package создан:\n{p}"))
            except Exception as e:
                try:
                    log_folder = problem_logger.capture_exception(e, "export_support_package", {"destination": str(p), "dump_path": str(report.dump_path)})
                except Exception:
                    log_folder = PROBLEM_LOG_DIR
                ui_queue.put(("error", f"Не удалось собрать ZIP: {e}\n\nЛог: {log_folder}"))
                ui_queue.put(("refresh_logs",))
        threading.Thread(target=worker, daemon=True).start()
    ttk.Button(actions, text="Собрать ZIP для поддержки", command=export_current).pack(side="left", padx=6)

    def open_current_html():
        if current_report.get("html"):
            open_path(current_report["html"])
        else:
            messagebox.showinfo(APP_NAME, "Сначала выполните анализ.")
    ttk.Button(actions, text="Открыть HTML-отчёт", command=open_current_html).pack(side="left", padx=6)

    # Live tab
    live_top = ttk.Frame(tab_live)
    live_top.pack(fill="x")
    ttk.Label(live_top, text="Пассивный мониторинг", font=("Segoe UI", 14, "bold")).pack(side="left")
    live_state = tk.StringVar(value="выключен")
    ttk.Label(live_top, textvariable=live_state).pack(side="right")
    ttk.Label(tab_live, wraplength=1000,
              text=("Программа каждые несколько секунд отслеживает новые Minidump, а раз в минуту сохраняет предаварийный snapshot "
                    "активных kernel-драйверов и процессов. Она также читает релевантные события Windows. Это пассивная диагностика: "
                    "она не вмешивается в ядро и не включает Driver Verifier автоматически.")).pack(fill="x", pady=(8, 10))

    hist_watch_box = ttk.LabelFrame(tab_live, text="Связанные с предыдущими BSOD", padding=6)
    hist_watch_box.pack(fill="x", pady=(0, 8))
    hist_watch_cols = ("driver", "priority", "company", "version", "crashes", "reason")
    hist_watch_tree = ttk.Treeview(hist_watch_box, columns=hist_watch_cols, show="headings", height=6)
    for col, title, width in [
        ("driver", "Драйвер", 180), ("priority", "Приоритет", 75), ("company", "Компания", 190),
        ("version", "Версия", 120), ("crashes", "Уникальных BSOD", 110), ("reason", "Основание", 390)
    ]:
        hist_watch_tree.heading(col, text=title); hist_watch_tree.column(col, width=width, anchor="w")
    hist_watch_tree.pack(fill="x")

    third_watch_box = ttk.LabelFrame(tab_live, text="Остальные активные сторонние kernel-драйверы (инвентарь, НЕ риск)", padding=6)
    third_watch_box.pack(fill="both", expand=True)
    third_watch_cols = ("driver", "company", "version", "signed", "note")
    third_watch_tree = ttk.Treeview(third_watch_box, columns=third_watch_cols, show="headings", height=12)
    for col, title, width in [
        ("driver", "Драйвер", 190), ("company", "Компания", 240), ("version", "Версия", 130),
        ("signed", "Подпись", 80), ("note", "Примечание", 430)
    ]:
        third_watch_tree.heading(col, text=title); third_watch_tree.column(col, width=width, anchor="w")
    third_watch_tree.pack(fill="both", expand=True)
    ttk.Label(tab_live, text="Важно: числовой приоритет показывается только для драйверов, уже имевших прямые crash evidence в уникальных прошлых BSOD.", foreground="#8a5a00").pack(anchor="w", pady=8)

    # History tab
    hist_cols = ("when", "bugcheck", "culprit", "confidence", "status", "dump")
    hist_tree = ttk.Treeview(tab_history, columns=hist_cols, show="headings")
    for col, title, width in [
        ("when", "Время dump", 170), ("bugcheck", "BugCheck", 230), ("culprit", "Кандидат", 190),
        ("confidence", "Уверенность", 95), ("status", "Статус истории", 170), ("dump", "Файл", 220)
    ]:
        hist_tree.heading(col, text=title); hist_tree.column(col, width=width, anchor="w")
    hist_tree.pack(fill="both", expand=True)
    hist_map: dict[str, dict[str, Any]] = {}

    def refresh_history():
        for item in hist_tree.get_children(): hist_tree.delete(item)
        hist_map.clear()
        for row in db.list_crashes():
            status = row.get("history_status", "") or "не классифицировано"
            iid = hist_tree.insert("", "end", values=(
                row.get("dump_mtime", ""), f"0x{row.get('bugcheck_code','')} {row.get('bugcheck_name','')}",
                row.get("culprit", ""), f"{row.get('confidence',0)}%", status, row.get("dump_name", "")
            ))
            hist_map[iid] = row

    def open_history_report(_event=None):
        sel = hist_tree.selection()
        if not sel: return
        row = hist_map.get(sel[0])
        if row and row.get("report_html"):
            open_path(row["report_html"])
    hist_tree.bind("<Double-1>", open_history_report)
    hist_actions = ttk.Frame(tab_history)
    hist_actions.pack(fill="x", pady=8)
    ttk.Button(hist_actions, text="Открыть выбранный HTML", command=open_history_report).pack(side="left", padx=(0, 8))

    history_repair_var = tk.StringVar(value="")
    def refresh_history_repair_status():
        st = db.last_repair_stats or {}
        if st.get("status") == "ok":
            history_repair_var.set(
                "Ремонт истории: "
                f"canonical={st.get('canonical',0)}, legacy unique={st.get('legacy_unique',0)}, "
                f"ignored ambiguous/unresolved={st.get('ignored_for_repeat_scoring',0)}"
            )
        elif st:
            history_repair_var.set("Ремонт истории: " + str(st))
        else:
            history_repair_var.set("Ремонт истории: данных нет")

    def repair_history_now():
        try:
            db.last_repair_stats = db.repair_legacy_history()
            refresh_history_repair_status()
            refresh_history()
            problem_logger.activity("INFO", "history_repair", "Выполнена ручная проверка/миграция старой истории", db.last_repair_stats)
            messagebox.showinfo(APP_NAME, "История проверена. Неоднозначные legacy-записи не участвуют в повторном scoring.")
        except Exception as e:
            folder = problem_logger.capture_exception(e, "history_repair")
            messagebox.showerror(APP_NAME, f"Не удалось проверить историю: {e}\n\nЛог: {folder}")

    ttk.Button(hist_actions, text="Проверить/исправить старую историю", command=repair_history_now).pack(side="left")
    ttk.Label(tab_history, textvariable=history_repair_var, wraplength=1000).pack(anchor="w", pady=(0, 8))
    refresh_history_repair_status()

    # Problem logs tab
    logs_top = ttk.Frame(tab_logs)
    logs_top.pack(fill="x")
    ttk.Label(logs_top, text="AI-понятные логи проблем", font=("Segoe UI", 14, "bold")).pack(side="left")
    ttk.Label(tab_logs, wraplength=1000,
              text=("Программа сохраняет сюда ошибки собственного кода, результаты анализа BSOD и диагностические снимки. "
                    "В каждом событии есть JSON + Markdown с прямыми фактами, гипотезами, пробелами телеметрии и заданием для нейросети: "
                    "как исправить программу, улучшить логи и точнее выявлять виновников падений Windows.")).pack(fill="x", pady=(8, 8))
    ttk.Label(tab_logs, text=f"Папка: {PROBLEM_LOG_DIR}", wraplength=1000).pack(anchor="w", pady=(0, 8))

    log_buttons = ttk.Frame(tab_logs)
    log_buttons.pack(fill="x", pady=(0, 8))
    ttk.Button(log_buttons, text="Открыть папку «Логи проблем»", command=lambda: open_path(PROBLEM_LOG_DIR)).pack(side="left", padx=(0, 6))

    def create_manual_ai_snapshot():
        def worker():
            try:
                ui_status("Собираю диагностический снимок для нейросети…")
                folder = problem_logger.capture_manual_diagnostic()
                ui_queue.put(("info", f"Диагностический снимок создан:\n{folder}"))
                ui_queue.put(("refresh_logs",))
                ui_status("Готово")
            except Exception as e:
                try:
                    problem_logger.capture_exception(e, "manual_ai_snapshot")
                except Exception:
                    pass
                ui_queue.put(("error", f"Не удалось создать диагностический снимок: {e}"))
        threading.Thread(target=worker, daemon=True).start()
    ttk.Button(log_buttons, text="Создать диагностический снимок", command=create_manual_ai_snapshot).pack(side="left", padx=6)

    def export_ai_logs():
        initial = f"BSOD_Investigator_AI_Logs_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        p = filedialog.asksaveasfilename(title="Сохранить логи для нейросети", defaultextension=".zip",
                                         filetypes=[("ZIP", "*.zip")], initialfile=initial)
        if not p:
            return
        def worker():
            try:
                out = problem_logger.export_logs_zip(Path(p))
                ui_queue.put(("info", f"ZIP логов для нейросети создан:\n{out}"))
            except Exception as e:
                try:
                    problem_logger.capture_exception(e, "export_ai_logs", {"destination": p})
                except Exception:
                    pass
                ui_queue.put(("error", f"Не удалось собрать ZIP логов: {e}"))
        threading.Thread(target=worker, daemon=True).start()
    ttk.Button(log_buttons, text="Собрать ZIP логов для нейросети", command=export_ai_logs).pack(side="left", padx=6)

    log_tree = ttk.Treeview(tab_logs, columns=("type", "name", "modified"), show="headings", height=18)
    for col, title, width in [("type", "Тип", 180), ("name", "Событие", 520), ("modified", "Изменено", 200)]:
        log_tree.heading(col, text=title); log_tree.column(col, width=width, anchor="w")
    log_tree.pack(fill="both", expand=True)
    log_map: dict[str, Path] = {}

    def refresh_logs():
        for item in log_tree.get_children():
            log_tree.delete(item)
        log_map.clear()
        rows: list[tuple[float, str, Path]] = []
        for category in ("Ошибки программы", "Падения Windows", "Диагностика", "CDB"):
            base = PROBLEM_LOG_DIR / category
            if not base.exists():
                continue
            try:
                for folder in base.iterdir():
                    if folder.is_dir():
                        try: mt = folder.stat().st_mtime
                        except Exception: mt = 0.0
                        rows.append((mt, category, folder))
            except Exception:
                pass
        rows.sort(key=lambda x: x[0], reverse=True)
        for mt, category, folder in rows[:200]:
            modified = dt.datetime.fromtimestamp(mt).astimezone().strftime("%Y-%m-%d %H:%M:%S") if mt else ""
            iid = log_tree.insert("", "end", values=(category, folder.name, modified))
            log_map[iid] = folder

    def open_selected_log(_event=None):
        sel = log_tree.selection()
        if not sel:
            return
        folder = log_map.get(sel[0])
        if folder:
            open_path(folder)
    log_tree.bind("<Double-1>", open_selected_log)
    ttk.Button(tab_logs, text="Открыть выбранное событие", command=open_selected_log).pack(anchor="w", pady=8)
    refresh_logs()

    # Settings tab
    settings_box = ttk.LabelFrame(tab_settings, text="Поведение", padding=12)
    settings_box.pack(fill="x")
    ttk.Label(settings_box, text=f"Права администратора: {'ДА' if is_admin() else 'НЕТ'}").pack(anchor="w", pady=(0, 6))

    def toggle_autorun():
        try:
            set_autorun(startup_var.get())
        except Exception as e:
            startup_var.set(is_autorun_enabled())
            try:
                folder = problem_logger.capture_exception(e, "toggle_autorun", {"requested_enabled": startup_var.get()})
                messagebox.showerror(APP_NAME, f"Не удалось изменить автозапуск:\n{e}\n\nЛог: {folder}")
            except Exception:
                messagebox.showerror(APP_NAME, f"Не удалось изменить автозапуск:\n{e}")

    ttk.Checkbutton(settings_box, text="Запускать вместе с Windows", variable=startup_var, command=toggle_autorun).pack(anchor="w", pady=3)
    ttk.Checkbutton(settings_box, text="Пассивный мониторинг в реальном времени", variable=monitor_var).pack(anchor="w", pady=3)
    ttk.Checkbutton(settings_box, text="Автоматически анализировать новые dump-файлы", variable=auto_analyze_var).pack(anchor="w", pady=3)
    ttk.Checkbutton(settings_box, text="Включать .dmp в ZIP для поддержки (может содержать чувствительные технические данные)", variable=include_dump_var).pack(anchor="w", pady=3)
    ring_row = ttk.Frame(settings_box); ring_row.pack(fill="x", pady=(8, 2))
    ttk.Label(ring_row, text="Лёгкий pre-crash snapshot каждые, сек:").pack(side="left")
    ttk.Spinbox(ring_row, from_=10, to=60, increment=5, textvariable=fast_snapshot_var, width=6).pack(side="left", padx=(6, 16))
    ttk.Label(ring_row, text="Расширенный snapshot, сек:").pack(side="left")
    ttk.Spinbox(ring_row, from_=30, to=300, increment=15, textvariable=heavy_snapshot_var, width=6).pack(side="left", padx=(6, 16))
    ttk.Label(ring_row, text="Ring-buffer до сбоя, мин:").pack(side="left")
    ttk.Spinbox(ring_row, from_=10, to=120, increment=5, textvariable=precrash_window_var, width=6).pack(side="left", padx=6)

    cdb_box = ttk.LabelFrame(tab_settings, text="Microsoft Debugging Tools", padding=12)
    cdb_box.pack(fill="x", pady=12)
    ttk.Label(cdb_box, text="Путь к cdb.exe (для глубокого !analyze -v):").pack(anchor="w")
    cdb_row = ttk.Frame(cdb_box); cdb_row.pack(fill="x", pady=5)
    ttk.Entry(cdb_row, textvariable=cdb_var).pack(side="left", fill="x", expand=True)
    def choose_cdb():
        p = filedialog.askopenfilename(title="Выберите cdb.exe", filetypes=[("CDB debugger", "cdb*.exe"), ("Executable", "*.exe")])
        if p: cdb_var.set(p)
    ttk.Button(cdb_row, text="Обзор…", command=choose_cdb).pack(side="left", padx=6)

    cdb_timeout_var = tk.IntVar(value=max(60, int(getattr(config, "cdb_timeout_seconds", 600) or 600)))
    timeout_row = ttk.Frame(tab_settings)
    timeout_row.pack(fill="x", pady=(0, 12))
    ttk.Label(timeout_row, text="Лимит времени CDB, сек:").pack(side="left")
    ttk.Spinbox(timeout_row, from_=60, to=3600, increment=60, textvariable=cdb_timeout_var, width=8).pack(side="left", padx=8)
    ttk.Label(timeout_row, text="Первый анализ может долго скачивать symbols; рекомендуется 600 сек.").pack(side="left")

    advanced_box = ttk.LabelFrame(tab_settings, text="Диагностика", padding=12)
    advanced_box.pack(fill="x")
    dump_ready_text = tk.Text(advanced_box, height=8, wrap="word")
    dump_ready_text.pack(fill="x", pady=(6, 6))
    def check_dump_readiness():
        def worker():
            data = tools.dump_readiness()
            ui_queue.put(("dump_ready", json.dumps(data, ensure_ascii=False, indent=2)))
        threading.Thread(target=worker, daemon=True).start()
    ttk.Button(advanced_box, text="Проверить настройки crash dump / pagefile", command=check_dump_readiness).pack(side="left", padx=(0,6))
    def open_verifier():
        if messagebox.askyesno(APP_NAME,
            "Driver Verifier — мощный инструмент Microsoft, который может специально вызвать BSOD и даже цикл загрузки при проблемном драйвере.\n\n"
            "BSOD Investigator НЕ включает его автоматически. Открыть verifier.exe для ручной диагностики?"):
            subprocess.Popen(["verifier.exe"])
    ttk.Button(advanced_box, text="Открыть Driver Verifier (опасно)", command=open_verifier).pack(side="left", padx=6)

    def save_settings():
        config.monitor_enabled = monitor_var.get()
        config.auto_analyze_new_dumps = auto_analyze_var.get()
        config.include_dump_in_support_zip = include_dump_var.get()
        config.cdb_path = cdb_var.get().strip()
        try:
            config.fast_snapshot_seconds = max(10, min(60, int(fast_snapshot_var.get())))
            config.snapshot_seconds = max(30, min(300, int(heavy_snapshot_var.get())))
            config.precrash_window_minutes = max(10, min(120, int(precrash_window_var.get())))
        except Exception:
            config.fast_snapshot_seconds = 15
            config.snapshot_seconds = 60
            config.precrash_window_minutes = 30
        try:
            config.cdb_timeout_seconds = max(60, min(3600, int(cdb_timeout_var.get())))
        except Exception:
            config.cdb_timeout_seconds = 600
        config.save()
        messagebox.showinfo(APP_NAME, "Настройки сохранены. Изменение мониторинга применится после перезапуска приложения.")
    ttk.Button(tab_settings, text="Сохранить настройки", command=save_settings).pack(anchor="w", pady=12)

    refresh_history()

    monitor: PassiveMonitor | None = None
    if config.monitor_enabled:
        def on_new_report(report: CrashReport, html_path: Path):
            ui_queue.put(("report", report, html_path))
            ui_queue.put(("refresh_history",))
            ui_queue.put(("notify", f"Новый BSOD: {report.suspects[0].driver if report.suspects else 'виновник не определён'}"))
        def on_risk(risks): ui_queue.put(("risk", risks))
        monitor = PassiveMonitor(config, db, tools, analyzer, ui_status, on_new_report, on_risk, problem_logger)
        monitor.start()
        live_state.set("активен")

    def tick_analysis_clock():
        if analysis_state.get("running"):
            elapsed = time.monotonic() - float(analysis_state.get("started_mono") or time.monotonic())
            analysis_elapsed_var.set(_format_elapsed(elapsed))
        root.after(1000, tick_analysis_clock)

    def process_queue():
        try:
            while True:
                item = ui_queue.get_nowait()
                kind = item[0]
                if kind == "status": status_var.set(item[1])
                elif kind == "report": show_report(item[1], item[2])
                elif kind == "error": messagebox.showerror(APP_NAME, item[1])
                elif kind == "info": messagebox.showinfo(APP_NAME, item[1])
                elif kind == "refresh_history": refresh_history()
                elif kind == "refresh_logs": refresh_logs()
                elif kind == "analysis_done":
                    _set_analysis_controls(False)
                    if analysis_stage_var.get() not in {"Готово", "Отменено"}:
                        analysis_stage_var.set("Готово")
                    status_var.set("Готово")
                elif kind == "analysis_cancelled":
                    analysis_stage_var.set("Отменено")
                    status_var.set("Анализ отменён")
                    _append_cdb_live("[BSOD Investigator] Анализ отменён пользователем.")
                elif kind == "cdb_event":
                    ev = item[1]
                    if ev.get("log_dir"):
                        analysis_state["cdb_log_dir"] = ev.get("log_dir")
                    et = ev.get("type")
                    if et == "stage":
                        stage = ev.get("stage_display") or ev.get("stage") or "CDB"
                        analysis_state["stage"] = stage
                        analysis_stage_var.set(stage)
                        _append_cdb_live(f"[ЭТАП] {stage}")
                    elif et == "line":
                        line = str(ev.get("line") or "")
                        analysis_state["last_output"] = line
                        short = line if len(line) <= 180 else "…" + line[-179:]
                        analysis_last_var.set(short or "—")
                        # Stage markers are already rendered separately; skip duplicate marker line.
                        if "[BSODI_STAGE]" not in line:
                            _append_cdb_live(line)
                    elif et == "warning":
                        msg = str(ev.get("message") or "")
                        _append_cdb_live(f"[ПРЕДУПРЕЖДЕНИЕ SYMBOLS] {msg}")
                        status_var.set("CDB сообщил о проблеме symbols; анализ продолжается")
                    elif et == "heartbeat":
                        elapsed = float(ev.get("elapsed_seconds") or 0)
                        analysis_elapsed_var.set(_format_elapsed(elapsed))
                        age = ev.get("last_output_age_seconds")
                        if ev.get("core_evidence_ready"):
                            fields = ", ".join(ev.get("evidence_fields_seen") or [])
                            status_var.set(f"CDB работает {_format_elapsed(elapsed)}; основные crash-поля уже получены")
                            if fields:
                                analysis_last_var.set("Получено: " + fields)
                        elif age is not None and int(age) >= 30:
                            status_var.set(f"CDB работает {_format_elapsed(elapsed)}; нет нового вывода {int(age)} сек")
                    elif et == "started":
                        analysis_stage_var.set("CDB запущен")
                        _append_cdb_live(f"[CDB] PID {ev.get('pid')} запущен")
                    elif et == "cancelling":
                        analysis_stage_var.set("Остановка CDB…")
                    elif et == "timeout":
                        analysis_stage_var.set("Таймаут CDB")
                        _append_cdb_live(f"[TIMEOUT] CDB превысил {ev.get('timeout_seconds')} сек")
                    elif et == "finished":
                        analysis_elapsed_var.set(_format_elapsed(float(ev.get("elapsed_seconds") or 0)))
                        _append_cdb_live(f"[CDB] Завершение: {ev.get('end_reason')}, exit={ev.get('exit_code')}")
                elif kind == "risk":
                    for x in hist_watch_tree.get_children(): hist_watch_tree.delete(x)
                    for x in third_watch_tree.get_children(): third_watch_tree.delete(x)
                    for r in item[1]:
                        signed_text = "Да" if r["signed"] else ("Нет" if r["signed"] is False else "?")
                        if r.get("category") == "historical_bsod":
                            details = r.get("historical_crashes") or []
                            summary = []
                            for c in details[:3]:
                                when = str(c.get("crash_time_utc") or "?")[:19]
                                summary.append(f"{when} 0x{c.get('bugcheck_code','?')}")
                            reason = "; ".join(summary) or "; ".join(r.get("reasons") or [])
                            hist_watch_tree.insert("", "end", values=(
                                r["driver"], r.get("priority", 0), r["company"], r["version"],
                                r.get("historical_count", 0), reason
                            ))
                        else:
                            third_watch_tree.insert("", "end", values=(
                                r["driver"], r["company"], r["version"], signed_text,
                                "; ".join(r.get("reasons") or [])
                            ))
                elif kind == "notify":
                    root.deiconify(); root.lift();
                    messagebox.showwarning(APP_NAME, item[1])
                elif kind == "dump_ready":
                    dump_ready_text.delete("1.0", "end"); dump_ready_text.insert("1.0", item[1])
        except queue.Empty:
            pass
        root.after(250, process_queue)

    def on_close():
        try:
            ev = analysis_state.get("cancel_event")
            if analysis_state.get("running") and isinstance(ev, threading.Event):
                ev.set()
                tools.cancel_active_cdb()
                worker_thread = analysis_state.get("worker_thread")
                if isinstance(worker_thread, threading.Thread) and worker_thread.is_alive():
                    worker_thread.join(timeout=1.5)
            problem_logger.activity("INFO", "shutdown", "Приложение закрывается", {
                "analysis_running": bool(analysis_state.get("running")),
                "cdb_log": analysis_state.get("cdb_log_dir", ""),
            })
        except Exception:
            pass
        if monitor: monitor.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(1000, tick_analysis_clock)
    root.after(250, process_queue)
    root.mainloop()


# ---------------- Utility functions ----------------

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_iso(value: str) -> dt.datetime:
    s = value.strip().replace("Z", "+00:00")
    d = dt.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                b = f.read(chunk)
                if not b: break
                h.update(b)
    except PermissionError as e:
        raise PermissionError(
            f"Нет доступа к crash dump: {path}\n"
            "Windows защищает файлы C:\\Windows\\Minidump. "
            "BSOD Investigator должен быть запущен с правами администратора."
        ) from e
    return h.hexdigest()


def list_dump_files() -> list[Path]:
    """List automatic-analysis dump candidates without double-counting one BSOD.

    Windows can create both MEMORY.DMP and a Minidump for one crash. If their file
    modification times are close, keep the Minidump in the automatic queue and leave
    MEMORY.DMP available through the manual file picker for deeper analysis.
    """
    mins: list[Path] = []
    try:
        if MINIDUMP_DIR.exists():
            mins = [p for p in MINIDUMP_DIR.glob("*.dmp") if p.is_file()]
    except Exception:
        mins = []
    dumps: list[Path] = list(mins)
    try:
        if MEMORY_DMP.exists():
            mem_mtime = MEMORY_DMP.stat().st_mtime
            near_min = False
            for m in mins:
                try:
                    if abs(m.stat().st_mtime - mem_mtime) <= 15 * 60:
                        near_min = True
                        break
                except Exception:
                    pass
            if not near_min:
                dumps.append(MEMORY_DMP)
    except Exception:
        pass
    try:
        dumps.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        pass
    return dumps


def select_latest_dump() -> Path | None:
    """Choose the newest crash efficiently.

    If MEMORY.DMP and a minidump were written for the same crash, prefer the much
    smaller minidump for interactive analysis. Use MEMORY.DMP when it is clearly
    newer (more than five minutes) or when no minidump exists.
    """
    mins: list[Path] = []
    try:
        if MINIDUMP_DIR.exists():
            mins = [p for p in MINIDUMP_DIR.glob("*.dmp") if p.is_file()]
            mins.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        mins = []
    mem = MEMORY_DMP if MEMORY_DMP.exists() else None
    if not mins:
        return mem
    latest_min = mins[0]
    if mem:
        try:
            if mem.stat().st_mtime > latest_min.stat().st_mtime + 300:
                return mem
        except Exception:
            pass
    return latest_min


def filter_events_near(events: list[dict[str, Any]], target: dt.datetime, minutes: int = 20) -> list[dict[str, Any]]:
    target = target.astimezone(dt.timezone.utc)
    result = []
    for e in events:
        try:
            t = parse_iso(str(e.get("TimeCreated", "")))
            if abs((t - target).total_seconds()) <= minutes * 60:
                result.append(e)
        except Exception:
            pass
    result.sort(key=lambda e: str(e.get("TimeCreated", "")))
    return result



def _repair_cp866_mojibake(value: Any) -> Any:
    """Best-effort repair for legacy CP866 text accidentally decoded as CP1251.

    v1.4 logs from Russian Windows showed strings such as ``ЋиЁЎЄа``. New
    PowerShell calls are UTF-8, but this repair keeps imported/legacy event text
    readable and makes AI logs self-healing.
    """
    if not isinstance(value, str) or not value:
        return value
    # Character fingerprints that are very common in CP866->CP1251 mojibake.
    suspicious = sum(value.count(ch) for ch in "ҐЎўЋЏ‘’“®¬ЇЄ")
    if suspicious < 2:
        return value
    try:
        fixed = value.encode("cp1251").decode("cp866")
    except Exception:
        return value
    # Keep the repair only when it clearly reduces the mojibake fingerprint.
    fixed_suspicious = sum(fixed.count(ch) for ch in "ҐЎўЋЏ‘’“®¬ЇЄ")
    return fixed if fixed_suspicious < suspicious else value


def normalize_windows_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in events or []:
        if not isinstance(raw, dict):
            continue
        e = dict(raw)
        for key in ("LevelDisplayName", "Message", "ProviderName"):
            e[key] = _repair_cp866_mojibake(e.get(key, ""))
        result.append(e)
    return result


def extract_wer_driver_correlations(events: list[dict[str, Any]]) -> list[str]:
    """Extract WER-reported possibly related drivers without treating it as independent proof."""
    found: list[str] = []
    seen: set[str] = set()
    for e in events or []:
        if str(e.get("ProviderName", "")) != "Microsoft-Windows-WER-SystemErrorReporting":
            continue
        msg = str(e.get("Message", "") or "")
        patterns = [
            r"(?i)(?:Возможно\s+связанный\s+драйвер|Possibly\s+related\s+driver|Possibly\s+associated\s+driver)\s*:\s*([^\s,;]+\.sys)",
            r"(?i)\b([A-Za-z0-9_.-]+\.sys)\b",
        ]
        for pat in patterns:
            m = re.search(pat, msg)
            if m:
                drv = Path(m.group(1)).name.lower()
                if drv not in seen:
                    seen.add(drv)
                    found.append(drv)
                break
    return found


def classify_event_timeline(events: list[dict[str, Any]], crash_time: dt.datetime) -> list[dict[str, Any]]:
    """Add AI-friendly temporal phase, delta and semantic role to Event Log rows."""
    crash_time = crash_time.astimezone(dt.timezone.utc)
    result: list[dict[str, Any]] = []
    for e0 in normalize_windows_events(events):
        e = dict(e0)
        try:
            when = parse_iso(str(e.get("TimeCreated", "")))
            delta = (when - crash_time).total_seconds()
        except Exception:
            delta = None
        provider = str(e.get("ProviderName", ""))
        event_id = int(e.get("Id") or 0)
        msg = str(e.get("Message", "") or "")
        role = "other"
        if provider == "volmgr" and event_id in {161, 162}:
            role = "dump_write"
        elif provider == "Microsoft-Windows-Kernel-Power" and event_id == 41:
            role = "unexpected_reboot"
        elif provider == "Microsoft-Windows-WER-SystemErrorReporting" and event_id in {1001, 1019}:
            role = "wer_crash_report" if event_id == 1001 else "wer_driver_correlation"
        elif provider == "Microsoft-Windows-WHEA-Logger":
            role = "hardware_whea"
        elif provider == "Display" or event_id == 4101:
            role = "display_driver"
        elif provider == "Service Control Manager":
            role = "service_state"
        elif "driver" in msg.lower() or "драйвер" in msg.lower():
            role = "driver_related"

        if delta is None:
            phase = "UNKNOWN"
        elif delta < -30:
            phase = "PRE_CRASH"
        elif delta <= 30:
            phase = "CRASH_WINDOW"
        elif role in {"dump_write", "unexpected_reboot", "wer_crash_report", "wer_driver_correlation"}:
            phase = "REBOOT_DUMP"
        else:
            phase = "POST_CRASH"
        e["delta_from_crash_seconds"] = round(delta, 3) if delta is not None else None
        e["phase"] = phase
        e["role"] = role
        result.append(e)
    result.sort(key=lambda e: str(e.get("TimeCreated", "")))
    return result


def summarize_dump_health(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize volmgr/WER dump creation health into a compact diagnostic object."""
    vol161 = [e for e in events if str(e.get("ProviderName")) == "volmgr" and int(e.get("Id") or 0) == 161]
    vol162 = [e for e in events if str(e.get("ProviderName")) == "volmgr" and int(e.get("Id") or 0) == 162]
    wer1001 = [e for e in events if str(e.get("ProviderName")) == "Microsoft-Windows-WER-SystemErrorReporting" and int(e.get("Id") or 0) == 1001]
    dump_paths: list[str] = []
    for e in wer1001:
        msg = str(e.get("Message", "") or "")
        for pat in (r"(?i)(?:Дамп памяти сохранен в|Dump was saved in|dump file was saved in)\s*:\s*([^\r\n]+?\.dmp)", r"(?i)\b([A-Z]:\\[^\r\n]+?\.dmp)\b"):
            m = re.search(pat, msg)
            if m:
                val = m.group(1).strip().rstrip(". ")
                if val not in dump_paths:
                    dump_paths.append(val)
                break
    if vol162 and vol161:
        status = "success_after_warning"
        summary = "Windows сначала зарегистрировала ошибку записи dump (volmgr 161), затем успешное создание dump (volmgr 162)."
    elif vol162:
        status = "success"
        summary = "Windows зарегистрировала успешное создание dump (volmgr 162)."
    elif vol161:
        status = "failed_or_incomplete"
        summary = "Windows зарегистрировала ошибку создания dump (volmgr 161) без последующего подтверждения volmgr 162 в выбранном окне."
    elif wer1001:
        status = "wer_reported_dump"
        summary = "WER сообщил о сохранённом dump, но события volmgr 161/162 в выбранном окне не найдены."
    else:
        status = "unknown"
        summary = "По Event Log нельзя подтвердить состояние записи dump."
    progress = []
    for e in vol161:
        m = re.search(r"(?i)BugCheckProgress\s+was:\s*(0x[0-9A-Fa-f]+)", str(e.get("Message", "")))
        if m:
            progress.append(m.group(1))
    return {
        "status": status,
        "summary": summary,
        "volmgr_161_count": len(vol161),
        "volmgr_162_count": len(vol162),
        "wer_1001_count": len(wer1001),
        "bugcheck_progress_values": progress,
        "reported_dump_paths": dump_paths,
    }


def make_crash_fingerprint(parsed: dict[str, Any]) -> str:
    """Stable fingerprint for deduplicating MEMORY.DMP + Minidump of one BSOD."""
    crash_time = str(parsed.get("crash_time_utc") or "")
    try:
        t = parse_iso(crash_time)
        # Milliseconds can differ slightly across dump variants; round to whole second.
        crash_time = t.replace(microsecond=0).isoformat()
    except Exception:
        pass
    params = [str(x or "").lower().replace("0x", "") for x in (parsed.get("bugcheck_parameters") or [])]
    payload = {
        "time": crash_time,
        "bugcheck": str(parsed.get("bugcheck_code") or "").lower(),
        "params": params,
        "failure_id_hash": str(parsed.get("failure_id_hash") or "").lower(),
        "failure_bucket": str(parsed.get("failure_bucket_id") or "").lower(),
    }
    if not any(payload.values()):
        return ""
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8", "ignore")
    return hashlib.sha256(raw).hexdigest()[:24]



def system_runtime_snapshot() -> dict[str, Any]:
    """Very lightweight runtime context for the pre-crash ring buffer."""
    if not IS_WINDOWS:
        return {}
    result: dict[str, Any] = {}
    try:
        result["uptime_seconds"] = round(ctypes.windll.kernel32.GetTickCount64() / 1000.0, 3)
    except Exception:
        pass
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        mem = MEMORYSTATUSEX(); mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
            result["memory_load_percent"] = int(mem.dwMemoryLoad)
            result["memory_total_mb"] = round(mem.ullTotalPhys / (1024 * 1024), 1)
            result["memory_available_mb"] = round(mem.ullAvailPhys / (1024 * 1024), 1)
    except Exception:
        pass
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if hwnd:
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            title_len = user32.GetWindowTextLengthW(hwnd)
            title_buf = ctypes.create_unicode_buffer(max(1, title_len + 1))
            user32.GetWindowTextW(hwnd, title_buf, len(title_buf))
            proc_path = ""
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            hproc = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
            if hproc:
                try:
                    size = ctypes.c_ulong(32768)
                    buf = ctypes.create_unicode_buffer(size.value)
                    if ctypes.windll.kernel32.QueryFullProcessImageNameW(hproc, 0, buf, ctypes.byref(size)):
                        proc_path = buf.value
                finally:
                    ctypes.windll.kernel32.CloseHandle(hproc)
            result["foreground"] = {
                "pid": int(pid.value), "title": title_buf.value,
                "path": proc_path, "process": Path(proc_path).name if proc_path else "",
            }
    except Exception:
        pass
    return result


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Relaunch the current app elevated. Returns True if elevation was started."""
    if not IS_WINDOWS or is_admin():
        return False
    if getattr(sys, "frozen", False):
        executable = sys.executable
        args = sys.argv[1:]
    else:
        executable = sys.executable
        args = [str(Path(__file__).resolve()), *sys.argv[1:]]
    params = subprocess.list2cmdline(args)
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
        return int(rc) > 32
    except Exception:
        return False


def _autorun_action() -> tuple[str, str]:
    """Return executable and argument string for Task Scheduler."""
    if getattr(sys, "frozen", False):
        return sys.executable, "--startup"
    script = Path(__file__).resolve()
    py = Path(sys.executable)
    pythonw = py.with_name("pythonw.exe") if py.name.lower() == "python.exe" else py
    if not pythonw.exists():
        pythonw = py
    return str(pythonw), subprocess.list2cmdline([str(script), "--startup"])


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_powershell_quiet(script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, errors="replace", timeout=timeout, creationflags=flags
    )


def _legacy_run_enabled() -> bool:
    if not IS_WINDOWS:
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, AUTORUN_VALUE)
            return bool(val)
    except OSError:
        return False


def _remove_legacy_run() -> None:
    if not IS_WINDOWS:
        return
    import winreg
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, AUTORUN_VALUE)
            except FileNotFoundError:
                pass
    except OSError:
        pass


def is_autorun_enabled() -> bool:
    if not IS_WINDOWS:
        return False
    script = f"if (Get-ScheduledTask -TaskName {_ps_quote(AUTORUN_TASK)} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
    try:
        cp = _run_powershell_quiet(script)
        if cp.returncode == 0:
            return True
    except Exception:
        pass
    return _legacy_run_enabled()


def set_autorun(enabled: bool) -> None:
    """Use Task Scheduler with highest privileges so protected crash dumps are readable after logon."""
    if not IS_WINDOWS:
        return
    if enabled:
        exe, args = _autorun_action()
        script = f'''
$ErrorActionPreference = 'Stop'
$taskName = {_ps_quote(AUTORUN_TASK)}
$action = New-ScheduledTaskAction -Execute {_ps_quote(exe)} -Argument {_ps_quote(args)}
$trigger = New-ScheduledTaskTrigger -AtLogOn -User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
'''
        cp = _run_powershell_quiet(script)
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or "Не удалось создать задачу автозапуска")
        _remove_legacy_run()
    else:
        script = f"Unregister-ScheduledTask -TaskName {_ps_quote(AUTORUN_TASK)} -Confirm:$false -ErrorAction SilentlyContinue"
        cp = _run_powershell_quiet(script)
        if cp.returncode not in (0, 1):
            raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or "Не удалось удалить задачу автозапуска")
        _remove_legacy_run()


def self_test() -> int:
    sample = r'''
SYSTEM_SERVICE_EXCEPTION (3b)
Debug session time: Fri Aug  7 20:42:09.004 2026 (UTC + 3:00)
BUGCHECK_CODE:  3b
BUGCHECK_P1: c0000005
BUGCHECK_P2: fffff80743101e98
BUGCHECK_P3: fffff48a15c3e9f0
BUGCHECK_P4: 0
EXCEPTION_CODE: (NTSTATUS) 0xc0000005
PROCESS_NAME:  MaonoAiService
SYMBOL_NAME:  MaonoAiDriver+1234
MODULE_NAME: MaonoAiDriver
IMAGE_NAME:  MaonoAiDriver.sys
FAILURE_BUCKET_ID:  AV_MaonoAiDriver!unknown_function
FAILURE_ID_HASH: {dcd4afef-a032-391a-3f20-cfc765a99716}
Probably caused by : MaonoAiDriver.sys ( MaonoAiDriver+0x1234 )
STACK_TEXT:
fffff foo : MaonoAiDriver+0x1234

LOADED_MODULE_NOISE: pwdrvio.sys msio64.sys
'''
    parsed = DumpParser().parse(sample)
    assert parsed["bugcheck_code"] == "3b", parsed
    assert parsed["image_name"].lower() == "maonoaidriver.sys", parsed
    assert parsed["crash_time_utc"].startswith("2026-08-07T17:42:09.004"), parsed["crash_time_utc"]
    assert parsed["exception_code"].lower().replace("0x", "") == "c0000005", parsed["exception_code"]
    assert parsed["bugcheck_parameters"][0].lower() == "c0000005", parsed["bugcheck_parameters"]
    assert parsed["crash_fingerprint"], parsed
    assert DumpParser().candidate_names(parsed) == ["maonoaidriver.sys"], DumpParser().candidate_names(parsed)

    legacy_events = [
        {"TimeCreated":"2026-08-07T17:48:26.1158908Z","ProviderName":"volmgr","Id":161,"LevelDisplayName":"ЋиЁЎЄ ","Message":"ЌҐ г¤ «®бм б®§¤ вм д ©« ¤ ¬Ї  Ё§-§  ®иЁЎЄЁ ЇаЁ б®§¤ ­ЁЁ ¤ ¬Ї . BugCheckProgress was: 0x02120004"},
        {"TimeCreated":"2026-08-07T17:48:26.1229014Z","ProviderName":"volmgr","Id":162,"LevelDisplayName":"ЋиЁЎЄ ","Message":"” ©« ¤ ¬Ї  гбЇҐи­® б®§¤ ­."},
        {"TimeCreated":"2026-08-07T17:48:41.0770694Z","ProviderName":"Microsoft-Windows-WER-SystemErrorReporting","Id":1019,"LevelDisplayName":"ЋиЁЎЄ ","Message":"Љ®¬ЇмовҐа ЇҐаҐ§ Јаг§Ё«бп Ї®б«Ґ Їа®ўҐаЄЁ ®иЁЎ®Є.  ‚®§¬®¦­® бўп§ ­­л© ¤а ©ўҐа: MaonoAiDriver.sys."},
    ]
    timeline = classify_event_timeline(legacy_events, parse_iso(parsed["crash_time_utc"]))
    assert "Не удалось" in timeline[0]["Message"], timeline[0]
    assert timeline[0]["phase"] == "REBOOT_DUMP", timeline[0]
    assert extract_wer_driver_correlations(timeline) == ["maonoaidriver.sys"], timeline
    health = summarize_dump_health(timeline)
    assert health["status"] == "success_after_warning", health
    parsed["wer_driver_correlations"] = extract_wer_driver_correlations(timeline)
    with tempfile.TemporaryDirectory(prefix="bsod_inv_test_") as test_dir:
        td_root = Path(test_dir)
        tmp = td_root / "history.sqlite3"
        db = HistoryDB(tmp)

        inv = {
            "maonoaidriver.sys": DriverInfo(
                name="MaonoAiDriver",
                path=r"C:\Windows\System32\drivers\MaonoAiDriver.sys",
                company="Shenzhen Maono Technology Co., Ltd.",
                provider="MAONO",
                signed=True,
                signer="CN=Microsoft Windows Hardware Compatibility Publisher",
            )
        }
        suspects = ScoringEngine(db).score(parsed, inv, crash_fingerprint=parsed["crash_fingerprint"])
        assert suspects and suspects[0].driver == "maonoaidriver.sys", suspects
        assert all(s.driver not in {"pwdrvio.sys", "msio64.sys"} for s in suspects), suspects
        assert suspects[0].vendor_type == "third_party", suspects[0]
        assert any("WHQL" in e for e in suspects[0].evidence), suspects[0].evidence
        assert any("WER" in e for e in suspects[0].evidence), suspects[0].evidence
        assert DriverInfo(name="x", provider="Microsoft Corporation").microsoft is True
        assert DriverInfo(name="x", provider="MAONO", signer="CN=Microsoft Windows Hardware Compatibility Publisher").microsoft is False

        reports_dir = td_root / "reports"
        reports_dir.mkdir()
        base = CrashReport(
            dump_path="a.dmp", dump_name="a.dmp", analyzed_at=utc_now(), dump_mtime=parsed["crash_time_utc"],
            sha256="a"*64, crash_time_utc=parsed["crash_time_utc"], bugcheck_code="3b", bugcheck_name="SYSTEM_SERVICE_EXCEPTION",
            image_name="MaonoAiDriver.sys", module_name="MaonoAiDriver", faulting_module="maonoaidriver.sys",
            failure_bucket_id="AV_MaonoAiDriver!unknown_function", failure_id_hash=parsed["failure_id_hash"],
            bugcheck_parameters=parsed["bugcheck_parameters"], crash_fingerprint=parsed["crash_fingerprint"],
            stack_modules=["maonoaidriver.sys"], suspects=suspects,
            debugger_found=True, raw_debugger_output=sample, event_timeline=timeline,
            wer_driver_correlations=["maonoaidriver.sys"], dump_health=health,
        )

        # Two fingerprinted dump files of one crash must count as ONE historical incident.
        for idx, sha in enumerate(("a"*64, "b"*64), 1):
            r = CrashReport(**{**base.to_dict(), "dump_path": f"dup{idx}.dmp", "dump_name": f"dup{idx}.dmp", "sha256": sha})
            # Restore nested dataclass suspects after dict expansion.
            r.suspects = suspects
            jp = reports_dir / f"r{idx}.json"
            hp = reports_dir / f"r{idx}.html"
            jp.write_text(json.dumps(r.to_dict(), ensure_ascii=False), encoding="utf-8")
            hp.write_text("x", encoding="utf-8")
            db.save_crash(r, jp, hp)

        # Simulate a legacy MEMORY.DMP row from an old version: same 0x3B/MAONO evidence
        # but no crash fingerprint and no reliable crash time. It must remain visible in
        # history while being excluded from repeat scoring.
        legacy = CrashReport(
            dump_path="MEMORY.DMP", dump_name="MEMORY.DMP", analyzed_at=utc_now(), dump_mtime=utc_now(),
            sha256="c"*64, crash_time_utc="", bugcheck_code="3b", bugcheck_name="SYSTEM_SERVICE_EXCEPTION",
            image_name="MaonoAiDriver.sys", module_name="MaonoAiDriver", faulting_module="maonoaidriver.sys",
            failure_bucket_id="AV_MaonoAiDriver!unknown_function", crash_fingerprint="",
            stack_modules=["maonoaidriver.sys"], suspects=suspects,
        )
        legacy_json = reports_dir / "legacy.json"
        legacy_html = reports_dir / "legacy.html"
        legacy_json.write_text(json.dumps(legacy.to_dict(), ensure_ascii=False), encoding="utf-8")
        legacy_html.write_text("x", encoding="utf-8")
        db.save_crash(legacy, legacy_json, legacy_html)

        details = db.previous_driver_strong_hit_details("maonoaidriver.sys")
        assert len(details) == 1, details
        legacy_state = db.history_state("c"*64)
        assert legacy_state.get("status") == "legacy_ambiguous_duplicate", legacy_state
        assert db.last_repair_stats.get("legacy_ambiguous_duplicate", 0) >= 1, db.last_repair_stats

        quality = telemetry_quality(base)
        assert quality["telemetry_score"] > 0 and quality["telemetry_level"] in {"MEDIUM", "HIGH", "VERY HIGH"}, quality
        print(
            "SELF TEST OK",
            suspects[0],
            "fingerprint", parsed["crash_fingerprint"],
            "dedupe", len(details),
            "legacy", legacy_state.get("status"),
            "telemetry", quality["telemetry_score"], quality["telemetry_level"],
        )
        return 0



def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    if not IS_WINDOWS:
        print("BSOD Investigator is a Windows 10/11 application.")
        return 2
    if not is_admin():
        if relaunch_as_admin():
            return 0
        try:
            import tkinter.messagebox as mb
            mb.showerror(APP_NAME, "Для чтения C:\\Windows\\Minidump нужны права администратора. Разрешите запрос UAC при запуске программы.")
        except Exception:
            pass
        return 5
    try:
        launch_gui()
        return 0
    except Exception as e:
        err = traceback.format_exc()
        log_folder = None
        try:
            cfg = Config.load()
            fatal_tools = WindowsTools(cfg)
            fatal_logger = ProblemLogger(cfg, fatal_tools, HistoryDB())
            log_folder = fatal_logger.capture_exception(e, "fatal_main")
        except Exception:
            try:
                (LOG_DIR / "fatal.log").write_text(err, encoding="utf-8")
            except Exception:
                pass
        try:
            import tkinter.messagebox as mb
            extra = f"\n\nAI-лог: {log_folder}" if log_folder else ""
            mb.showerror(APP_NAME, f"{e}{extra}")
        except Exception:
            print(err)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
