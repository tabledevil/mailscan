# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MATT (Mail Analysis and Triage Tool) is a modular file analysis tool for dissecting emails and various file types. It recursively analyzes files, extracts nested content (attachments, archive contents), and produces structured reports with severity-rated findings.

## Commands

```bash
# Install
pip install -e .                     # core, editable install
pip install -e ".[dev]"              # development extras (pytest, etc.)
pip install -e ".[all]"              # all optional features

# Run analysis
python matt.py <file1> <file2> ...
python matt.py --format json <file>      # json output (also: text, rich, markdown, html)
python matt.py --network-policy offline <file>   # no outbound connections
python matt.py -x <file>                 # extract attachments to ./extract/
python matt.py -d <file>                 # debug mode
python matt.py --check                   # verify all analyzer dependencies
```

## Architecture

The core analysis pipeline is: `matt.py` → `Structure` → `Analyzer` → `Report` → `Renderer`

- **`matt.py`** — CLI entry point. Parses args, creates `Structure` objects, dispatches to renderers.
- **`structure.py`** — Contains `Structure` (central data container), `Analyzer` (base class), `Report`, and the `Severity` enum (INFO/LOW/MEDIUM/HIGH/CRITICAL). `Structure` objects are cached by SHA-256 hash. The `from Analyzers import *` at the bottom must come after the `Analyzer` class definition since analyzers import from `structure`.
- **`eml.py`** — `Eml` class wraps Python's `email` module with decoding, hashing, and `ReceivedParser` for parsing mail relay headers.
- **`renderers/`** — Output format system. `renderers/__init__.py` defines base `Renderer` class and format registry. Individual renderers: `text_renderer.py`, `rich_renderer.py`, `json_renderer.py`, `markdown_renderer.py`, `html_renderer.py`.
- **`Config/config.py`** — Global `flags` dataclass (debug, max_analysis_depth, max_file_size, max_compression_ratio, network_policy, cache_path, yara_rules_dir).
- **`Config/passwords.py`** — Default password list for encrypted archive analysis.
- **`Utils/filetype.py`** — MIME detection with provider chain (python-magic → file command → magika → stdlib fallback).
- **`Utils/ioc_extractor.py`** — Extract IOCs (IPs, URLs, emails, domains, MD5/SHA1/SHA256 hashes, candidate passwords) from text.
- **`Utils/password_broker.py`** — Event-driven cross-analyzer password coordination. Analyzers register pending encrypted files; the broker retries them when passwords are discovered by other analyzers.
- **`Utils/received_parser.py`** — Parse `Received:` headers, supports 20+ server formats, extracts relay chain and timestamps.
- **`Utils/logger.py`** — Named logger `matt`, suppresses 3rd-party library noise.
- **`Utils/temp_manager.py`** — Temp file lifecycle management with suffix/prefix params and cleanup.

## Analyzer System

Analyzers live in `Analyzers/` and subclass `Analyzer` from `structure.py`. Registered via the `analyzers_list` in `Analyzers/__init__.py`. Module discovery is by string-name lookup; subclass discovery via `Analyzer.__subclasses__()`. The package's `__all__` is built dynamically from successfully imported modules.

Each analyzer declares:
- `compatible_mime_types` — MIME types it handles (primary dispatch)
- `can_handle(struct)` — optional classmethod for content-based probing on ambiguous MIME types (typically `application/octet-stream` or `text/plain`)
- `specificity` — primary/contributor ranking (5=generic, 10=container, 15=semi, 20=format, 25=sub-analyzer)
- `pip_dependencies` / `system_dependencies` — for `--check` validation
- `analysis()` — populates `self.reports` dict with `Report` objects and `self.childitems` with child `Structure` objects

Current analyzers: `EmailAnalyzer`, `PlainTextAnalyzer`, `ZipAnalyzer`, `SevenZipAnalyzer`, `HTMLAnalyzer`, `PDFAnalyzer`, `MsgAnalyzer`, `MboxAnalyzer`, `OfficeDocumentAnalyzer` (handles DOCX/XLSX/PPTX), `OLEOfficeAnalyzer` (legacy .doc/.xls/.ppt), `OfficeRelationshipAnalyzer`, `OfficeXMLAnalyzer`, `VBAProjectAnalyzer`, `RTFAnalyzer`, `ImageAnalyzer`, `QRAnalyzer`, `ICSAnalyzer`, `RARAnalyzer`, `ScriptAnalyzer`.

To add a new analyzer: copy `Analyzers/TEMPLATE_ANALYZER.py`, set `compatible_mime_types`, implement `analysis()`, add the module name to `analyzers_list` in `Analyzers/__init__.py`.

## Severity System

Reports carry a `Severity` level. The `Analyzer` base class aggregates severity across all reports and child items. CLI and renderers use severity to color/prioritize output.

```python
from structure import Severity
self.reports['finding'] = Report("Macro detected", severity=Severity.CRITICAL)
```

## Password Broker

For encrypted archives where the password isn't known at analysis time:

```python
from Utils.password_broker import PasswordBroker
PasswordBroker.register_pending(struct=self.struct, description="...",
    try_password_cb=self._retry_with_password, on_unlock=self._on_unlocked)
```

Passwords discovered by other analyzers (e.g., PlainTextAnalyzer finding "password: infected" in an email body) are published to the broker, which retries pending items.

## Packaging

- **`pyproject.toml`** is canonical (PEP 517, `setuptools.build_meta` backend). Optional extras: `office`, `pdf`, `html`, `msg`, `7z`, `lang`, `mime`, `tui`, `fuzzy`, `fuzzy-ssdeep`, `yara`, `js`, `qr`, `rar`, `dev`, `all`.
- Core dependencies: `charset-normalizer>=3.0`, `python-dateutil>=2.8`, `pytz`, `rich>=13.0`.
- System dependencies (per-extra): `libmagic` (mime), `libzbar0` + `zbar-tools` (qr), `poppler-utils` (pdf preview), `unrar` (rar), `box-js` via npm (js dynamic).

## Standalone Tools (in Analyzers/)

Utility scripts not part of the analyzer pipeline:
- `Analyzers/archive_hash.py` — hash all files within an archive (requires `libarchive-c`)
- `Analyzers/exif.py` — extract EXIF data from images (requires `Pillow`)

Legacy CLI scripts in repo root (use `eml.py` directly):
- `mailfrom.py`, `mailheader.py`, `mailattachments.py`, `maildump.py`
- `getallfromfields.py`, `mail2timeline.py`, `mailexport.py`

## Key Details

- Python 3.10+ required (per `pyproject.toml`).
- Logging goes to stderr (not to file) unless debug mode. Configured via `Utils/logger.py`.
- `Structure` objects are cached by `(sha256, basename, mime_type)` — duplicate attachments with the same name+type collapse, but the same bytes under different filenames don't mask filename-based detections.
- Multi-dispatch: every Analyzer that `can_analyze` runs against the Structure; highest-`specificity` is primary, others are contributors.
- Root-level post-pass builds `iocs_aggregate` (defanged) and `capability_hints` (skipped optional checks).
- The `NUL` device file that sometimes appears in `git status` on Windows is in `.gitignore`.

## Sandbox safety (dynamic JS)

`Utils/js_tools.py` (box-js wrapper) refuses to run unless one of:
- `MATT_IN_DOCKER=1` (set automatically by the MATT image)
- `MATT_ALLOW_HOST_SANDBOX=1` (analyst opt-in on an isolated host)

This prevents accidentally detonating attacker-controlled JS through
a host install of box-js. Static analysis is always available.
