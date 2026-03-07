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

Analyzers live in `Analyzers/` and subclass `Analyzer` from `structure.py`. Registered via `Analyzers/__init__.py` (`__all__` list). Discovery via `Analyzer.__subclasses__()`.

Each analyzer declares:
- `compatible_mime_types` — MIME types it handles (primary dispatch)
- `can_handle(data, mime_type)` — optional classmethod for content-based probing
- `pip_dependencies` / `system_dependencies` — for `--check` validation
- `analysis()` — populates `self.reports` dict with `Report` objects and `self.childitems` with child `Structure` objects

Current analyzers: Email, PlainText, Zip, SevenZip, HTML, PDF, Msg, Mbox, Docx, OfficeRelationship, OfficeXML, VBAProject.

To add a new analyzer: copy `Analyzers/TEMPLATE_ANALYZER.py`, set `compatible_mime_types`, implement `analysis()`, add the class name to `__all__` in `Analyzers/__init__.py`.

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

- **`pyproject.toml`** is canonical (PEP 517). Optional extras: `[dev]`, `[yara]`, `[office]`, `[web]`.
- Core dependencies: `charset-normalizer>=3.0`, `python-dateutil>=2.8`. Optional: `rich`, `pyzipper`, `py7zr`, `lingua-language-detector`, `beautifulsoup4`, `pillow`, `python-magic`.
- `libmagic` system library needed for `python-magic` (e.g., `apt-get install libmagic1` on Debian/Ubuntu).

## Standalone Tools (in Analyzers/)

Utility scripts not part of the analyzer pipeline:
- `Analyzers/archive_hash.py` — hash all files within an archive (requires `libarchive-c`)
- `Analyzers/exif.py` — extract EXIF data from images (requires `Pillow`)

Legacy CLI scripts in repo root (use `eml.py` directly):
- `mailfrom.py`, `mailheader.py`, `mailattachments.py`, `maildump.py`
- `getallfromfields.py`, `mail2timeline.py`, `mailexport.py`

## Key Details

- Python 3.8+ required.
- Logging goes to stderr (not to file) unless debug mode. Configured via `Utils/logger.py`.
- `Structure` objects are cached by content hash — duplicate attachments are analyzed only once.
- The `NUL` device file that sometimes appears in `git status` on Windows is in `.gitignore`.
