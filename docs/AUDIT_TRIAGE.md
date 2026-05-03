# Audit Fleet Triage — 2026-05-03

24-agent fleet (6 roles × codex+gemini × 2 runs). Gemini hit free-tier
rate limits on 9 of 12 runs; codex covered all 12. Effective corpus:
**16 audits**.

Each finding below has been **validated against the actual code** to
weed out hallucinations. Convergence (multiple independent audits
flagging the same item) is noted in the `confirmed_by` column.

Action verdicts:
- **FIX_NOW** — real, exploitable / correctness bug, ship a fix + test.
- **FIX_SOON** — real but not urgent.
- **FIX_NEXT_SPRINT** — valid, larger refactor; track in TODO_NEXT.
- **DEFER** — valid but low priority.
- **REJECTED** — hallucinated, misread, or invalid.

## CRITICAL — security & memory exhaustion

| # | Finding | File:Line | confirmed_by | Action |
|---|---------|-----------|--------------|--------|
| 1 | box-js detonation runs on host without MATT_IN_DOCKER gate | `Utils/js_tools.py:20-47`, `Analyzers/ScriptAnalyzer.py:dynamic_analysis` | codex_security_1, _2 | FIX_NOW |
| 2 | /ObjStm decompression unbounded; concatenates back onto rawdata | `Utils/pdf_policy.py:319-371` | codex_perf_1, gemini_perf_1 | FIX_NOW |
| 3 | PDF /JS, /EF, /XObject, /FontFile* `get_data()` no per-stream cap | `Analyzers/PDFAnalyzer.py:96, 219, 450, 484` | codex_security_1, _2 | FIX_NOW |

## HIGH — correctness bugs in detection

| # | Finding | File:Line | confirmed_by | Action |
|---|---------|-----------|--------------|--------|
| 4 | SHA-256 cache returns existing Structure regardless of filename — masks dangerous-ext detections under benign-then-dangerous order | `structure.py:594-618` | codex_security_1, _2 | FIX_NOW |
| 5 | DDE multi-run instrText evasion — current regex matches single element only | `Analyzers/OfficeDocumentAnalyzer.py:_dde_re_instrtext` | codex_test_cov_1, _2; gemini_test_cov_2 | FIX_NOW |
| 6 | pdf_policy module docstring claims `(...)` literal strings are skipped; `_strip_pdf_noise` doesn't | `Utils/pdf_policy.py:16-18 vs 273-280` | codex_test_cov_1, _2; codex_detect_corr_1, _2; codex_doc_1, _2; gemini_doc_2 | FIX_NOW |
| 7 | Indirect-reference forms (`/AcroForm 5 0 R`) invisible to scanner | `Utils/pdf_policy.py:347-351` | codex_detect_corr_1, _2 | FIX_NOW |
| 8 | Filter array — only first filter captured; `/Filter [/FlateDecode /JBIG2Decode]` skips JBIG2 | `Utils/pdf_policy.py:_RE_FILTER` | codex_detect_corr_2 | FIX_NOW |
| 9 | JS-at-opening uses 2KB byte proximity — escalates unrelated actions | `Utils/pdf_policy.py:399-414` | codex_detect_corr_2 | FIX_SOON |
| 10 | CVE-2009-0658 mislabel — `customDictionaryOpen` is CVE-2009-1493 | `Utils/js_analysis.py:551` | codex_detect_corr_1, _2 | FIX_NOW |
| 11 | `util.printf` regex too narrow (`%D` only); misses `%f`, `%s` exploit shapes | `Utils/js_analysis.py:539-541` | codex_detect_corr_2 | FIX_NOW |
| 12 | `util.printf` regex too broad — fires on benign `util.printf("%d", n)` | `Utils/js_analysis.py:539-541` | codex_detect_corr_1 | FIX_NOW |
| 13 | `getAnnots` CVE detection fires on normal API usage; double-fires CRITICAL+HIGH | `Utils/js_analysis.py:549-550, 583-584` | codex_detect_corr_1, _2 | FIX_NOW |
| 14 | `exportDataObject` overbroad — needs `nLaunch>0` gate | `Utils/js_analysis.py:574-577` | codex_detect_corr_1 | FIX_NOW |
| 15 | `submitForm` misses `{cURL: "..."}` object form | `Utils/js_analysis.py:584-588` | codex_detect_corr_1 | FIX_SOON |
| 16 | Threat patterns scan comments + string literals — `// powershell -enc` fires CRITICAL | `Analyzers/ScriptAnalyzer.py:_detect_threats`, `Utils/js_analysis.py:detect_threat_patterns` | codex_detect_corr_2 | FIX_SOON |
| 17 | `Collab.collectEmailInfo` description wrong — buffer overflow, not "sandbox escape" | `Utils/js_analysis.py:543-544` | codex_detect_corr_1 | FIX_NOW |

## HIGH — test integrity (tests don't actually test what they claim)

| # | Finding | File:Line | confirmed_by | Action |
|---|---------|-----------|--------------|--------|
| 18 | `test_dedup_repeated_js_references` doesn't create duplicate references | `tests/test_pdf_js_extraction.py:106-119` | codex_test_cov_1, _2; codex_detect_corr_1 | FIX_NOW |
| 19 | `test_dedup_attachments_by_content_hash` claims FileAttachment but uses Names+/AF | `tests/test_pdf_completeness.py:263-280` | codex_test_cov_1, _2 | FIX_NOW |
| 20 | Portfolio + AF tests don't verify extracted file content bytes | `tests/test_pdf_completeness.py:108-117 et al` | gemini_test_cov_2 | FIX_NOW |
| 21 | `test_pdf_resources` only covers DCT JPEG — `_render_image_xobject` reconstruction path untested | `tests/test_pdf_resources.py` | codex_test_cov_2 | FIX_SOON |
| 22 | DDE split-instrText not pinned (links to #5 above) | `tests/test_office_dde.py` | codex_test_cov_1, _2; gemini_test_cov_2 | FIX_NOW (with #5) |
| 23 | PDF policy literal-string FP not pinned (links to #6) | `tests/test_pdf_policy.py` | codex_test_cov_1, _2 | FIX_NOW (with #6) |
| 24 | `test_no_collision_clobber` only counts files, doesn't check content preservation | `tests/test_extraction_layout.py:102-113` | codex_test_cov_2; gemini_test_cov_2 | FIX_NOW |
| 25 | `test_observe_persists_first_seen_and_last_seen` only does one observe call | `tests/test_relay_cache.py:46-51` | gemini_test_cov_2 | FIX_SOON |
| 26 | `test_embedded_js_report_emitted_on_root` asserts `"1" in rep.text` — brittle | `tests/test_pdf_js_extraction.py:82-85` | gemini_test_cov_2 | FIX_NOW |

## HIGH — perf

| # | Finding | File:Line | confirmed_by | Action |
|---|---------|-----------|--------------|--------|
| 27 | IOC aggregation: rescans cached `_ioc_result` AND text; `IOCResult.merge()` re-dedups whole list per merge | `structure.py:711-725`, `Utils/ioc_extractor.py:183-190` | codex_perf_1, _2 | FIX_SOON |
| 28 | `detect_incremental_updates` materializes every PDF object body; regex compiled per-call | `Analyzers/PDFAnalyzer.py:594-606` | codex_perf_1, _2 | FIX_SOON |
| 29 | exiftool spawned per Structure (no MIME gate, no size cap, no cache) | `structure.py:121-124, 193-202` | codex_perf_1 | FIX_SOON |
| 30 | ScriptAnalyzer runs `detect_threat_patterns` 3x on deobf path | `Analyzers/ScriptAnalyzer.py:201, 429, 446` | codex_perf_2 | FIX_SOON |
| 31 | PDF text extraction `text += ...` in loop = quadratic | `Analyzers/PDFAnalyzer.py:59-64` | codex_perf_1 | FIX_SOON |
| 32 | JS-at-opening `O(actions × anchors)` proximity check | `Utils/pdf_policy.py:399-414` | codex_perf_1 | FIX_SOON |

## HIGH — security (other)

| # | Finding | File:Line | confirmed_by | Action |
|---|---------|-----------|--------------|--------|
| 33 | Archive bombs — member-count attack passes through size-only gate | `Analyzers/ZipAnalyzer.py`, `SevenZipAnalyzer.py`, `RARAnalyzer.py` | codex_security_1 | FIX_SOON |
| 34 | PDF Poppler preview: no timeout, no DPI cap, runs on every PDF | `Analyzers/PDFAnalyzer.py:generate_preview` | codex_security_1, _2 | FIX_NOW |
| 35 | Renderer triggers `enrich_iocs` (VT lookups) at render-time on attacker IOCs | `renderers/__init__.py:_collect_ioc_summary`, `Utils/advanced_analysis.py:enrich_iocs` | codex_security_2 | FIX_NOW |
| 36 | Recovered passwords printed cleartext in reports | `Analyzers/PlainTextAnalyzer.py:248`, `structure.py:752`, archive analyzers | codex_security_2 | FIX_SOON |

## MEDIUM — docs / packaging drift

| # | Finding | File:Line | confirmed_by | Action |
|---|---------|-----------|--------------|--------|
| 37 | README describes `Analyzer.get_analyzer(mimetype)` single-dispatch — code is multi-dispatch via `run_all_analyzers` | `README.md:13-18` | codex_doc_1, _2; gemini_doc_1 | FIX_NOW |
| 38 | README claims "legacy setup.py build" — pyproject.toml uses `setuptools.build_meta` | `README.md:93` | codex_doc_1, _2; gemini_doc_1 | FIX_NOW |
| 39 | README's `pip install .[all]` fails in zsh (needs quotes) | `README.md:97-99` | codex_doc_1 | FIX_NOW |
| 40 | RAR support: `RARAnalyzer.extra="rar"` so `--check` says `pip install .[rar]` but no `rar` extra exists | `Analyzers/RARAnalyzer.py:30-32`, `pyproject.toml` | codex_doc_1, _2 | FIX_NOW |
| 41 | CLAUDE.md says Python 3.8+, lists [web] extra (doesn't exist), missing 7 analyzers, lists `from Analyzers import *` at wrong location | `CLAUDE.md` | codex_doc_1, _2; gemini_doc_1, _2 | FIX_NOW |
| 42 | TODO_E2E.md still marks shipped items as open; contradicts TODO_NEXT.md | `docs/TODO_E2E.md` | codex_doc_1, _2; gemini_doc_1 | FIX_NOW |
| 43 | `PDFAnalyzer.policy_check` docstring says "one report per profile" — actual emits per-finding + one rollup | `Analyzers/PDFAnalyzer.py:671-676` | codex_doc_2; gemini_doc_1 | FIX_NOW |
| 44 | `CLAUDE.md` says `Eml` uses `ReceivedParser` from `Utils.received_parser` — `eml.py` has its own duplicate parser | `CLAUDE.md:32, 39`, `eml.py:43-72` | codex_doc_1 | FIX_SOON |

## MEDIUM — code style / dead code

| # | Finding | File:Line | confirmed_by | Action |
|---|---------|-----------|--------------|--------|
| 45 | `Analyzers/TEMPLATE_ANALYZER.py` imports nonexistent `.base` module; placeholder deps `'new_dependency'` | `Analyzers/TEMPLATE_ANALYZER.py` | codex_style_1, _2 | FIX_NOW |
| 46 | `Analyzers/OfficeXMLAnalyzer.py` is stale duplicate — references dead class `'DocxAnalyzer'`, re-implements DDE/XXE scans now in OfficeDocumentAnalyzer | `Analyzers/OfficeXMLAnalyzer.py:5-22, 32-65` | codex_style_2 | FIX_SOON |
| 47 | `_report_exiftool`, `can_analyze`, renderer tree builder use bare `except Exception: pass` | `structure.py:251-252, 367-371`, `renderers/__init__.py:83-89` | codex_style_1, _2 | FIX_SOON |
| 48 | `SevenZipAnalyzer` uses `logging.warning/error` directly (root logger, not matt) — Sprint 7 fix only covered ZipAnalyzer | `Analyzers/SevenZipAnalyzer.py:26, 52, 72, 79, 84, 113` | codex_style_2 | FIX_NOW |
| 49 | `SevenZipAnalyzer` swallows `Exception as e: pass` (e never used) | `Analyzers/SevenZipAnalyzer.py:65-70` | codex_style_1, _2 | FIX_SOON |
| 50 | `py7zr` mislabeled as `optional_pip_dependencies` — analyzer can't function without it | `Analyzers/SevenZipAnalyzer.py:19-27` | codex_style_2 | FIX_NOW |
| 51 | `RelayCache.annotate(hostname, ip="")` — `ip` parameter never used | `Utils/relay_cache.py:174-184` | codex_style_1 | FIX_SOON |
| 52 | `getAttachments` camelCase — repo uses snake_case | `Analyzers/PDFAnalyzer.py:245` | codex_style_2 | FIX_SOON |
| 53 | Renderer `verbosity` parameter threaded but unused by concrete renderers | `renderers/__init__.py:64-72`, all `_render` methods | codex_style_1 | DEFER (or implement) |
| 54 | Conftest fixture duplicated across test files | `tests/test_*.py` autouse fixtures | codex_style_1 | FIX_SOON |
| 55 | `_dde_target_re` defined but never used (dead regex) | `Analyzers/OfficeDocumentAnalyzer.py:534-536` | codex_style_2 | FIX_NOW |
| 56 | `pattern = word.encode(...)` dead assignment in RTF scan | `Analyzers/RTFAnalyzer.py:102-105` | codex_style_2 | FIX_NOW |
| 57 | OLE package parser parses fields then discards them | `Utils/ole_package.py:102, 108, 177` | codex_style_2 | DEFER |
| 58 | JSE decoder has unused `_JSE_PICK` table | `Utils/js_analysis.py:699, 759` | codex_style_2 | DEFER |

## REJECTED / NOT-A-FINDING

(None so far — every finding sampled has held up to validation.)

## Action plan

Sequence the FIX_NOW items into thematic commits:

1. **A. Security gates** (#1 box-js host gate, #4 cache key, #34 Poppler timeout, #35 VT render-time)
2. **B. PDF policy correctness** (#6 literal strings, #7 indirect refs, #8 filter arrays, #2 ObjStm budget, #3 stream budget)
3. **C. JS detection correctness** (#10 CVE label, #11+#12 util.printf, #13 getAnnots, #14 exportDataObject, #17 collectEmailInfo description)
4. **D. DDE multi-run + test integrity** (#5+#22 DDE, #18+#19+#20 dedup tests, #24+#26 brittle assertions)
5. **E. Docs hygiene** (#37-#43 README, CLAUDE.md, TODO consolidation, RAR extra, policy_check docstring)
6. **F. Style / dead code cleanup** (#45 TEMPLATE_ANALYZER, #48 SevenZip logger, #50 py7zr, #55 dead regex, #56 dead assignment)

Each commit pins the fix with a regression test (per the regression-test rule in feedback memory).
