# MATT — Next Sprint Backlog

Consolidated open items as of `8b2b2f3`. The earlier `docs/TODO_E2E.md`
captures the original Sprint 7 audit; almost everything from there has
shipped. This doc tracks what's left and what to add.

Each item links the file the work belongs in and notes the regression
test that must come with the fix (per the
[regression-test rule](../../.claude/projects/-Users-tabledevil-repos-mailscan/memory/feedback_regression_tests.md)).

## High-value static analysis

### Office active content (highest priority)

- [ ] **DDE field codes** — `{DDEAUTO …}` / `{DDE …}` in DOCX
  document.xml or DOC streams. Pre-macro execution vector that
  bypasses macro-disable settings. **Home:** `OfficeDocumentAnalyzer`
  / `OLEOfficeAnalyzer`. **Test:** synthetic .docx with a DDE field
  → DDE finding emitted with HIGH severity.

- [ ] **External relationship targets** — `_rels/document.xml.rels`
  entries with `Target` pointing at remote `http(s)://` / `file://`
  URLs and `TargetMode="External"`. Common template-injection vector
  (CVE-2017-0199). **Home:** `OfficeRelationshipAnalyzer`. **Test:**
  synthetic .docx with a remote-template `oleObject` rel → external
  target finding HIGH severity, URL flows into root iocs_aggregate.

- [ ] **Autoload triggers beyond olevba** — explicit detection of
  `Document_Open`, `AutoOpen`, `AutoExec`, `Workbook_Open`,
  `Auto_Open`, `Document_New`, `Workbook_BeforeClose`, plus form-
  control event handlers (`*_Click`, `*_Change` on UserForm). Olevba
  catches some; explicit enumeration in our reports gives a list the
  analyst can scan. **Home:** `VBAProjectAnalyzer`. **Test:** synthetic
  VBA module with each trigger name → enumerated by name in report.

### RTF active content

- [ ] **`objupdate` / `objemb` triggers** — RTF object update flag is
  the classic CVE-2017-11882 / CVE-2018-0802 EQNEDT32 carrier.
  **Home:** `RTFAnalyzer`. **Test:** synthetic RTF with `\objupdate
  \objclass Equation.3` → CRITICAL EQNEDT32 fingerprint emitted.

- [ ] **CLSID-based equation-editor detection** — match
  `0002CE02-0000-0000-C000-000000000046` (Equation.3) or
  `0003000A-0000-0000-C000-000000000046` (Excel Sheet) inside RTF
  `\object` payloads. **Home:** `RTFAnalyzer`. **Test:** RTF with the
  raw CLSID byte sequence → finding fires.

### HTML phishing heuristics

- [ ] **Login-form mismatch** — form `action` posting to a domain
  that doesn't match any of From / Reply-To / Return-Path / List-Id.
  Phishing tell when an email body has a `<form>` posting to an
  attacker domain. **Home:** `HTMLAnalyzer`. **Test:** HTML body
  with `<form action="https://evil.example/collect">` inside an eml
  whose From is `corp.example` → HIGH credential-harvest finding.

- [ ] **Hidden credential fields** — `<input type=hidden name=…
  value=…>` collocated with `password` field, or fields named
  `username`/`password`/`pin` with off-screen positioning CSS.
  **Home:** `HTMLAnalyzer`. **Test:** synthetic HTML with hidden
  credential field → MEDIUM credential-form finding.

- [ ] **Single-page JS-only redirect** — `<script>`-driven
  `window.location` / `meta refresh` to a non-original domain.
  **Home:** `HTMLAnalyzer`. **Test:** HTML with
  `<meta http-equiv="refresh" content="0;url=https://evil.example/">`
  → MEDIUM redirect finding with destination URL.

### Email forensics extensions

- [ ] **ARC chain depth** — count ARC-Authentication-Results /
  ARC-Message-Signature / ARC-Seal hops; flag `cv=fail` (chain
  validation failed) as MEDIUM. **Home:** `EmailAnalyzer`.
  **Test:** synthesised eml with broken ARC seal → finding fires.

- [ ] **received-spf softfail vs hardfail** — already parsed; surface
  a separate finding when `softfail` (record says "should fail" but
  was let through) since that's a weaker signal than `pass` and
  stronger than `none`. **Home:** `EmailAnalyzer`. **Test:**
  synthesised eml with `Received-SPF: softfail` → LOW finding.

- [ ] **BCC-leakage** — when `To:` and `Cc:` contain only
  `undisclosed-recipients:;` AND `Bcc:` is missing AND `Received` chain
  shows ≥2 different envelope-To values, flag as bulk send.
  **Home:** `EmailAnalyzer`. **Test:** synthesised eml matching the
  shape → MEDIUM bulk-send finding.

## Niche PDF carry-overs (added per user request)

- [ ] **CVE-shellcode-string fingerprints** — extend
  `Utils/js_analysis.PDF_CRITICAL_PATTERNS` with byte-string heap
  spray markers found in known CVE PoCs (e.g. `0c0c0c0c` IE5/6
  spray, `41414141` AAAA fill, NSCK / NSCM marker bytes). **Home:**
  `Utils/js_analysis.py`. **Test:** PoC-shaped JS with each
  fingerprint → CRITICAL finding.

- [ ] **Adobe-specific embedded Flash detection** — `/Subtype
  /Application/x-shockwave-flash` annotation subtype (not currently
  in `_ANNOTATION_RIGHTS`); also legacy `/3D` annotations carrying
  `/Subtype /Flash3D`. Both are dead surfaces today (Flash is gone)
  but appear in archived malware corpora. **Home:**
  `Utils/pdf_policy.py`. **Test:** synthetic PDF with
  `/Subtype /Application/x-shockwave-flash` → CRITICAL finding under
  every profile.

## Infrastructure hygiene

- [ ] **Replace PyPDF2 with pypdf** — PyPDF2 is deprecated; pypdf is
  the maintained fork with the same API surface. The
  `DeprecationWarning` shows on every test run. **Home:** `pyproject.toml`,
  `Analyzers/PDFAnalyzer.py`. **Test:** existing PDF tests must still
  pass under pypdf; CI guard against regression.

- [ ] **Suppress oletools pyparsing deprecation warnings** — they
  flood the docker test output and are noise the user can't act on.
  Either pin a compatible pyparsing or filter the warnings at the
  module level. **Home:** `pyproject.toml` (warnings filter) or
  `Utils/logger.py`. **Test:** running pytest doesn't print the
  PyparsingDeprecationWarning lines.

- [ ] **Pin direct dependencies** — pyproject.toml `dependencies`
  has version floors but no upper pins; brittle against future
  breaking releases (we already saw this with setuptools 80+
  breaking ssdeep and `_legacy` backend). **Home:** `pyproject.toml`.
  **Test:** none required (this is policy, not behavior).

## Already shipped (for reference)

The following were on the original Sprint 7 backlog and are done:
header forensics (A1-A6), relay annotation cache, renderer polish
(B1-B4), max-depth runaway, compression-ratio reporting, YARA/VT
skip hints, testfiles housekeeping, mailing-list FP suppression,
ScriptAnalyzer obfuscated-JS gate, Report.label autofill, root IOC
aggregate, extraction layout (manifest.json + filenames-by-default),
QR analyzer, pdfcop policy parity (4 profiles, 30+ markers),
/ObjStm decompression, PDF→JS bridge, PDF Reader DOM threat
patterns, embedded-file harvesting completeness, incremental-update
detection + multi-version object extraction, inline image/font
extraction, Docker deployment validation, box-js wrapper end-to-end.
