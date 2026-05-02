# MATT — End-to-End Findings TODO

Generated 2026-04-30 from a full-tool E2E test pass over `samples/` and
`testfiles/`. Items grouped by severity. Each item references the failing
test (where applicable) in `tests/test_e2e_findings.py`.

## Critical correctness

- [ ] **#2 ScriptAnalyzer.can_handle gate too strict.** Heavily-obfuscated
  `.JS` droppers (e.g. `samples/845ecc88…eml` SWIFT lure: 4.5 MB of
  `this.X += "..."` repeats) carry no `function`/`var`/`let`/`const`/`=>`
  in the first 4 KB, so the analyzer never runs. Loosen: `.js`/`.jse`/
  `.mjs`/`.cjs` extension alone should suffice; add `this\.\w+\s*\+?=`,
  JScript.Encoded `#@~^`, and very-low-entropy `.js` content as positive
  signals.
  *Test:* `test_script_analyzer_handles_obfuscated_this_assignment_js`

- [ ] **#3 Report.label not auto-filled from dict key.** `Report.label`
  defaults to `""`. Many analyzers (PlainText `summary`/`language`,
  EmailAnalyzer encoding rows, Zip filenames) rely on the dict key but
  don't pass `label=`. HTML emits `<span class="report-label"></span>`,
  Markdown emits `****:`. Auto-fill in the report-emit path.
  *Test:* `test_report_label_autofills_from_dict_key`

- [ ] **#4 Root-logger leakage from ZipAnalyzer.** `logging.error()` /
  `logging.warning()` calls in `Analyzers/ZipAnalyzer.py` route to the
  root logger (`ERROR:root:Error testing password…`) instead of the
  `matt` logger. Switch to `Utils.logger.log` and convert
  "compression method not supported" to a structured `Report`.
  *Test:* `test_zip_uses_matt_logger_only`

- [ ] **#5 No aggregate IOC report at root.** Per-analyzer IOC extraction
  works but no end-of-analysis rollup. Walk the Structure tree and
  attach `iocs_aggregate` to the root, with defang in display text.
  *Test:* `test_root_has_aggregate_ioc_report`

- [ ] **#6 `-x` extraction loses original extension.** Files extracted
  via `Structure.extract()` use `mimetypes.guess_extension(mime)` —
  obfuscated `.JS` saved as `.txt` because content is `text/plain`.
  Prefer the original archive entry name's extension when present.
  *Test:* `test_extraction_preserves_original_extension`

## Renderer / output unrefined

- [ ] **HTML renderer**: only MD5 (no SHA1/SHA256), no severity color on
  node headers, hop-table CSS defined but never emitted (only rich/text
  draw the hop chain), no aggregate IOC block, truncation banner is
  literal inline text rather than `<details>`.

- [ ] **Markdown renderer**: no severity badges, only MD5, empty labels
  render as `****:`, no hop chain, no defang.

- [ ] **JSON renderer**: no top-level severity rollup, no aggregate
  IOCs, hop chain only available via the separate `timeline` format.

- [ ] **MIME provider noise** — `exiftool` constantly mis-classifies
  (`.eml → text/plain`, `.msg → image/vnd.fpx`) and is rendered as the
  last entry of the type list, looking like a disagreement. Drop from
  dispatch chain, or only show on fallback.

- [ ] **Max-depth WARNING fires on benign 6-message mbox** (default
  depth 10). Either the depth budget is off-by-one or the multi-dispatch
  chain double-counts container layers.

- [ ] **Encrypted-zip "compression method not supported"** leaks pyzipper
  internals to stderr; should become an INFO/MEDIUM `Report`.

## Roadmap items still open

- [ ] **Mail-relay hop annotation cache** — hops show only raw
  `host -> host`. No "internal relay" / "M365" / "first external hop"
  callouts; no persistent known-relay DB.

- [ ] **Reply-To vs From / Return-Path vs From / Message-ID-domain vs
  From-domain mismatch checks** — auth report has SPF/DKIM/DMARC but
  none of the spoofing-mismatch heuristics from Phase 1.1.

- [ ] **`undisclosed-recipients` warning** — BEC eml has
  `To: undisclosed-recipients:;` but no MEDIUM/LOW finding fires.

- [ ] **Compression-ratio reporting** — Zip report lists filenames + sizes
  but no `compression_ratio: 13.7:1` line.

- [ ] **IOC defang in display** — no `evil[.]com`-style anywhere in
  default output.

- [ ] **YARA / VirusTotal / MITRE ATT&CK** — Sprint 5 features ship as
  no-ops without config; no UX hint that they would help. Surface an
  INFO report when skipped.

- [ ] **JS dynamic-analysis tool absence is silent** — only `--check`
  mentions box-js missing; surface inside the Script section.

- [ ] **PDFAnalyzer active-content checks** — no `/JavaScript`,
  `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/AA` flagging visible.

- [ ] **QR-code decoding on images** — common phishing channel;
  ImageAnalyzer is exif-only.

## Test/infra

- [ ] **`tests/test_sample_corpus.py::test_encrypted_zip_corpus_present`
  fails** because `testfiles/infected.zip` has an unencrypted `.eml`
  (duplicates `RE_.zip`). Drop the dup or relax the assertion.
