# Testing `pstforensic` against a real / classified sample (content-sealed)

`test_real_sample.py` lets you validate the parser against a **real PST/OST/NST
file whose contents must never leak into any transcript** (the assistant's, a
subagent's, or version control). It is the bridge that closes the Axis-D
(differential / real-corpus) gap noted in `STATUS.md` — without exposing a single
byte of the evidence.

## Guarantees

- **The file is never read by an assistant tool and never copied into the repo.**
  You pass its path via an env var; it may live anywhere (ideally outside the repo).
- **Every assertion is sealed**: it compares counts / lengths / hashes / booleans,
  never values. Failure messages contain no content.
- **Unexpected exceptions are caught** and rewritten to a content-free message;
  full detail goes only to a gitignored report.
- **`.gitignore` blocks** `*.pst`, `*.ost`, `*.nst`, any `private/` dir, and
  `sealed_report*.txt` / `*.sealed.txt`, so neither the sample nor the report can
  be committed.
- The harness **SKIPS** unless the env var points at an existing file, so the
  normal suite (`224 passed`) is unaffected.

## Run it

```bash
# from repo root; the sample can be anywhere on disk
PSTFORENSIC_PRIVATE_SAMPLE=/secure/path/evidence.pst \
  python3 -m pytest pstforensic/tests/test_real_sample.py -q --tb=line -p no:cacheprovider
```

Use **`--tb=line`** (one safe line per failure) and **do not** pass `-l`,
`--showlocals`, `-s`, or `-rA` — those could surface in-process values. The flags
above are the safe set.

Optional: choose where the sealed metadata report is written (default
`pstforensic/tests/fixtures/private/sealed_report.txt`, gitignored):

```bash
PSTFORENSIC_PRIVATE_REPORT=/secure/path/report.sealed.txt
```

## What you get

Console: only `passed` / `skipped` / `FAILED <safe message>`.

Sealed report (you read it; the assistant never does) — **metadata only**:
folder/message/recipient/attachment counts, attachment **byte count** (not bytes),
distinct property-tag count, MS-OXPROPS/named coverage %, warning-code histogram,
detected variant + crypt method, recovery item/method/confidence counts, and the
differential match counts.

## What it proves

| Check | Meaning |
|-------|---------|
| `test_opens_without_crash` | the real file parses; records variant + crypt method |
| `test_total_coverage_no_render_errors` | every folder/message/recipient/attachment walked; **every** property renders without raising |
| `test_property_catalog_coverage` | % of distinct tags resolved by name (coverage gap meter) |
| `test_warning_codes_are_safe_metadata` | which advisories fired (CRC, AMap, `UNVERIFIED_CONST`, …) |
| `test_deterministic_parse` | two independent parses yield an identical (salted) fingerprint |
| `test_recovery_runs_sealed` | `RecoveryEngine` runs on the real file; item/method/confidence counts only |
| `test_differential_vs_pypff_sealed` | **Axis D** — set parity vs `pypff`; asserts we miss nothing it finds |

## Unlocking the differential + the UNVERIFIED constants

Install an independent oracle so the harness can cross-check (sealed, hash-set only):

```bash
pip install libpff-python   # provides `pypff`
```

Running against samples that actually use **NDB_CRYPT_PERMUTE / NDB_CRYPT_CYCLIC**
or the **4K-OST** format is what lets us promote the four `# UNVERIFIED` constants
(crypt S-box decode-direction, 4K geometry, 4K compression order, conversation-index
deltas) from "round-trip only" to "locked against ground truth" — the `warning_codes`
line in the report will show `UNVERIFIED_CONST` whenever the sample exercises one,
telling you (without leaking anything) exactly which gap that file can close.
```
