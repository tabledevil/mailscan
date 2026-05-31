# pstforensic — STATUS (honest coverage scorecard)

Integration agent pass.  This is a deliberately *honest* accounting of what is
covered by test vectors versus what is still a working hypothesis or unbuilt.
Governing rule: no byte-level constant is "correct" until a known-answer test
locks it (PLAN §0.5); 4K / real-corpus axes are explicitly **not** locked.

## Full-suite result

```
224 passed in ~0.14s   (python3 -m pytest pstforensic/tests -q)
```

(Was 210 before the recovery-completion pass; +14 from `test_recovery.py`.)

## Per-subpackage test counts

| Test file              | Passing | Subpackage(s) exercised                          |
|------------------------|---------|--------------------------------------------------|
| test_foundation.py     | 17      | exceptions, proptypes, variant, fileio, mapi     |
| test_crc.py            | 17      | ndb.crc (CRC-32 + sig, oracle cross-check)       |
| test_ndb.py            | 34      | ndb (header/btree/block/crypt/subnode/nodedb)    |
| test_ltp.py            | 16      | ltp (heap/bth/pc/tc)                             |
| test_render.py         | 34      | render (filetime/guid/entryid/rtf/convindex/str) |
| test_catalog.py        | 52      | catalog (oxprops + namedprops)                   |
| test_msg.py            | 13      | msg.cfbf + msg.parser (open_msg, embedded)       |
| test_messaging.py      | 20      | messaging (store/folder/message/recipient/nameid)|
| test_endtoend.py       | 7       | PUBLIC API + recovery (open_store/open_msg/Recovery) |
| test_recovery.py       | 14      | recovery cascade (carve/rebuild/encode_detect/orphan/dedup/score) |
| **Total**              | **224** |                                                  |

Recovery now has a dedicated `test_recovery.py` (14 known-answer cases) covering
the full cascade: AC-2 (`truncate`→carve survivor-prefix, method≠'btree'), AC-4
(`bad_header_crc`→clean-twin reads + HEADER_CRC_FAIL), AC-3 (`zero_amap`→identical
to clean twin), `drop_nbt_entry`→orphan-PC recovery (confidence<1.0, correct
class), plus carve-finds-known-block, encode_detect NONE/PERMUTE/CYCLIC, dedup
collapse, the free-space three-set algebra (H14), and advisory-AMap-in-memory.

## PLAN §1.3 coverage axes

| Axis | What it means | Status |
|------|---------------|--------|
| **A — format variant** | ANSI / Unicode / Unicode-4K, ANSI vs Unicode header & block geometry | **PARTIAL.** ANSI + Unicode are byte-locked by synth fixtures (`build_ansi_pst`, `build_unicode_pst`, `build_unicode_pst_tree`). **4K-OST geometry is UNVERIFIED** (`variant.UNICODE_4K.verified is False`) — no fixture, no real sample. |
| **B — property catalog** | PidTag*/PidLid* names, types, named-prop map | **GOOD for the analyst envelope.** oxprops + namedprops resolve the common envelope/body/time/header tags and the well-known sets; named-prop map (NID 0x61) round-trips id-named + string-named entries (test_messaging, test_endtoend). Not exhaustive vs the full [MS-OXPROPS] catalog. |
| **C — code paths** | every parser/decoder branch hit by a vector | **GOOD on the trusted path.** NDB (header→ROOT→BBT/NBT→block/XBLOCK/subnode), LTP (HN/BTH/PC/TC), render dispatcher, msg CFBF, messaging bootstrap+walk are all driven. PERMUTE/CYCLIC *encode* is exercised via round-trip synth, but the **decode-direction** is not independently locked (below). |
| **D — differential** | cross-check vs an independent implementation (libpff/readpst) on a real corpus | **NOT COVERED.** Everything is self-oracle (synth writes the bytes our reader reads). No real proprietary PST/OST, no libpff/readpst differential. This is the single largest gap to "100%". |

## UNVERIFIED constants still needing a real-sample vector

All are implemented, marked `# UNVERIFIED`, and emit
`sink.warn(WarnCode.UNVERIFIED_CONST, ...)` at runtime (PLAN §0.5):

1. **`ndb/crypt.py` — `mpbbCrypt` (PERMUTE/CYCLIC S-boxes, [MS-PST] §5.1).**
   The 768 substitution bytes are transcribed from the spec but not locked
   against a real encrypted PST.  Encode⇄decode are functional inverses *by
   construction*, so round-trip tests pass, but a byte-perfect transcription is
   unproven.  Needs: one real NDB_CRYPT_PERMUTE and one NDB_CRYPT_CYCLIC block
   from a genuine Outlook store as a known-answer vector (decode-direction).
2. **`variant.py` — `UNICODE_4K` geometry ([MS-PST] Appendix A H20).**
   `verified=False`.  4K page size, trailer offsets, and AMap geometry are a
   working hypothesis.  Needs a real 4K OST.
3. **`ndb/block.py` — 4K block compression order.**
   The zlib-decompress path for 4K blocks is a hypothesis (warns when
   `variant.verified` is False).  Needs the same real 4K OST.
4. **`render/convindex.py` — `_DELTA_SHIFT_COARSE=18` / `_DELTA_SHIFT_FINE=10`
   (PidTagConversationIndex child-delta scale).**
   The FILETIME-delta bit-shift constants are unverified; conversation-index
   *header* (the 22-byte root FILETIME + GUID) is locked, the per-child time
   deltas are best-effort.

## Concrete remaining work to reach 100%

Ordered by forensic value:

1. **Real-corpus differential tests (axis D).**  Acquire (or generate with real
   Outlook) ANSI + Unicode + 4K samples; assert our folder/message/recipient
   enumeration and rendered envelope match `libpff`/`readpst`.  This is the only
   way to retire the self-oracle caveat and the crypt/4K UNVERIFIED flags.
2. **PERMUTE / CYCLIC decode-direction vectors.**  Lock `mpbbCrypt` with a
   known ciphertext→plaintext pair per method from a real store (today only the
   round-trip is tested, which cannot catch a self-consistent transcription
   error).
3. **4K-OST geometry.**  Verify page size / trailer / AMap offsets and block
   compression against a real 4K OST; flip `UNICODE_4K.verified` to True and add
   `build_unicode_4k_pst` to synth.
4. **Soft-deleted / dumpster differential.**  `orphan.classify_soft_deleted_folders`
   recognises *Deleted Items* + the Recoverable-Items dumpster subfolders
   (Deletions/Versions/Purges/DiscoveryHolds) by folder location (no `mfDeleted`
   bit — H8), and deletion timestamps resolve via the catalog (H9).  But the
   synth fixtures don't yet *build* a Deleted-Items / dumpster folder tree, so
   that classification path is unit-reachable but not driven by a known-answer
   fixture.  Needs a `synth` dumpster-folder knob (or a real Exchange OST).
5. **Slack-fragment KAT.**  `orphan.extract_slack_fragments` emits post-HNPAGEMAP
   residual bytes as fragments (never items, §8.4), but there is no synth fixture
   that *plants* a known slack residue, so its byte-exact output is unverified.
6. **PERMUTE/CYCLIC decode-direction in carve/encode_detect.**  `encode_detect`
   correctly picks the method that round-trips the synth oracle, but — like
   `ndb/crypt.py` — cannot prove the absolute decode direction of a real Outlook
   block (it emits `UNVERIFIED_CONST`).  Same real-sample need as gap #2.
7. **>4GB streaming.**  `FileReader` reads via offset/len and never holds the
   whole image, but the synth fixtures and tests are all small in-memory blobs;
   large-file (multi-FAT-sector, >2^32 ib) paths are untested.  Needs a large
   fixture or a sparse/streamed source test.
8. **Property-catalog completeness (axis B).**  Extend oxprops/namedprops beyond
   the analyst envelope toward the full [MS-OXPROPS] set if exhaustive name
   resolution is required.

## What this integration pass changed

- Created `recovery/__init__.py` + `recovery/engine.py` (`RecoveryEngine`,
  `RecoveredItem`) — the trusted-walk + reachability-diff cascade per CONTRACTS.
- Wired `pstforensic.RecoveryEngine` into the package root (PEP-562 lazy export);
  `open_store`/`open_msg` entry points were already real and are now end-to-end
  tested.
- Extended `tests/synth.py`:
  * `build_unicode_pst_tree` now adds `PidTagBody` (0x1000) + a locked
    `PidTagMessageDeliveryTime` (0x0E06 → 2021-06-15T12:00:00Z) to message 1,
    and a new `deleted=` knob that emits an orphaned (folder-unreferenced)
    message node for the recovery oracle.
  * Fixed the CFBF/MSG writer (`_write_cfbf_minimal`): replaced the
    right-sibling directory chain with a **balanced BST** ([MS-CFB] §2.6.4
    collation) and a **generic multi-sector** directory / mini-FAT / mini-stream
    layout, so `build_msg` round-trips through `olefile`/`open_msg` for any
    stream count (previously dropped entries past the first directory sector).
- Added `tests/test_endtoend.py` (7 tests) driving only the public API.

## Recovery-completion pass (the cascade is now COVERED)

The recovery tier was PARTIAL (only trusted-walk + NBT reachability diff).  It is
now the **full cascade** (PLAN §7/§8), each stage backed by `test_recovery.py`:

- **`recovery/carve.py`** — linear full-file scan for valid PAGETRAILER (BBT/NBT
  leaf recovery) and BLOCKTRAILER (data-block) signatures, validated via
  `compute_sig` + `compute_crc` + normalized-bid range + block/page alignment.
  Pages are probed on the block-align (64B) stride because real/synth stores
  place B-tree pages on 64B — not 512B — boundaries.
- **`recovery/rebuild.py`** — reconciles carved BBT/NBT entries into deduped
  indexes (`RebuiltIndex`), exposes a `NodeDatabase`-compatible
  `RebuiltNodeDatabase` so carved nodes hit the *real* LTP/messaging parser
  (§7.6 cross-validation), and reconstructs an **in-memory / advisory-only**
  AMap (never writes the evidence file — Appendix A N1/H14).
- **`recovery/encode_detect.py`** — brute-forces NONE/PERMUTE/CYCLIC by
  trial-decoding a probe data block and scoring for HN `bSig 0xEC` + a known
  `bClientSig` + plausible MAPI tags; reuses `ndb.crypt.decode_block`.
- **`recovery/orphan.py`** — the four-state engine: soft-deleted (folder
  location + dumpster, **no `mfDeleted` bit** H8, timestamps via catalog H9),
  hard-deleted (carve PC blocks from free space = NOT-in-rebuilt-BBT H14,
  require `PidTagMessageClass`, classify into the four recovery classes), orphan
  PC (allocated-but-unreferenced), slack (post-HNPAGEMAP residue as fragments
  only).  Exposes `free_space_for_carving` → the H14 three-set algebra.
- **`recovery/dedup.py`** — collapses re-carved duplicates by normalized-envelope
  SHA-256 (`from|to|subject|client_submit_time`) or raw-PC-bytes fallback; keeps
  the highest-confidence instance and records `duplicate_count` (§8.6).
- **`recovery/engine.py`** — `RecoveryEngine.recover()` runs trusted-walk → (if
  roots broken/truncated) carve → rebuild → encode-detect → carve survivor PCs;
  on healthy roots, orphan-PC + free-space hard-deleted carve; all merged through
  `dedup`.  Each item carries `RecoveryMeta(method, confidence, deleted_on,
  attributed_folder, attribution_confidence, recovery_class, truncated, flags,
  duplicate_count, raw_pc)`.  **The original constructor + trusted-walk behavior
  (`btree` method, conf-banding) that `test_endtoend` relies on is preserved.**
- **`tests/synth.py`** — added a `corrupt=` parameter to `build_unicode_pst_tree`
  (the existing knobs plus a `'truncate'` that drops the trailing BBT/NBT pages,
  keeping the message PCs in the survivor prefix — the AC-2 carve oracle).  All
  existing callers are unaffected.
