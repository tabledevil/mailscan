# libpst-native / `pstforensic` — Master Design Document

**A forensic-grade, host-static-safe, recovery-first PST/OST/MSG parsing library with a shared MAPI object model.**

Version 1.0 — design baseline. Module name: `pstforensic`. Distribution name: `libpst-native`. Target: Python 3.10+, pure-Python core (zero native build deps), optional accelerators.

> **⚠️ Source-of-truth notice.** This document was synthesized from a 10-agent research dossier and then **adversarially reviewed by two independent models (codex, gemini)** and reconciled against the primary MS-PST / MS-OXMSG / MS-OXPROPS / MS-OXRTFCP / MS-OXOMSG specifications. The review found that **all three sources (dossier + both reviewers) were each wrong about different byte-level constants**, and that the reviewers themselves were confidently wrong on several "critical" findings. The governing engineering principle that came out of this — **§0.5 and Appendix A — is that no byte-level constant in this document is to be trusted until it is pinned by a test vector against the MS-PST sample file or a real fixture.** Where the body and **Appendix A (Adversarial-Review Reconciliation & Spec-Verified Constants)** disagree, **Appendix A wins.**

---

## 0. Document map

0.5. **Verification methodology** (trust-nothing-without-a-test-vector)
1. Goals, non-goals, "100%/proven" definition & acceptance criteria
2. Layered architecture, package layout, public API
3. Data model & lazy/streaming for multi-GB files
4. NDB reader
5. LTP reader
6. Messaging reader
7. Recovery engine
8. Deleted/orphan/slack reconstruction engine
9. Property/metadata catalog & human-readable renderers
10. Native MSG parser & `MsgAnalyzer` migration
11. Test strategy & coverage scorecard
12. Risks, hard unknowns, dependencies
13. Phased roadmap M0..M9
- **Appendix A** — Adversarial-review reconciliation & spec-verified constants (authoritative)

---

## 0.5 Verification methodology — trust nothing without a test vector

This project's correctness bar is "provably 100%," so it must treat **every byte-level constant as unverified until a test asserts it against ground truth.** The adversarial review proved why this is not paranoia:

- The synthesis dossier, codex, and gemini **each stated a different wrong value** for the `bCryptMethod` header offset (0x0219 vs 0x205/0x1B5 vs "near FPMap"). The spec-true values are **0x0201 (Unicode) / 0x01CD (ANSI)** — *none of the three sources had them.*
- gemini's two highest-severity findings were **both wrong**: it called `hidIndex` 0-based (it is **1-based, must-not-be-zero**, MS-PST §2.3.1.1) and called the CRC "CRC-32C/Castagnoli" (it is **standard CRC-32 poly 0xEDB88320, seed 0, no inversion**, MS-PST §5.3). Its `ComputeSig` "CRC-16" claim was also wrong.
- codex's substantive corrections (header layout, PC 4-byte inline, `PidTagAttachMethod` 5-vs-6, LZFu, `PtypCurrency`, MSG `__substg1.0_%08X`) were **right** and are now folded in.

**Operating rules enforced in code/CI:**
1. **Spec extraction over memory.** Constants come from the MS-* specs (offsets, tables, enums), captured in `catalog/` data files with a comment citing the section, never typed from recollection.
2. **Test-vector lock.** Each structural constant has a unit test that decodes a known-answer fixture (the MS-PST sample file where available; otherwise a byte-literal fixture with a hand-verified expected value). A constant with no locking test is flagged `UNVERIFIED` in the scorecard and may not gate a milestone.
3. **Differential cross-check.** Where libpff/readpst succeed, their output is a second oracle (§11) — disagreement is a test failure to be explained, not silently accepted.
4. **Reviewers are inputs, not authority.** Adversarial findings (human or model) are themselves verified against spec+vector before being applied — see Appendix A for the per-finding disposition.

---

## 1. Goals, non-goals, and the definition of "100% / proven"

### 1.1 Goals

- **G1 — Universal format coverage.** Parse every PST/OST variant: ANSI "small" (`wVer` 14/15), Unicode (`wVer` 23–35), 4K-page OST (`wVer` 36/37, Outlook 2013+ cached-mode), across Outlook 97→365 and all Exchange cached-mode OSTs. Detect — and refuse to mis-parse — WIP-encrypted stores (`bCryptMethod=0x10`).
- **G2 — Host-static-safe.** No code execution, no macro/script detonation, no outbound network by default. The library only reads bytes and decodes obfuscation (PERMUTE/CYCLIC are reversible transforms, not detonation). Embedded executables/scripts are surfaced as child `Structure`s for downstream MATT analyzers, never run.
- **G3 — Recovery-first.** Read files where `readpst`, `msgconvert`, ScanPST, and `libpff` fail: dirty `fAMapValid`, bad header CRC, truncated tail, broken NBT/BBT roots, dangling BIDs, cyclic parents, overlapping allocations, encode-method mismatch. Always degrade, never abort on a single defect.
- **G4 — Deleted/orphan/slack reconstruction.** Recover soft-deleted (Deleted Items / dumpster), hard-deleted (freed-but-unzeroed), orphaned (unreferenced) and slack-space items, each with a confidence score and attribution.
- **G5 — Total attribute exposure.** Every MAPI property rendered human-readably: complete MS-OXPROPS catalog, named-property resolution, FILETIME→ISO-8601, GUID→RFC-4122, EntryID→SMTP, conversation-index trees, compressed-RTF/LZFu decompression, codepage-correct strings.
- **G6 — One MAPI object model** shared by the PST/OST reader and a native MSG parser that replaces `extract_msg` in `MsgAnalyzer`.
- **G7 — Proven by test before wiring into MATT.** No analyzer registration until the coverage scorecard (§11) hits its gate.

### 1.2 Non-goals

- **N1** — No write/repair-in-place. Recovery is read-only; we emit reconstructed output, never mutate the evidence file. (An *advisory* AMap rebuild is computed in-memory only.)
- **N2** — No WIP/RMS/AIP decryption (requires Windows DPAPI/TPM context). We detect, flag, and extract clear metadata only.
- **N3** — No Outlook-for-Mac **OLM** parsing (SQLite/OLK bundle, distinct format). Detected and reported as out-of-scope, not mis-parsed.
- **N4** — No malware scanning/detonation (MATT policy). We flag dangerous content via child Structures.
- **N5** — No live Exchange/EWS/MAPI-over-RPC. Offline file parsing only.
- **N6** — No S/MIME cryptographic verification in-process; we extract the opaque MIME envelope for downstream tools.

### 1.3 Definition of "100% / proven" coverage

"100%" is **operationalized as four independently measurable axes**, each with a hard gate. We never claim "perfect recovery"; we claim *measured* coverage.

| Axis | Metric | Gate to ship M-final |
|---|---|---|
| **A. Format-variant coverage** | Each declared variant (ANSI, Unicode, 4K-OST, encrypted-PERMUTE, encrypted-CYCLIC) has ≥1 golden corpus fixture that round-trips at item-fidelity ≥ threshold | 100% of declared variants green |
| **B. Property-catalog coverage** | % of MS-OXPROPS canonical tags with (a) a typed decoder and (b) a human renderer, plus named-prop resolution | ≥ 99% of MS-OXPROPS tags decode; 100% of *type codes* (PtypXxx + MV variants) decode |
| **C. Structural code coverage** | line+branch coverage of `ndb/`, `ltp/`, `messaging/`, `recovery/` | ≥ 95% line, ≥ 90% branch |
| **D. Differential parity** | On every fixture readable by libpff/readpst, our extracted message set ⊇ theirs (item count, subject, sender, recipients, attachment hashes) | ≥ 100% superset on clean fixtures; documented per-fixture delta on corrupted ones |

**"Proven" means**: every gate is enforced by CI (`pytest` + coverage + a `scorecard.py` that fails the build below threshold), and a signed **coverage scorecard artifact** (`coverage_scorecard.json`) is produced per release listing per-axis numbers and the exact fixture hashes used.

### 1.4 Acceptance criteria (concrete)

- **AC-1** Given any file whose first 4 bytes are `21 42 44 4E` (`!BDN`), the loader returns a `Store` object or a structured `UnsupportedStore`/`EncryptedStore` result — never an uncaught exception.
- **AC-2** A truncated copy of any clean fixture (cut at 50%, 90%, 99% of EOF) yields ≥ the items recoverable from the surviving prefix via carving, all flagged `recovery_method != "btree"`.
- **AC-3** A fixture with `fAMapValid != 0x02` parses read-only with identical item output to its clean twin (AMap is advisory for reads).
- **AC-4** A fixture with header `dwCRCPartial`/`dwCRCFull` corrupted (but body intact) parses with a `HEADER_CRC_FAIL` warning and identical items.
- **AC-5** Named properties (ID ≥ 0x8000) resolve to `(GUID, name|lid)` when `NID_NAME_TO_ID_MAP` (0x61) is intact; degrade to numeric-tag display with `NAMEID_MISSING` flag otherwise.
- **AC-6** `PR_RTF_COMPRESSED` (`0x10090102`) decompresses (LZFu `LZFu`/uncompressed `MELA`) with CRC check; on CRC fail, best-effort partial RTF + `RTF_CRC_FAIL`.
- **AC-7** The native MSG parser extracts the *superset* of fields `extract_msg` currently exposes for every fixture in `tests/msg/`, plus recipient-type flags, named properties, RTF body, S/MIME envelope, and MAPI transport headers.
- **AC-8** No test, on any fuzzed input, causes: unbounded memory (cap enforced), infinite loop (cycle guards), or a read past `min(ibFileEof, physical_size)`.

---

## 2. Layered architecture, package layout, public API

### 2.1 The six layers

```
┌─────────────────────────────────────────────────────────────┐
│ 6. export/render   pstforensic.render / pstforensic.export   │  ISO8601, GUID, EntryID→SMTP, RTF, EML/JSON
├─────────────────────────────────────────────────────────────┤
│ 5. MAPI object model   pstforensic.mapi                      │  MapiObject, MapiMessage, MapiRecipient, MapiAttachment
├─────────────────────────────────────────────────────────────┤
│ 4. messaging   pstforensic.messaging                         │  Store, Folder, Message, Recipient, Attachment, NamedPropMap
├─────────────────────────────────────────────────────────────┤
│ 3. LTP   pstforensic.ltp                                     │  HN, BTH, PropertyContext, TableContext
├─────────────────────────────────────────────────────────────┤
│ 2. NDB   pstforensic.ndb                                     │  Header, Root, NBT, BBT, BlockReader, decode (NONE/PERMUTE/CYCLIC), subnode tree
├─────────────────────────────────────────────────────────────┤
│ 1. file I/O   pstforensic.io                                 │  Windowed/mmap reader, byte-range cache, bounds guard
└─────────────────────────────────────────────────────────────┘
            ▲                                   ▲
            │                                   │
   pstforensic.recovery (cross-cuts 1–4)   pstforensic.catalog (cross-cuts 4–6)
```

The MSG parser (`pstforensic.msg`) **bypasses layers 1–3** (it is OLE/CFBF, not NDB) but feeds the **same layer-5 MAPI object model** and reuses layer-6 renderers and the layer-5/6 property catalog. This is the shared-model contract: *everything above the storage substrate speaks `MapiObject`*.

### 2.2 Package layout (file/module names)

```
pstforensic/
  __init__.py                 # public API re-exports: open_store, open_msg, ...
  version.py
  errors.py                   # PstError hierarchy (§2.5)
  flags.py                    # ParseOptions / RecoveryOptions dataclasses
  consts.py                   # NID_TYPE_*, PTYPE_*, PTYPE_MV flag, ptype page consts, NDB_CRYPT_*

  io/
    __init__.py
    reader.py                 # ByteReader: mmap + windowed fallback, read(off,len) bounds-checked
    cache.py                  # LRU block/page cache keyed by (bid|file-offset)
    structs.py                # little-endian unpack helpers, sized-int readers

  ndb/
    __init__.py
    header.py                 # Header, Root, version detection, CRC (advisory)
    crc.py                    # MS-PST CRC (§4.6), ComputeSig (wSig)
    crypt.py                  # decode_none/permute/cyclic + mpbbCrypt table (§4.5)
    bid_nid.py                # BID/NID/BREF parse + bit masking
    btree.py                  # NBT/BBT B-tree walker (generic, version-parametric)
    page.py                   # BTPAGE, PAGETRAILER, AMap/DList parse
    block.py                  # data block + BLOCKTRAILER, XBLOCK/XXBLOCK reassembly, decompress
    subnode.py                # SLBLOCK/SIBLOCK subnode tree
    nodedb.py                 # NodeDatabase facade: nid→(data,sub) resolution

  ltp/
    __init__.py
    heap.py                   # HNHDR, HNPAGEMAP, HID/HNID resolution
    bth.py                    # BTree-on-Heap
    pc.py                     # PropertyContext
    tc.py                     # TableContext, Row Matrix, CEB

  messaging/
    __init__.py
    store.py                  # Store (NID_MESSAGE_STORE 0x21), open_store
    folder.py                 # Folder (PC + 3 TCs)
    message.py                # Message (PC + subnode recipients/attachments/embedded)
    recipient.py
    attachment.py
    nameid.py                 # NID_NAME_TO_ID_MAP (0x61) resolver
    special_nids.py           # 0x21/0x61/0x122/dumpster mapping

  mapi/
    __init__.py
    object.py                 # MapiObject base: props dict, get/getall, typed accessors
    message.py                # MapiMessage / MapiRecipient / MapiAttachment
    value.py                  # MapiValue: tag, type, raw, decoded, encoding meta, flags

  catalog/
    __init__.py
    oxprops.py                # generated MS-OXPROPS dict (id→canonical name, type, set)
    oxprops_data.json         # shipped data (build-time generated, §9.1)
    namedprops.py             # PS_* GUIDs, well-known LIDs
    msgclass.py               # IPM.* class → human label

  render/
    __init__.py
    filetime.py               # FILETIME→datetime/ISO8601, conversation-index 100ms
    guid.py                   # mixed-endian GUID → RFC4122
    entryid.py                # EntryID → {type, MAPIUID, smtp, x500, display}
    rtf.py                    # LZFu/compressed-RTF decompress (§9.5)
    convindex.py              # PR_CONVERSATION_INDEX tree
    strings.py                # codepage-aware decode (PT_STRING8/PT_UNICODE)

  recovery/
    __init__.py
    engine.py                 # RecoveryEngine: orchestrates passes (§7)
    carve.py                  # page/block signature carving
    rebuild.py                # NBT/BBT rebuild, AMap reconstruct (advisory)
    encode_detect.py          # brute-force ANSI/Unicode + crypt method
    score.py                  # candidate scoring (§7.7)
    orphan.py                 # deleted/orphan/slack engine (§8)
    dedup.py                  # content-hash dedup

  msg/
    __init__.py
    cfbf.py                   # CFB/OLE container (wraps olefile, with orphan-FAT scan)
    parser.py                 # MsgParser → MapiMessage
    nameid.py                 # __nameid_version1.0 resolver (shares catalog)

  export/
    __init__.py
    eml.py                    # MapiMessage → RFC822/EML
    json.py                   # full property dump (forensic)
    summary.py                # triage summary

  tools/
    build_oxprops.py          # build-time: parse MS-OXPROPS → oxprops_data.json
    scorecard.py              # emit coverage_scorecard.json, CI gate
```

### 2.3 Public API surface (the contract)

```python
# pstforensic/__init__.py

def open_store(path_or_bytes, *, options: ParseOptions = ParseOptions()) -> Store: ...
def open_msg(path_or_bytes, *, options: ParseOptions = ParseOptions()) -> MapiMessage: ...
def probe(path_or_bytes) -> StoreInfo: ...   # cheap: variant, wVer, crypt, encrypted?, fAMapValid

# Store (messaging layer)
class Store:
    info: StoreInfo                       # variant, wVer, crypt_method, is_encrypted, amap_valid
    @property
    def root_folder(self) -> Folder: ...
    def folders(self) -> Iterator[Folder]: ...        # lazy DFS
    def messages(self) -> Iterator[Message]: ...      # lazy, across all folders
    def get_message(self, nid: int) -> Message: ...
    def named_properties(self) -> NamedPropMap: ...
    def recover(self, *, options: RecoveryOptions = RecoveryOptions()) -> RecoveryResult: ...
    def warnings(self) -> list[ParseWarning]: ...

class Folder:
    nid: int
    display_name: str
    path: str
    container_class: str | None
    def subfolders(self) -> Iterator[Folder]: ...
    def messages(self, *, include_fai=False) -> Iterator[Message]: ...
    def is_dumpster(self) -> bool: ...

class Message(MapiMessage):  # IS-A MapiMessage
    nid: int
    recipients: list[Recipient]
    attachments: list[Attachment]
    def embedded_messages(self) -> Iterator[Message]: ...
    recovery: RecoveryMeta | None         # None for tree-reached; set for carved

# MAPI object model (shared with MSG)
class MapiObject:
    def get(self, tag: int, default=None) -> MapiValue | None: ...
    def get_value(self, tag: int, default=None): ...           # decoded python value
    def getall(self) -> dict[int, MapiValue]: ...
    def named(self, guid: bytes, name_or_lid) -> MapiValue | None: ...
    def render(self, tag: int) -> str: ...                     # human string
    def to_dict(self, *, human=True) -> dict: ...

class MapiValue:
    tag: int; ptype: int; is_mv: bool
    raw: bytes
    value: Any                # decoded
    encoding: str | None
    flags: set[str]           # e.g. {"TRUNCATED","CRC_FAIL"}
    def render(self) -> str: ...

# Recovery result objects
class RecoveryResult:
    tree_items: int; carved_items: int; orphan_items: int; slack_items: int
    items: list[RecoveredItem]            # each with confidence, method, attribution
    amap_rebuilt: bool
    integrity_score: float                # 0..1

class StoreInfo:
    variant: Literal["ansi","unicode","unicode4k"]
    wVer: int; wVerClient: int
    crypt_method: Literal["none","permute","cyclic","wip","unknown"]
    is_encrypted: bool                    # True only for wip/unknown
    is_ost: bool
    amap_valid: bool
    file_eof: int; physical_size: int; truncated: bool
```

### 2.4 `ParseOptions` / `RecoveryOptions` (mirror MATT `flags`)

```python
@dataclass
class ParseOptions:
    max_block_size: int = 64 * 1024       # reject larger (DoS guard); 65536 for 4k
    max_recursion_depth: int = 64         # embedded msg / subnode / XBLOCK chains
    max_item_bytes: int = 1 * 1024**3     # per-property cap
    strict_crc: bool = False              # default advisory
    network: bool = False                 # always offline by default
    decode_rtf: bool = True
    resolve_named: bool = True

@dataclass
class RecoveryOptions:
    carve_orphans: bool = True
    carve_slack: bool = True
    rebuild_amap: bool = True             # advisory, in-memory
    brute_force_encode: bool = True
    min_confidence: float = 0.5
    dedup: bool = True
```

### 2.5 Error/warning hierarchy (`errors.py`)

```
PstError
 ├─ NotAPstError              # bad !BDN magic
 ├─ UnsupportedVariantError   # wVer outside known + structure unrecognizable
 ├─ EncryptedStoreError       # bCryptMethod=0x10 (WIP) — clear metadata only
 └─ FatalCorruptionError      # only when even carving yields nothing

ParseWarning  (collected, never raised)  — code + offset + context
  codes: HEADER_CRC_FAIL, AMAP_INVALID, BLOCK_CRC_FAIL, PAGE_CRC_FAIL,
         SIG_MISMATCH, DANGLING_BID, CYCLE_DETECTED, ENTRY_OVERFLOW,
         NAMEID_MISSING, RTF_CRC_FAIL, TRUNCATED_PROP, ORPHAN_BLOCK,
         ENCODE_GUESSED, COMPRESS_FAIL, WIP_ENCRYPTED, OLM_DETECTED
```

**Golden rule:** layers 1–5 *collect* `ParseWarning`s into `store.warnings()`; only `open_store` may raise (the four fatal classes). Everything else degrades.

---

## 3. Data model & lazy/streaming for multi-GB files

### 3.1 The `MapiValue` / `MapiObject` core

`MapiObject` holds **a tag→lazy-value map**, not eagerly-decoded values. Each entry is either:
- inline (≤4B ANSI / ≤8B Unicode) — value already in the property row, or
- a *deferred reference* — an `HNID` (HID into a heap allocation) or a subnode `NID`, resolved on first access.

```python
class _PropEntry:
    tag: int
    ptype: int
    inline: bytes | None          # set if value fit inline
    ref: HNID | int | None        # HID or subnode NID for large values
    resolver: Callable[[], bytes] # closure capturing the HN/subnode source
```

Decoding (codepage, RTF, FILETIME) happens **on `.value`/`.render()` access**, memoized. This means opening a 50 GB store and iterating subjects never materializes bodies/attachments.

### 3.2 Lazy/streaming strategy for multi-GB files

- **`io.reader.ByteReader`**: `mmap` the file when ≤ platform addressable; else a windowed pread reader. All access is `read(offset, length)` with a single `assert 0 <= offset and offset+length <= physical_size` bounds guard (the §2 "never read past EOF" invariant). `effective_eof = min(header.ibFileEof, physical_size)`.
- **No full-tree preload.** NBT/BBT pages are loaded **on demand** during traversal and cached LRU (`io.cache`, keyed by page BID / file offset, default 64 MB budget, configurable). `Store.folders()` and `Store.messages()` are generators doing lazy DFS — folder hierarchy expands node-by-node.
- **Block-chain streaming.** `block.read_node_data(nid)` returns a *lazy byte source* over the XBLOCK/XXBLOCK BID chain; large attachment bodies (`PR_ATTACH_DATA_BIN`) are exposed as a `BinaryIO`-like stream (`attachment.open()`), never buffered whole. MATT child `Structure`s receive bytes via a streaming `generate_struct` path.
- **Subnode laziness.** A message's recipient/attachment TCs live in its subnode tree (`bidSub`); we parse the subnode B-tree only when `.recipients`/`.attachments` is touched.
- **Memory caps.** `ParseOptions.max_item_bytes` and `max_block_size` reject pathological sizes (`cb > 65536` etc.) → `ParseWarning`, not allocation.
- **Iterator contract.** All public enumerators (`folders`, `messages`, `embedded_messages`, `recover().items`) are generators with cycle guards (visited-NID/BID sets), so a 10-million-message store streams at constant memory.

### 3.3 Version-parametric structs

A single `Variant` descriptor drives all size-dependent parsing (avoids hard-coded offsets — the dossier's #1 quirk source):

```python
@dataclass(frozen=True)
class Variant:
    name: str                      # ansi | unicode | unicode4k
    wide: bool                     # 64-bit BID/IB/NID-extension
    page_size: int                 # 512 or 4096
    page_trailer: int              # 12 / 16 / (4k) per §4.4
    block_trailer: int             # 12 / 16 / 24
    bbtentry: int; nbtentry: int; btentry: int
    root_offset: int               # 0x004C ansi / 0x0054 unicode
    bid_size: int; ib_size: int
    max_block: int                 # 8192 / 65536
    compress: bool                 # 4k OST deflate possible
```

Every reader takes a `Variant`. ANSI/Unicode/4K differences are *data*, not branches scattered through code.

---

## 4. The NDB reader

### 4.1 Header detection (all `wVer`)

`ndb/header.py::detect()`:

1. Read 4 bytes @0x0000; require `21 42 44 4E` (`!BDN`) → else `NotAPstError`.
2. Read `wMagicClient` @0x0008 (`53 4D` `SM` expected; mismatch → `ParseWarning(SIG_MISMATCH)`, continue).
3. Read `wVer` @0x000A (LE u16). Classify (**offsets spec-verified — see Appendix A**):
   - 14,15 → **ANSI** (`root` @**0x00A4**, 40-byte ROOT, 12-byte trailers).
   - 23–35 → **Unicode** (`root` @**0x00B4**, 72-byte ROOT, 16-byte trailers).
   - 36,37 → **Unicode 4K** (page_size=4096, expanded trailers, deflate possible). `wVer=37` specifically signals a store that *may* be WIP-protected (`bCryptMethod=0x10`).
   - else → **brute-force structural inference** (§7.3): try Unicode then ANSI layout, pick the one whose ROOT BREFs land on valid `ptype=0x80/0x81` pages → emit `ENCODE_GUESSED`.
4. Read `bCryptMethod` @**0x0201** (Unicode) / @**0x01CD** (ANSI) — fixed offsets from MS-PST §2.2.2.6, resolved via `Variant` (**Appendix A**; the dossier's 0x0219/0x01A9 were wrong): `0x00 none, 0x01 permute, 0x02 cyclic, 0x10 wip`. `0x10` (`NDB_CRYPT_EDPCRYPTED`) → `EncryptedStoreError` (or clear-metadata mode if requested). Unknown → mark `crypt=unknown`, defer to encode brute force.
5. Parse `ROOT` (`ibFileEof, ibAMapLast, cbAMapFree, BREFNBT, BREFBBT, fAMapValid`). `fAMapValid != 0x02` → `ParseWarning(AMAP_INVALID)` (read-only safe — AC-3).
6. Compute `dwCRCPartial`(471B) & `dwCRCFull`(516B/ANSI variant). Mismatch → `HEADER_CRC_FAIL` warning; **do not** abort (AC-4). `strict_crc=True` still only warns for header (we always try to read).

`probe()` stops after step 5 — cheap variant/encryption triage for MATT dispatch.

### 4.2 B-tree walk (NBT & BBT)

`ndb/btree.py::BTreeWalker` is generic over `Variant` and `key_kind ∈ {NID, BID}`:

- Descend from `ROOT.BREFNBT`/`BREFBBT`. For each `BTPAGE`:
  - Validate `PAGETRAILER.ptype == 0x81` (NBT) / `0x80` (BBT) and `ptype == ptypeRepeat` (single-bit-error check). Mismatch → skip page, `PAGE_CRC_FAIL`/`SIG_MISMATCH`, attempt sibling (graceful degradation).
  - Validate `dwCRC` (advisory). Iterate entries using **`cbEnt` stride** (never `sizeof`), `cEnt` count, guarding `cEnt ≤ cEntMax` and `cEnt*cbEnt + trailer ≤ page_size` (→ `ENTRY_OVERFLOW`, clamp).
  - If `cLevel > 0`: `BTENTRY` (btkey + child BREF); validate child IB in-bounds & aligned; **cycle guard** via visited-page-offset set (`CYCLE_DETECTED` → prune).
  - If `cLevel == 0`: emit `NBTENTRY`(nid, bidData, bidSub, nidParent) / `BBTENTRY`(BREF, cb, cRef).
- Verify key monotonicity per page; out-of-order → `ParseWarning`, fall back to **linear scan** of that leaf (real-world Aspose/legacy quirk).
- Build two in-memory indexes lazily but cache fully once first full walk requested: `nbt: dict[nid, NBTENTRY]`, `bbt: dict[bid, BBTENTRY]`.

### 4.3 Block reassembly

`ndb/block.py`:

- `resolve_block(bid)` → `BBTENTRY` → read `cb` bytes @ `ib`; locate trailer at the 64-byte-aligned end; verify `BLOCKTRAILER.bid == bid` and `cb`. CRC over **`cb` bytes only** (exclude padding — the explicit spec rule). Mismatch → `BLOCK_CRC_FAIL`, still return data (CRC advisory; AC-4 spirit).
- **Internal bit** (`bid & 2`): `1` → intermediate (XBLOCK/XXBLOCK/SLBLOCK/SIBLOCK), `0` → data.
- `read_node_stream(nid)`:
  - If `bidData` is a data block → that's the stream.
  - If XBLOCK (`btype=0x01,cLevel=1`) → iterate `rgbid[]`, concatenate child data blocks in order, length-checked vs `lcbTotal`.
  - If XXBLOCK (`cLevel=2`) → fan out to XBLOCKs then data. **Depth-limited** (`max_recursion_depth`) + cycle-guarded (`CYCLE_DETECTED`).
  - 4K-OST: if BBT marks block deflate-compressed (`cb < lcbTotal`/flag), `zlib.decompress`; on failure → `COMPRESS_FAIL`, emit raw bytes flagged.

### 4.4 PAGETRAILER / BLOCKTRAILER layout table (resolved by `Variant`)

| Field | ANSI offset (from trailer start) | Unicode | 4K-OST |
|---|---|---|---|
| ptype | +0 | +0 | +0 |
| ptypeRepeat | +1 | +1 | +1 |
| wSig | +2..3 | +2..3 | +2..3 |
| dwCRC | +8..11 (ANSI: after bid) | +4..7 | +4..7 |
| bid | +4..7 | +8..15 | +8..15 |
| trailer size | 12 | 16 | 16/24 (empirically; see open Q) |

`page.py` reads via the `Variant`-supplied offsets; the ANSI dwCRC/bid swap (dossier's "memcpy will fail") is encoded as data.

### 4.5 Decryption: NONE / PERMUTE / CYCLIC

`ndb/crypt.py`, applied to **data blocks only** (NDB metadata, B-trees, AMap are never encrypted):

- **Embed `mpbbCrypt[768]`** (mpbbR/mpbbS/mpbbI, 256 each) as a module constant, validated by a self-checksum at import (catch truncation). Load once, reuse.
- `decode_none(b)` → identity.
- `decode_permute(b)`: per byte `b = mpbbI[mpbbS[mpbbR[b]]]` (decode path). Symmetric tables; correct direction per encode/decode.
- `decode_cyclic(b, bid)`: `dwKey = bid & 0xFFFFFFFF; w = (dwKey ^ (dwKey>>16)) & 0xFFFF`; per byte the documented add/permute/sub/decrement sequence, `w++` each byte.
- Decode happens **before** CRC validation and before LTP parsing. For 4K-OST: **decompress then decode** (order matters; compression is the outer layer per dossier).
- **Encode brute force** (recovery): if `crypt=unknown` or post-decode bytes lack MAPI structure (no HN `bSig=0xEC`, no plausible property tags), try {none, permute, cyclic}; pick the candidate whose decoded block yields a valid HN signature / passes CRC (`encode_detect.py`, §7.5).

### 4.6 CRC & signature (advisory)

`ndb/crc.py` (**spec-verified against MS-PST §5.3 — see Appendix A**):
- MS-PST CRC is **standard CRC-32, poly `0xEDB88320` (reflected)**, but with **seed `0x00000000` and NO pre/post inversion** (unlike zlib's `0xFFFFFFFF` init + final XOR). The spec ships it as a slicing-by-8 implementation (`CrcTableOffset32..88`); `CrcTableOffset32` *is* the standard CRC-32 table. Tables embedded and import-time checksummed; a byte-wise fallback (`crc32_slow`) guarantees correctness. (gemini's "CRC-32C/Castagnoli `0x1EDC6F41`" review finding is **rejected** — verified wrong.) **Locked by a test vector against the MS-PST sample header CRC.**
- `ComputeSig(ib, bid)` = `WORD((x >> 16) ^ x)` where `x = ib ^ bid` — the simple XOR-fold of MS-PST §5.5 (gemini's "CRC-16 over page data" finding is **rejected** — verified wrong).
- All CRC/sig checks **advisory by default**: failures produce `ParseWarning`, never halt — this is precisely where libpff over-rejects and we don't.

### 4.7 Subnode tree

`ndb/subnode.py`: `NBTENTRY.bidSub` roots a separate SLBLOCK(leaf)/SIBLOCK(intermediate) tree (distinct ptypes). `iter_subnodes(bidSub)` yields `(internal_nid, bidData, bidSub)` — the source of message recipient/attachment TCs and embedded-message PCs. Same cycle/depth guards.

`ndb/nodedb.py` is the NDB facade: `NodeDatabase.node(nid) → NodeRef(data_stream, subnodes)` — the *only* surface the LTP layer consumes.

---

## 5. The LTP reader

### 5.1 Heap-on-Node (`ltp/heap.py`)

- Parse `HNHDR` @0 of node's first data block: `ibHnpm`(u16), `bSig`(0xEC — else not an HN → bail/`ParseWarning`), `bClientSig`(0xBC PC / 0x7C TC / 0xB5 BTH), `hidUserRoot`(HID), `rgbFillLevel`.
- Continuation blocks use `HNPAGEHDR`/`HNBITMAPHDR` (treated identically — we scan `ibHnpm`).
- `HNPAGEMAP` @`ibHnpm`: `cAlloc`,`cFree`,`rgibAlloc[cAlloc+1]`. Allocation `i` spans `[rgibAlloc[i], rgibAlloc[i+1])`.
- `resolve_hid(hid)`: split `hidType`(bits0-4, must be 0), `hidIndex`(bits5-15, **1-based**, reject 0 → `ParseWarning`), `hidBlockIndex`(bits16-31; 4K-OST: 13 bits + 3 flag bits). Index into the right block's HNPAGEMAP → raw allocation bytes.
- **Recovery hook**: if HNPAGEMAP is stale/truncated, `recovery.orphan.rebuild_hnpagemap()` re-scans the heap for structure signatures (BTHHEADER 0xB5, TCINFO 0x7C, PC record patterns) to reconstruct `rgibAlloc` (§8).

### 5.2 BTree-on-Heap (`ltp/bth.py`)

- `BTHHEADER`(8B): `bType=0xB5`, `cbKey∈{2,4,8,16}`, `cbEnt`, `bIdxLevels`, `hidRoot`.
- If `bIdxLevels=0` → leaf records `(key[cbKey], data[cbEnt])` tightly packed. Else intermediate `(key, HID)` pairs; binary search by key, recurse to leaves.
- Validate key ordering; out-of-order/duplicate → `ParseWarning` + linear scan / dedup (keep-first), so corrupted BTHs still yield properties.

### 5.3 Property Context (`ltp/pc.py`)

- `bClientSig=0xBC`; `hidUserRoot` → BTH with `cbKey=2`(wPropId), `cbEnt=6`(wPropType + dwValueHnid).
- For each record:
  - tag = `(wPropId<<16)|wPropType`.
  - **Inline vs HID vs subnode** — the PC BTH record is `cbEnt=6` = `wPropType(2)` + `dwValueHnid(4)` in **both** ANSI and Unicode, so **only 4 bytes are ever inline** (Appendix A; codex finding confirmed — the dossier's "≤8B Unicode inline" was wrong). Decision:
    - Fixed types ≤4B (`PtypInteger16/32`, `PtypBoolean`, `PtypFloating32`, error/enum) → value is `dwValueHnid` inline.
    - Fixed types >4B (`PtypInteger64`, `PtypFloating64`, `PtypTime`, `PtypCurrency`, `PtypGuid`) → `dwValueHnid` is an **HNID** (HID or subnode NID), never inline.
    - Variable (String/Binary/MV) ≤3580B → HNID is an **HID** → heap allocation; >3580B → HNID is a **subnode NID** → resolve via `NodeRef.subnodes`.
    - **Classify by HNID low bits first** (HID has `hidType==0`), then validate against the type's expected size (codex: don't infer HID/NID from a guessed length).
  - **MV types** (`0x1000` flag): per dossier layout — `ulCount`, then for fixed-width MV an array of N items; for variable-width MV an offset table + N length-prefixed blocks. `pc.read_mv()` handles both, validating monotonic offsets (corrupt → carve boundaries, §8).
- Output: populates a `MapiObject` with lazy `_PropEntry`s (§3.1). No eager decode.

### 5.4 Table Context (`ltp/tc.py`)

- `bClientSig=0x7C`; `hidUserRoot` → `TCINFO`: `bType=0x7C`, `cCols`, `rgib[4]`(TCI_4b/2b/1b/bm group ends), `hidRowIndex`(BTH), `hnidRows`(HNID→Row Matrix), `rgTCOLDESC[cCols]`.
- `TCOLDESC`(8B): `tag`, `ibData`(row offset), `cbData`(width), `iBit`(CEB index).
- **Row Matrix** in subnode (`hnidRows`): rows fixed size `rgib[TCI_bm]`, never span blocks → `rows_per_block = (block_size - trailer)//row_size`. Row layout: 8/4B group, 2B group, 1B group, then **CEB bitmap** (`iBit` → present/null).
- `iter_rows()` resolves `dwRowID → RowIndex` via `hidRowIndex` BTH (or, if corrupt/`hidRowIndex=0`, **linear scan with CEB validation** — recovery path). Each row → a `MapiObject` view.
- Variable-width columns store an HNID in the cell → resolved like PC values.

The LTP layer's single output contract: a node becomes **either** a `MapiObject` (PC) **or** an iterable of `MapiObject` rows (TC). Messaging layer composes these.

---

## 6. The messaging reader

### 6.1 Store bootstrap (`messaging/store.py`)

1. `Store(nodedb)` → resolve `NID_MESSAGE_STORE (0x21)` PC. Missing → recovery bootstrap (§7) scanning for the message-store PC signature; if truly absent → still carve folders/messages and synthesize a `RECOVERED` root.
2. Extract `PidTagDisplayName (0x3001)`, `PidTagRecordKey (0x0FF9)`, `PidTagIpmSubTreeEntryId (0x35E0)` → root IPM folder EntryID → NID, `PidTagPstPassword (0x67FF)` (CRC-32 hash; we **bypass** it — read access needs no password; flag if present).
3. Load `NamedPropMap` from `NID_NAME_TO_ID_MAP (0x61)` (§6.6).

### 6.2 Folders (`messaging/folder.py`)

A folder = **PC (nidType 0x02 normal / 0x03 search) + 3 TCs** sharing `nidIndex`:
- Hierarchy TC `nidType=0x0D` (subfolders, one row each; `PidTagEntryId` → child NID).
- Contents TC `nidType=0x0E` (messages; `mfDeleted 0x4000` rows surfaced as soft-deleted).
- FAI TC `nidType=0x0F` (associated/system items; `include_fai=True` to surface).

`subfolders()`/`messages()` are lazy DFS with a **visited-NID cycle guard** (`CYCLE_DETECTED` → orphan the subtree, AC-style graceful). `path` built from display names; cyclic parent → relocate under synthetic `LostAndFound`.

**Dumpster detection** (`is_dumpster`): folder with `PidTagContainerClass = IPF.Ipm.Wastebasket` / name "Recoverable Items", subfolders Deletions/Versions/Purges/DiscoveryHolds → soft-deleted item source (§8).

### 6.3 Messages (`messaging/message.py`)

Message = top-level node (`nidType 0x04` normal / `0x08` FAI), PC + subnode tree:
- Subnode Recipient TC (`nidType 0x12`, template 0x692) — required; absent → `ParseWarning`, empty list.
- Subnode Attachment TC (`nidType 0x11`, template 0x671) — optional.
- Subnode Attachment PCs (`nidType 0x05`, one per attachment).
- Subnode LTP raw (`nidType 0x1F`) — optional.

`Message` *is-a* `MapiMessage` (§5.3 PC populates it). `recipients`/`attachments`/`embedded_messages` are lazy.

### 6.4 Recipients (`messaging/recipient.py`)

One per Recipient-TC row: `PidTagDisplayName`, `PidTagEmailAddress`, `PidTagAddressType` (SMTP/EX/X500), `PidTagRecipientType` (1=To,2=Cc,3=Bcc), `PidTagEntryId` (→ EntryID renderer → SMTP, §9.4). Surfaced as `MapiRecipient`.

### 6.5 Attachments (`messaging/attachment.py`)

Per Attachment PC: `PidTagAttachFilenameW`/`AttachLongFilename`, `PidTagAttachSize`, `PidTagAttachMethod`, `PidTagAttachMimeTag`. **`PidTagAttachMethod` enum (Appendix A; codex confirmed — the dossier had embedded/OLE swapped):** `0=afNone`, `1=afByValue`→`PidTagAttachDataBinary (0x37010102)`, `2=afByReference`, `3=afByReferenceResolve`, `4=afByReferenceOnly`, **`5=afEmbeddedMessage`** → nested Message via subnode `PidTagAttachDataObject (0x3701000D, PtypObject)`, **`6=afStorage`** (OLE/`PtypObject`). Use **full type-qualified tags** (`0x3701000D` for embedded object vs `0x37010102` for binary) — `0x3701` alone is ambiguous.
- ByValue → `attachment.open()` streams `PR_ATTACH_DATA_BIN` (no full buffer; feeds MATT `generate_struct`).
- `afEmbeddedMessage (5)` → `embedded_messages()` recurses into the subnode PC, depth-limited & cycle-guarded.

### 6.6 Named-property map (`messaging/nameid.py`)

`NID_NAME_TO_ID_MAP (0x61)` PC streams:
- GUID Stream (`PidTagNameidStreamGuid`) — array of 16-byte GUIDs.
- Entry Stream (`PidTagNameidStreamEntry`) — `NAMEID`(8B): `dwPropertyID`, `N` flag, `wGuid` (0 none,1 PS_MAPI,2 PS_PUBLIC_STRINGS,≥3 → GUID[(wGuid-3)]), `wPropIdx` → NPID `0x8000+wPropIdx`.
- String Stream (UTF-16LE) — for `N=1` string names.

`NamedPropMap.resolve(npid) → (GUID, name|lid)` and reverse. Missing/corrupt map → `NAMEID_MISSING`; named props display as numeric `0x8xxx` (AC-5).

---

## 7. The RECOVERY ENGINE

`recovery/engine.py::RecoveryEngine` runs an ordered **fallback cascade**; each stage feeds candidates to a scorer (§7.7) and the deleted/orphan engine (§8). The cascade is the differentiator vs readpst/libpff.

### 7.1 Stage 0 — Trusted walk (fast path)

Normal NBT/BBT traversal (§4.2). Mark every reached `(nid, bid)`. If it completes with a valid message store → most items come from here at confidence **1.0**. Defects encountered (skipped pages, bad CRCs) are logged but don't stop the walk.

### 7.2 Stage 1 — Signature carving (`recovery/carve.py`)

When roots are invalid/zero, or to find what the trusted walk missed:

```
for off in range(0, effective_eof, stride):     # stride = 64 (data) or page_size
    trailer = read_trailer_candidate(off)
    if trailer.ptype in {0x80,0x81} and trailer.ptype==trailer.ptypeRepeat:
        if page_crc_ok(off) or structurally_plausible(off):
            register_btpage_candidate(off)
    elif looks_like_blocktrailer(off):          # bid range, cb sane, alignment
        if block_crc_ok(off): register_block_candidate(off)
```

False-positive suppression: require CRC match **or** (valid bid range ∧ aligned ∧ adjacent-page consistency). Zeroed regions (`ptype=0x00`) rejected.

### 7.3 Stage 2 — BBT/NBT rebuild (`recovery/rebuild.py`)

From carved leaf pages/blocks:
- Collect all `BBTENTRY` candidates → `bbt_rebuilt: dict[bid → (ib,cb)]`.
- Collect all `NBTENTRY` candidates → `nbt_rebuilt: dict[nid → (bidData,bidSub,nidParent)]`.
- Resolve `bidData`/`bidSub` against `bbt_rebuilt`; dangling → `DANGLING_BID`, keep node but mark data-missing.
- Reconstruct folder DAG from `nidParent` + Hierarchy-TC rows; cross-validate; cycles → `LostAndFound`.
- Overlapping allocations → arbitrate by `cRef` then lower-NID priority (§7.7), losers flagged.

### 7.4 Stage 3 — AMap reconstruct (advisory, `recovery/rebuild.py`)

Spec §2.6.1.3.7 algorithm, **in-memory only** (non-destructive, N1):
1. New all-free bitmap.
2. Walk (trusted or rebuilt) NBT: mark each `bidData`/`bidSub` block's 64B granules allocated.
3. Walk BBT: mark every block allocated.
4. Set advisory `fAMapValid=0x02`.

Used to compute **free space** for slack/orphan carving (§8): `free = allocated_per_rebuilt_amap XOR on-disk-amap` ⇒ candidate deleted regions. Never written to the file.

### 7.5 Stage 4 — Encode-method brute force (`recovery/encode_detect.py`)

If header `crypt=unknown`, or decoded blocks don't yield valid HN (`bSig=0xEC`) / sane property tags:
- Independently test ANSI-vs-Unicode structural layout (compare valid-entry counts per §dossier) and {none,permute,cyclic} on a sample of data blocks.
- Score by: HN signature present, CRC pass-rate, fraction of plausible MAPI tags (`0x0000–0x7FFF` or `0x8000–0x8FFF`).
- Pick max-score combo; apply store-wide; emit `ENCODE_GUESSED`. Per-block fallback for mixed-encryption files (try decode, else plaintext, flag per block).

### 7.6 Stage 5 — Cross-validation & messaging parse

Every rebuilt/carved node is handed to the **real LTP+messaging parser** (§5–6). A candidate "message" only counts if it produces a PC with a plausible `PidTagMessageClass` (`IPM.*`) or a recognizable envelope (subject/sender/recipients). This rejects carving false-positives that scoring alone misses.

### 7.7 Candidate scoring (`recovery/score.py`)

Each recovered item gets a 0..1 **confidence** = weighted sum of normalized signals:

| Signal | Weight | Source |
|---|---|---|
| reached by trusted B-tree walk | 0.40 | Stage 0 |
| block CRC valid | 0.15 | §4.6 |
| page/trailer signature valid | 0.10 | §4.2 |
| parent NID resolves (acyclic) | 0.10 | §7.3 |
| LTP parse → valid PC + `IPM.*` class | 0.15 | §7.6 |
| `cRef` consistent (no overlap loss) | 0.05 | §7.3 |
| not in slack/free per rebuilt AMap | 0.05 | §7.4 |

Mapped to bands: **1.0** tree-reached & CRC-clean; **0.95** Deleted-Items/dumpster soft-deleted; **0.7–0.85** hard-deleted carved w/ valid CRC+class; **0.5–0.7** slack fragment / partial; **<0.5** unattributed (suppressed unless `min_confidence` lowered). Overlapping-allocation arbitration uses these scores; losers flagged `OVERLAP_LOSER`, both retained in forensic output.

### 7.8 `integrity_score`

`RecoveryResult.integrity_score` = (% of NBT/BBT pages with valid CRC) × (% nodes parsed without warning) — an honest, single-number file-health summary surfaced to MATT.

---

## 8. The DELETED / ORPHAN / SLACK reconstruction engine

`recovery/orphan.py`. Distinguishes four states with distinct algorithms and confidence:

### 8.1 Soft-deleted (confidence ~0.95)

- **Deleted Items folder** contents are recovered by **normal traversal** — they remain fully referenced by the folder's Contents TC. There is **no `mfDeleted` bit at `0x4000`** in `PidTagMessageFlags` (Appendix A; codex confirmed — that test is removed). "Soft-deleted" here means *folder location*, not a flag. (For completeness we still surface the real `PidTagMessageFlags` bits — `mfRead 0x01`, `mfUnsent 0x08`, `mfUnmodified 0x02`, `mfFAI 0x40`, `mfHasAttach 0x10`, etc. — none of which encode deletion.)
- **Exchange dumpster / Recoverable Items** (`is_dumpster`, §6.2): parse Deletions/Versions/Purges/DiscoveryHolds subfolders explicitly (these are *not* user-visible — libpff/readpst miss them). For the deletion timeline use a **provenance-ranked candidate set** rather than a guessed constant (Appendix A; codex flagged the dossier's `0x6039/0x85FF` as unverified): resolve `PidTagDeletedOn` and related timestamps **via the named-property/MS-OXPROPS catalog at runtime**, recording which property supplied the value.

### 8.2 Hard-deleted (confidence ~0.7–0.85)

Node removed from NBT, block AMap-freed but data unzeroed:
1. **Primary free-space source = everything NOT covered by the rebuilt live BBT** (full-file span minus all `[ib, ib+cb)` of reachable blocks). This is the robust signal (codex+gemini both flagged XOR-of-AMaps as unsound — see §7.4 and Appendix A). The AMap delta (`on-disk-free` vs `rebuilt-reachable`) is a **secondary, lower-confidence** heuristic, and the three sets are reported separately: `on_disk_free`, `not_in_rebuilt_bbt`, `disagreement`.
2. Carve for `BLOCKTRAILER` signatures in that free space — require **all** of: valid trailer `cb`, normalized-`bid` in range, 64B (or 4K) alignment, signature match, AND a successful downstream HN/LTP parse before promoting to an item (codex: signature stride-scan alone yields many false positives).
3. For each candidate block: scan for HN `bSig=0xEC` + `bClientSig=0xBC` (PC). If found → parse as message PC; require `PidTagMessageClass` to confirm.
4. **Recovery classes** (codex: don't imply full reconstruction): `pc_plus_subnode` (top-level entry survived → recipients/attachments recoverable), `pc_body_only` (no `bidSub` → envelope/body only), `attachment_or_recipient_orphan`, `partial_fragment`. A hard-deleted NBTENTRY usually takes its `bidData`/`bidSub` binding with it, so most carves are `pc_body_only` and labelled `TRUNCATED` accordingly.

### 8.3 Orphan PC detection (confidence ~0.6–0.8)

Blocks allocated per AMap but unreachable from any folder Contents/Hierarchy TC:
- Build reachability set from Stage-0/3 walk; allocated-but-unreached blocks = orphans.
- Parse each as PC; attribute via `PidTagParentEntryId`/`nidParent` if it still resolves to a known folder, else `LostAndFound`.

### 8.4 Slack-space items (confidence ~0.5–0.7)

Within an *allocated* block, bytes after the live HNPAGEMAP-tracked region (property shrank, old bytes unzeroed):
- After parsing live allocations, scan remaining block bytes for additional property-tag sequences / string signatures / GUIDs.
- Extract as fragments flagged `SLACK`, lower confidence, no envelope guarantee.

### 8.5 Attribution & confidence flags

Each `RecoveredItem` carries:
```python
class RecoveryMeta:
    method: Literal["btree","dumpster","carve_hard","orphan_pc","slack"]
    confidence: float
    deleted_on: datetime | None        # PidTagDeletedOn
    attributed_folder: str | None      # resolved or "LostAndFound"
    attribution_confidence: float
    truncated: bool
    flags: set[str]                    # CRC_FAIL, OVERLAP_LOSER, NAMEID_MISSING ...
```

### 8.6 Dedup (`recovery/dedup.py`)

Hard-deleted items get re-carved from multiple slack copies. Dedup key = SHA-256 of normalized envelope (`from|to|subject|client_submit_time`) or, if envelope incomplete, of the full PC raw bytes. Keep highest-confidence instance; record `duplicate_count`. Suppresses the dossier's "duplicate carving" problem.

### 8.7 Guards

- Sub-node BID cycle detection (visited set) → bounded traversal.
- 4K-OST carving aligns to 4096 and validates 24-byte trailers (avoid 512-granularity false positives).
- Compressed orphan blocks: attempt inflate; truncated → partial + `COMPRESS_FAIL`.

---

## 9. The property/metadata catalog & human-readable renderers

### 9.1 Shipping a complete MS-OXPROPS dictionary (`catalog/`)

- **Build-time generator** `tools/build_oxprops.py` parses the MS-OXPROPS reference (canonical names, property IDs, types, property sets) into `catalog/oxprops_data.json`: `{ "0x0037": {"name":"PidTagSubject","types":["0x001F","0x001E"],"set":null}, ... }`. Shipped as package data; **no runtime download** (offline, G2).
- `oxprops.py` loads it into `dict[propid → PropDef]`, plus a reverse `name → id`. Unknown tags render as `0x{id:04X}:{type}` with `(undefined)` annotation (distinguish "unset" from "unknown").
- **Coverage tracking** (axis B, §1.3): the generator emits a manifest of all known tags; `scorecard.py` computes decode+render coverage against it.

### 9.2 Named-property resolution

`catalog/namedprops.py` ships well-known set GUIDs (PS_MAPI `00020328…`, PS_PUBLIC_STRINGS `00020329…`, PS_INTERNET_HEADERS `00020386…`, appointment/task/common/address sets) and well-known LIDs (e.g. PidLidReminderSet). `MapiObject.render(tag)` for `tag ≥ 0x8000`: resolve NPID via the store/MSG `NamedPropMap` → `(GUID, name|lid)` → friendly label from the catalog; else `Named[GUID:name]`.

### 9.3 FILETIME / SYSTIME (`render/filetime.py`)

`PT_SYSTIME (0x0040)`: u64 LE, 100-ns since 1601-01-01Z. `unix = (ft - 116444736000000000)/1e7`. Render ISO-8601 UTC. Sentinels: 0 → "never"; `>0x7FFF…` → `(invalid)` + hex. Always UTC (no TZ reinterpretation).

### 9.4 GUID & EntryID (`render/guid.py`, `render/entryid.py`)

- **GUID**: mixed-endian — first 3 groups LE (4+2+2), last 8 as-is → RFC-4122 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Annotate known GUIDs (PS_* set names).
- **EntryID→SMTP**: parse `abFlags`(4B) + `MAPIUID`(16B) + provider data. One-off (`abFlags[0]=0x01`): extract display name / addrtype / email (the SMTP). Store EntryID (`0x00`): server DN + mailbox GUID. EX/X500 addresses surfaced as `/O=…/OU=…`. Truncated → recover available fields, fall back to `PidTagSenderName`. Output `{type, mapiuid, smtp?, x500?, display, raw_hex}`.

### 9.5 Compressed-RTF / LZFu (`render/rtf.py`)

`PR_RTF_COMPRESSED (0x10090102)`: header `COMPSIZE`,`RAWSIZE`,`MAGIC`(`LZFu`=compressed / `MELA`=uncompressed),`CRC`. **Implement strictly from MS-OXRTFCP — do NOT trust the dossier's token formula** (codex+gemini confirmed it wrong; Appendix A). Key spec facts to encode and lock with test vectors: (a) the decompression dictionary is **pre-seeded with the exact static RTF prefix from MS-OXRTFCP §2.1.3.1.2** (the `{\rtf1\ansi\ansicpg1252\deff0\deftab720{\fonttbl…}` string — embed it verbatim and verify its byte length at import, do not hand-wave "standard `{\rtf1…}`"); (b) the dictionary is a **4096-byte circular buffer**; (c) control bytes are processed LSB-first as 8 flags, each flag 0=literal byte, 1=**16-bit big-endian dictionary reference** = 12-bit offset + 4-bit length, with the length field meaning `length+2`. Add a fixture whose body uses a back-reference **into the static dictionary** (the case naive impls get wrong). Validate CRC (the MS-PST CRC, §4.6) → on fail emit best-effort partial RTF + `RTF_CRC_FAIL` (AC-6). Lazy/memoized (`Message.rtf_body`).

### 9.6 Conversation index (`render/convindex.py`)

`PR_CONVERSATION_INDEX (0x0071)`: 1B reserved(`0x01`) + **5B header time** + 16B GUID + N×5B child blocks. **The 5-byte time is NOT "100ms units"** (Appendix A; gemini confirmed): it is a 40-bit value taken from a FILETIME — high 32 bits of the FILETIME, then the next 8 bits — reconstructed per MS-OXOMSG §2.2.1.3 by masking the low bits to zero. Each child block = the next bits of a FILETIME delta (encoded as a 31-bit value scaled by either 1.0s or `1/256` s per the high bit) + 4-bit random + 1-bit sequence. Render as a thread tree with absolute UTC times. Length not `22+5N` → `(corrupt)` but parse what's there. **Lock with a test vector** decoded from a known message.

### 9.7 Codepage-correct strings (`render/strings.py`)

- `PT_UNICODE (0x001F)` → UTF-16LE (strip stray BOM).
- `PT_STRING8 (0x001E)` → codepage resolved by **precedence** (Appendix A, gemini): message-level `PidTagInternetCodepage (0x3FDE)` → `PidTagMessageCodepage (0x3FFD)` → store-level `PidTagStoreSupportMask`/`PidTagCodePageId` → `PidTagMessageLocaleId` (LCID→codepage) → default 1252; map 65001→utf-8, 932→shift_jis, 936→gbk, 950→big5, etc. On decode failure → `charset-normalizer` fallback, then latin-1, record detected encoding in `MapiValue.encoding`. Mixed ANSI/Unicode hybrids (Mac/3rd-party) handled per-property via type inspection.

### 9.8 Other typed decoders

`PT_CURRENCY` (**signed int64 scaled by 10000 → fixed-4-decimal**, e.g. `12.3400`; render as a plain decimal with **no currency symbol** unless a locale property supplies one — Appendix A, codex confirmed `$x.xx`/2-decimal was wrong), `PT_APPTIME` (OLE automation date: f64 days since 1899-12-30), `PT_BOOLEAN`→True/False, `PT_BINARY` hex+ASCII preview with magic annotation (JPEG/ZIP/ELF), `PT_OBJECT`. Every `PtypXxx` and its `0x1000` MV variant has a decoder (axis-B gate: 100% of type codes).

---

## 10. Native MSG parser & `MsgAnalyzer` migration

### 10.1 Native MSG parser (`pstforensic/msg/`)

CFBF/OLE container (`msg/cfbf.py`) wrapping **`olefile`** (already a MATT `office` extra dep), plus an **orphan-FAT scan** for deleted recipient/attachment storages. `msg/parser.py::MsgParser` builds a **`MapiMessage`** (same layer-5 object as PST messages):

- **`__properties_version1.0`** → a header (whose size depends on the storage *role*: **8 bytes** for the top-level message store vs **24 bytes** for embedded-message/recipient/attachment storages — Appendix A, codex; this is NOT an "8B/16B ANSI/Unicode" split) followed by **16-byte fixed property entries** (`propTag(4)` + `flags(4)` + `value/reserved(8)`). Fixed types ≤8B stored inline in the entry; variable/large types referenced by a `__substg1.0_*` stream.
- **`__substg1.0_<TAG>`** streams → variable-length values (strings, binary, RTF, MIME). **Naming is `__substg1.0_%08X` using the full 8-hex-digit property tag** (id<<16 | type), e.g. subject = `__substg1.0_0037001F` (Appendix A, codex — there is no `0x1000 + tag` transform). MV instances get an index suffix `-%08X`.
- **`__nameid_version1.0`** storage → the three named-prop streams `__substg1.0_00020102` (GUID), `__substg1.0_00030102` (entry), `__substg1.0_00040102` (string) — sharing `catalog/` and the `render/` GUID logic (`msg/nameid.py`). Same `NAMEID` bit-packing as the PST name-to-id map.
- **`__recip_version1.0_#NNNNNNNN`** → `MapiRecipient` (type flags To/Cc/Bcc, EntryID→SMTP).
- **`__attach_version1.0_#NNNNNNNN`** → `MapiAttachment`; embedded `__substg1.0_3701000D` → recursive `MsgParser` (depth-limited).
- **RTF body** via shared `render/rtf.py`. **S/MIME** (`IPM.Note.SMIME`): expose the single opaque MIME attachment for downstream tools (no in-proc decrypt, N6).
- **Recovery**: orphan storage recovery (FAT free-block carve), partial-property reconstruction, FAT-cycle break — sharing scoring philosophy with PST recovery.

Because MSG feeds the **same `MapiMessage`**, every `render/` and `catalog/` capability (FILETIME, GUID, EntryID, named props, RTF, conversation-index) works identically for MSG and PST — fulfilling G6.

### 10.2 `MsgAnalyzer` migration (replace `extract_msg`)

**Strategy: replace, not augment** (cleaner dep graph; `extract_msg`'s forensic gaps are exactly our value-add). Migration is staged to de-risk:

- **Phase A (augment / shadow):** `MsgAnalyzer` keeps `extract_msg` as primary but, when `pstforensic` is installed, runs `MsgParser` in parallel and asserts field parity in tests (`tests/msg/test_parity.py`). No user-visible change. CI proves superset (AC-7).
- **Phase B (flip default):** `MsgAnalyzer` uses `pstforensic.open_msg` as primary; `extract_msg` becomes an *optional fallback* only if native parse raises (it shouldn't — it degrades). New reports added: `recipient_details`, `named_properties`, `rtf_body`, `s_mime_info`, `transport_headers_mapi`, `orphan_items`, `corruption_warnings`. Existing report labels (`summary`, body child Structures) preserved so renderers don't change.
- **Phase C (drop):** remove `extract_msg` from `[msg]` extra; `pstforensic` becomes the dep. `MsgAnalyzer.specificity` stays 20; `compatible_mime_types=['application/vnd.ms-outlook']` unchanged. Child bodies/attachments emitted via existing `self.generate_struct(...)` so MATT's multi-dispatch and IOC aggregation keep working.

A **new `PstAnalyzer`** (added only at M9) handles `application/vnd.ms-outlook-pst` / OST via `pstforensic.open_store`, `specificity=20`, emitting folder tree + per-message child Structures (each message → a `MapiMessage`-backed child the existing `EmailAnalyzer`/IOC pipeline can consume) + a recovery/triage report. Until M9 it is **not** registered in `Analyzers/__init__.py` (G7 gate).

---

## 11. Test strategy & coverage scorecard

### 11.1 Conformance corpus (generated + obtained)

`tests/corpus/` with a generator-first philosophy (mirrors MATT's `conftest.py` synthetic approach — no proprietary data needed for CI):

**Synthetic generators** (`tests/genfixtures/`) — we write *minimal valid* PST/OST/MSG writers (write-side is test-only, never shipped) to emit byte-exact fixtures per variant:
- `gen_ansi.py`, `gen_unicode.py`, `gen_unicode4k.py` — one each: store + 2 folders + 3 messages + 1 attachment + 1 embedded msg + named prop + MV prop + one of each PtypXxx.
- `gen_encrypted.py` — PERMUTE and CYCLIC twins of the Unicode fixture.
- These give deterministic **golden files**: `fixtures/clean/{ansi,unicode,unicode4k,permute,cyclic}.pst`.

**Corruption fixtures** (derived from clean by `tests/corrupt.py` byte-mutators — locked so regressions can't silently revert, per MATT's regression-test policy):
- `truncate_50/90/99` (AC-2), `header_crc_bad` (AC-4), `amap_invalid` (AC-3), `nbt_root_zero`, `bbt_page_corrupt`, `cyclic_parent`, `overlap_alloc`, `dangling_bid`, `encode_mismatch`, `nameid_missing` (AC-5).
- `deleted/` fixtures: soft-deleted (mfDeleted row), hard-deleted (freed block), dumpster items, slack fragment — for §8 with known ground-truth item sets.

**Real-world corpus** (out-of-CI, opt-in via `MATT_PST_CORPUS` env): real Outlook 97/2003/2007/2010/2013/365 PSTs and Exchange OSTs, third-party (Aspose/Independentsoft) generated, gathered per MATT's sample-safety policy (download untrusted samples OK; **static parse only**, no detonation, host-safe by construction since we never execute).

### 11.2 Golden-output snapshots

For each clean fixture, a checked-in `*.golden.json` = full `store.to_dict(human=True)` (folder tree, every message's every property rendered). Tests assert byte-stable output; intentional changes require regenerating + reviewing the diff. This locks property-by-property fidelity.

### 11.3 Property-by-property coverage tracking

`tools/scorecard.py`:
- Loads the MS-OXPROPS manifest; for every tag, checks a decoder + renderer exists and exercises it against a synthesized value → records pass/fail.
- For every `PtypXxx` + MV variant, a dedicated unit test in `tests/render/test_types.py`.
- Emits `coverage_scorecard.json` with axis-B numbers; CI fails if `<99%` tag decode or `<100%` type-code decode.

### 11.4 Fuzz harness

`tests/fuzz/` with `atheris` (or hypothesis-based byte mutation): seed with clean fixtures, mutate, assert **no crash / no >cap memory / no infinite loop / no read past EOF** (AC-8). Run nightly; corpus minimized & checked in for regression. Targets: `header.detect`, `btree.walk`, `block.read_node_stream`, `pc/tc parse`, `rtf.decompress`, `cfbf` parse.

### 11.5 Round-trip & differential testing

- **Round-trip**: generator writes fixture → parser reads → assert structural equality with the generator's intent model.
- **Differential** (`tests/diff/test_vs_libpff.py`, opt-in when libpff/readpst present): for every fixture they can open, assert our extracted message set ⊇ theirs (count, subject, sender, recipient set, attachment SHA-256). Deltas logged per fixture (we expect to *exceed* on corrupted/deleted ones — that's the whole point). Powers axis-D.

### 11.6 Recovery-scenario tests

`tests/recovery/` — each corruption/deleted fixture has an expected `RecoveryResult` (item counts per method, min confidences, dedup counts). Asserts AC-2/3/4/5 and §8 behavior. Cross-checks `integrity_score` monotonicity (more corruption ⇒ lower score).

### 11.7 Coverage scorecard (the proof artifact)

`coverage_scorecard.json` per release:
```json
{
  "axis_A_variants": {"ansi":"pass","unicode":"pass","unicode4k":"pass","permute":"pass","cyclic":"pass"},
  "axis_B_props": {"tag_decode_pct":0.994,"typecode_decode_pct":1.0,"render_pct":0.991},
  "axis_C_coverage": {"ndb_line":0.97,"ndb_branch":0.92,"ltp_line":0.96,"recovery_line":0.95},
  "axis_D_diff": {"clean_superset":true,"corrupted_deltas":{"truncate_90":"+3 items vs readpst(fail)"}},
  "fixtures": {"unicode.pst":"sha256:…"}
}
```
CI gate (`scorecard.py --gate`) fails the build below any threshold in §1.3. **This file is the operational meaning of "100%/proven."**

---

## 12. Risks, hard unknowns, dependencies

### 12.1 Hard unknowns (open questions to resolve before/at their milestone)

| # | Unknown | Resolution plan | Blocks |
|---|---|---|---|
| Q1 | Exact 4K-OST PAGETRAILER/BLOCKTRAILER byte layout & size (16 vs 24) | Empirically diff real Outlook-2013+ OST against Mythicsoft notes; encode in `Variant`; fixtures from real OST | M6 (4K) |
| Q2 | 4K-OST deflate scope (per-block flag location, whole-block?) | Reverse from real OST + BBTENTRY compressed-size field; `COMPRESS_FAIL` fallback if undecidable | M6 |
| Q3 | Subnode page ptypes (SLBLOCK/SIBLOCK exact ptype values) | Inferred from spec + validated against fixtures | M2 |
| Q4 | WIP (`0x10`) — any clear metadata extractable? | Treat as fully opaque; extract only unencrypted header/folder names if present; otherwise `EncryptedStoreError` | M1 |
| Q5 | Spec-noncompliant Outlook CRCs / out-of-order BTPAGE tolerance | Advisory-CRC + linear-scan fallback already designed; validate against real corpus | M5 |
| Q6 | `PidTagDeletedOn` presence across Outlook versions | Empirical audit; degrade to inferred window when absent | M7 |
| Q7 | Mixed-encoding Unicode strings (3rd-party) | Per-property type inspection + charset-normalizer | M4 |
| Q8 | `mpbbCrypt` table variants in the wild | Embed spec table; brute-force-from-known-plaintext recovery if a variant ever appears | M1 |

### 12.2 Engineering risks & mitigations

- **R1 Performance on 50 GB stores** — mitigate: mmap/windowed I/O, LRU page cache, fully lazy iterators, no eager decode (§3.2). Benchmark gate: stream subjects of a synthetic 5 GB / 100k-msg fixture in CI under a time budget.
- **R2 Pure-Python CRC/decode speed** — mitigate: 8-table CRC, vectorize decode with `bytes.translate` for PERMUTE; optional C/Rust accelerator behind the same API (post-ship).
- **R3 Carving false positives** — mitigate: multi-factor validation (CRC ∧ bid-range ∧ alignment ∧ LTP-parse-confirms) + scoring + dedup.
- **R4 Spec drift / our misreading** — mitigate: cite `[MS-PST] §x.y` in every struct's docstring; differential test vs libpff/readpst; golden snapshots.
- **R5 `olefile` limitations for MSG orphan recovery** — mitigate: our own FAT free-block scanner on top of olefile's directory parse.

### 12.3 Dependencies

- **Core (shipped):** none mandatory beyond stdlib (`struct`, `mmap`, `zlib`, `datetime`). Catalog data is package-data JSON.
- **Optional extras** (MATT `pyproject.toml` style): `[mime]` n/a; `[msg]` → `olefile`; `[fuzzy]` charset detection → `charset-normalizer` (already a MATT core dep); `[accel]` (future) → Rust ext.
- **Test-only:** `pytest`, `pytest-cov`, `atheris`/`hypothesis`, and *optionally* `pypff`/`libpst` for differential tests (skipped if absent).
- **No** network, no native-build-required deps for the core (keeps MATT's REMnux/Docker target clean and host-static-safe).

---

## 13. Phased delivery roadmap (M0..M9)

Each milestone lists **what it unlocks** and **how it's verified**. Nothing wires into MATT until **M9** (G7).

| M | Name | Deliverables | Unlocks | Verification gate |
|---|---|---|---|---|
| **M0** | Scaffold & I/O | `io/`, `errors.py`, `flags.py`, `consts.py`, `Variant`, `probe()` stub, CI skeleton, `tools/build_oxprops.py` → `oxprops_data.json` | Project builds; offline-by-construction; catalog shipped | `probe()` returns variant on `!BDN`; `build_oxprops` produces ≥99% tag manifest; CI green |
| **M1** | NDB core (clean) | `header.py` (all wVer detect), `crc.py`, `crypt.py` (NONE/PERMUTE/CYCLIC + mpbbCrypt), `bid_nid.py`, `page.py`, `btree.py`, `block.py` (+XBLOCK/XXBLOCK), `subnode.py`, `nodedb.py` | Walk NBT/BBT, resolve any node's decoded bytes for ANSI+Unicode clean stores | Read `clean/{ansi,unicode,permute,cyclic}.pst`; dump all node bids; CRC self-test; AC-1, AC-4 (header CRC advisory) |
| **M2** | LTP | `heap.py`, `bth.py`, `pc.py`, `tc.py` (inline/HID/subnode, MV) | Properties & tables from nodes | Golden PC/TC dumps on M1 fixtures; every PtypXxx decoded (axis-B type gate) |
| **M3** | Messaging + MAPI model + render | `messaging/*`, `mapi/*`, `render/*` (filetime,guid,entryid,rtf,convindex,strings), `catalog/namedprops` | `Store`, folders, messages, recipients, attachments, embedded; full human rendering | `clean/*` golden `to_dict` snapshots; AC-5 (named props), AC-6 (RTF) |
| **M4** | Native MSG + shared model | `msg/*`, `export/eml.py`,`json.py`, MSG↔MAPI parity harness | MSG parsing on shared model; export | AC-7 superset vs `extract_msg` on `tests/msg/`; round-trip EML |
| **M5** | Corruption tolerance | `recovery/carve.py`,`rebuild.py`,`encode_detect.py`,`score.py`,`engine.py` Stages 0–5 | Read corrupted stores readpst/libpff reject | AC-2 (truncation), AC-3 (amap), nbt_root_zero, encode_mismatch fixtures; `integrity_score` |
| **M6** | 4K-OST & compression | `Variant` unicode4k, deflate in `block.py`, resolve Q1/Q2 from real OST | Outlook 2013+ cached-mode OST, compressed blocks | `clean/unicode4k.pst` + real-OST corpus (opt-in); `COMPRESS_FAIL` fallback test |
| **M7** | Deleted/orphan/slack | `recovery/orphan.py`,`dedup.py`; dumpster parsing; attribution/confidence | Forensic recovery of deleted/orphaned/slack items | `deleted/*` fixtures with ground-truth item sets; confidence bands; dedup counts |
| **M8** | Hardening & scorecard | fuzz harness, differential tests, perf benchmark, `tools/scorecard.py --gate`, full docs w/ `[MS-PST]` cites | Provable completeness; CI gates enforced | Fuzz nightly clean; axis A–D thresholds met; `coverage_scorecard.json` emitted; 5 GB perf budget |
| **M9** | Wire into MATT | Migrate `MsgAnalyzer` (Phase A→B→C), add `PstAnalyzer` (`application/vnd.ms-outlook-pst`/OST), register in `Analyzers/__init__.py`, `pyproject` extras, `--check` deps | PST/OST/MSG triage inside MATT pipeline, IOC aggregation, child-Structure emission | All MATT tests pass; MSG parity in MATT; `PstAnalyzer` emits per-message child Structures + recovery report; **scorecard gate green = ship** |

**Critical path:** M0→M1→M2→M3 unlocks clean reads; M5 unlocks recovery; M6 unlocks 4K-OST; M7 unlocks deleted-item forensics; M8 *proves* it; M9 ships into MATT. M4 (MSG) can proceed in parallel after M3 since it reuses layers 5–6 without needing NDB/LTP.

**Ready-to-wire definition (end of M9):** every acceptance criterion (§1.4) passes in CI, the coverage scorecard meets all four axis gates, `MsgAnalyzer` runs on the native parser with no `extract_msg` regression, and `PstAnalyzer` is registered — at which point `pstforensic` is a first-class MATT storage substrate sharing one MAPI object model across MSG and PST/OST.
---

## Appendix A — Adversarial-review reconciliation & spec-verified constants (authoritative)

This appendix is the **single source of truth for byte-level constants**. It records the disposition of every finding from the two independent adversarial reviews (codex, gemini), adjudicated against the primary specifications (offsets/tables fetched live from MS-PST / MS-OXMSG / MS-OXPROPS / MS-OXRTFCP / MS-OXOMSG). Where this appendix and the body disagree, **this appendix wins.**

### A.1 Disposition legend

- **CONFIRMED** — reviewer was right; body corrected.
- **REJECTED** — reviewer was wrong (verified against spec); body unchanged or hardened with a note.
- **VERIFY@vector** — direction correct but exact value must be pinned by a test vector before code relies on it.

### A.2 Spec-verified HEADER layout (MS-PST §2.2.2.6, fetched from learn.microsoft.com)

Computed from the spec field sequence. **These supersede every header offset elsewhere in this doc and in the dossier.**

| Field | ANSI offset | ANSI size | Unicode offset | Unicode size | Notes |
|---|---|---|---|---|---|
| dwMagic (`!BDN` = `21 42 44 4E`) | 0x0000 | 4 | 0x0000 | 4 | |
| dwCRCPartial | 0x0004 | 4 | 0x0004 | 4 | CRC of **471 bytes** from 0x0008 |
| wMagicClient (`SM`) | 0x0008 | 2 | 0x0008 | 2 | |
| wVer | 0x000A | 2 | 0x000A | 2 | 14/15=ANSI; ≥23=Unicode; **37 ⇒ may be WIP-protected** |
| wVerClient | 0x000C | 2 | 0x000C | 2 | doc format = 19 |
| bidUnused | — | — | 0x0018 | 8 | Unicode only |
| bidNextB | 0x0018 | 4 | 0x0204 | 8 | ANSI here; Unicode is *after* bCryptMethod |
| bidNextP | 0x001C | 4 | 0x0020 | 8 | |
| dwUnique | 0x0020 | 4 | 0x0028 | 4 | |
| rgnid[32] | 0x0024 | 128 | 0x002C | 128 | |
| qwUnused | — | — | 0x00AC | 8 | Unicode only |
| **root (ROOT)** | **0x00A4** | **40** | **0x00B4** | **72** | dossier's 0x004C/0x0054 were WRONG |
| dwAlign | — | — | 0x00FC | 4 | Unicode only |
| rgbFM (deprecated, 0xFF) | 0x00CC | 128 | 0x0100 | 128 | |
| rgbFP (deprecated, 0xFF) | 0x014C | 128 | 0x0180 | 128 | |
| bSentinel (`0x80`) | 0x01CC | 1 | 0x0200 | 1 | |
| **bCryptMethod** | **0x01CD** | **1** | **0x0201** | **1** | dossier 0x01A9/0x0219, gemini 0x1B5/0x205 — **all WRONG** |
| rgbReserved | 0x01CE | 2 | 0x0202 | 2 | |
| bidNextB (Unicode) | — | — | 0x0204 | 8 | |
| dwCRCFull | — | — | 0x020C | 4 | Unicode only; CRC of **516 bytes** 0x0008→bidNextB |

`bCryptMethod` values: `0x00 NDB_CRYPT_NONE`, `0x01 NDB_CRYPT_PERMUTE`, `0x02 NDB_CRYPT_CYCLIC`, `0x10 NDB_CRYPT_EDPCRYPTED` (WIP — detect-and-flag, N2).

### A.3 Findings disposition table

| # | Source | Topic | Disposition | Authoritative resolution |
|---|---|---|---|---|
| H1 | codex#1,#2 / gemini#13 | HEADER `root`/`bCryptMethod` offsets | **CONFIRMED** (all three sources wrong) | Use §A.2. Unicode `bCryptMethod`@0x0201, `root`@0x00B4; ANSI @0x01CD / @0x00A4. |
| H2 | gemini#6 | `hidIndex` 0-based? | **REJECTED** | MS-PST §2.3.1.1: `hidIndex` is **1-based and MUST NOT be 0**; `hidType` 5 bits=0, `hidBlockIndex` 16 bits 0-based. Body (§5.1) was already correct. |
| H3 | gemini#1 | CRC = Castagnoli `0x1EDC6F41`? | **REJECTED** | MS-PST §5.3: **standard CRC-32, poly `0xEDB88320`**, slicing-by-8 (`CrcTableOffset32` = the standard table), **seed 0, no pre/post inversion**. Body (§4.6) correct; clarified. |
| H4 | gemini#2 | `wSig` = CRC-16 over page? | **REJECTED** | MS-PST §5.5: `ComputeSig(ib,bid)=WORD((x>>16)^x), x=ib^bid` — the XOR-fold the body already had. |
| H5 | codex#11 | PC inline ≤8B (Unicode)? | **CONFIRMED** | PC BTH `cbEnt=6` (type 2 + HNID 4) in both variants ⇒ **only 4B inline**; 8B/16B fixed go via HNID. Body §5.3 fixed. |
| H6 | codex#12 | HID/NID classified by guessed length | **CONFIRMED** | Classify by **HNID low bits first** (`hidType==0`⇒HID else subnode NID), then size-validate. Body §5.3 fixed. |
| H7 | codex#17 | `PidTagAttachMethod` 6=Embedded? | **CONFIRMED** | **5=afEmbeddedMessage, 6=afStorage(OLE)**. Body §6.5 fixed; embedded object tag = `0x3701000D`, binary = `0x37010102`. |
| H8 | codex#15 | `PidTagMessageFlags & 0x4000` = deleted? | **CONFIRMED** | No such bit. Soft-delete = folder location / dumpster. Body §8.1 fixed. |
| H9 | codex#16 | `PidTagDeletedOn` = 0x6039/0x85FF? | **CONFIRMED (unverified consts)** | Resolve via MS-OXPROPS/named-prop catalog at runtime with provenance, not a hardcoded id. Body §8.1 fixed. |
| H10 | codex#25 / gemini#5 | LZFu token formula & dictionary | **CONFIRMED** | Implement from MS-OXRTFCP: 4096-byte circular dict pre-seeded with the **exact static prefix (§2.1.3.1.2)**; control byte = 8 LSB-first flags; ref = 16-bit BE = 12-bit offset + 4-bit (len+2). Body §9.5 fixed; **VERIFY@vector** incl. a dict-back-reference fixture. |
| H11 | codex#26 | `PtypCurrency` = `$x.xx` | **CONFIRMED** | Signed int64 **scaled by 10000 → fixed-4-decimal**, no currency symbol. Body §9.8 fixed. |
| H12 | codex#27,#28 | MSG `__properties` 8/16B; `__substg` naming | **CONFIRMED** | Entries are **16B**; header 8B(top)/24B(embedded/recip/attach). Streams `__substg1.0_%08X` (full tag). Body §10.1 fixed. |
| H13 | codex#18 | Ambiguous `0x3701` | **CONFIRMED** | Use full type-qualified tags. Body §6.5 fixed. |
| H14 | codex#20 / gemini#4 | AMap **XOR** = free space | **CONFIRMED** | XOR=disagreement, not free. Primary free signal = **not covered by rebuilt live BBT**; report `on_disk_free`/`rebuilt_reachable`/`disagreement` separately. Body §7.4/§8.2 fixed. |
| H15 | codex#21,#22,#23,#31 / gemini#10,#12 | Recovery/“100%” over-claims | **CONFIRMED** | Reframed as **confidence-bounded, scenario-specific** recovery with explicit recovery classes; scoring weights declared heuristic & tunable on a labelled set. Body §1.3, §7.7, §8.2 already measure coverage; honesty notes added. |
| H16 | gemini#9 | Conversation-index “100ms units” | **CONFIRMED** | 40-bit time derived from FILETIME (MS-OXOMSG §2.2.1.3), not 100ms units. Body §9.6 fixed; **VERIFY@vector**. |
| H17 | gemini#7 | named-prop `wGuid` 1/2 special | **CONFIRMED** | `wGuid=1`⇒PS_MAPI, `2`⇒PS_PUBLIC_STRINGS are **hardcoded GUIDs not in the GUID stream**; `≥3`⇒`GuidStream[wGuid-3]`. Body §6.6 wording is consistent; note added. |
| H18 | gemini#8 | EntryID only 2 types | **CONFIRMED** | Expand `render/entryid.py` to folder/message/address-book/one-off/contact/DL EntryIDs (MS-OXCDATA §2.2.4). Also: store/message/folder EntryIDs map provider-UID+NID and **do not** contain SMTP — only one-off/AB recipient EntryIDs yield addresses (codex#24). |
| H19 | gemini#11 | Codepage precedence | **CONFIRMED** | Precedence: `PR_INTERNET_CPID`→`PR_MESSAGE_CPID`→store-level→LCID→1252. Body §9.7 fixed. |
| H20 | codex#3,#4 / gemini#3 | 4K-OST trailer 24B & “supported” claim | **VERIFY@vector** (downgrade) | Treat 4K-OST as a **blocked milestone (M6)** validated against real Outlook 2013+ OSTs; the 24-byte `PAGETRAILER` (with `bidNextPage`) is the working hypothesis to confirm, not a shipped guarantee. Goal G1 wording softened to “after empirical validation”. |
| H21 | codex#8,#9 | PERMUTE/CYCLIC direction; 4K decode/decompress order | **VERIFY@vector** | Lock NONE/PERMUTE/CYCLIC and the 4K compress↔encode order with known-plaintext block test vectors (libpff-compatible) before relying on them. |
| H22 | codex#5,#6,#7 | page-BID vs block-BID; BID reserved bit; SL/SI are blocks not ptypes | **CONFIRMED (clarify)** | Normalize block BIDs (clear reserved bit `A`/`r`; `B`/`i`=internal) before BBT lookup; page BIDs use a separate counter. SLBLOCK/SIBLOCK are **internal blocks** identified by `btype`/`cLevel`, not page ptypes. §4.2/§4.3/§4.7 to encode this explicitly. |
| H23 | codex#14 | TC RowIndex mapping & small-TC-in-block | **CONFIRMED** | Support `hnidRows` as HID *or* NID; map `dwRowID→dwRowIndex` via the RowIndex BTH (not row order); enforce CEB. Body §5.4 already notes HID/NID + CEB; mapping clarified. |
| H24 | codex#10 | HN header variants “identical” | **CONFIRMED (clarify)** | Implement `HNHDR`/`HNPAGEHDR`/`HNBITMAPHDR` distinctly (they share `ibHnpm` location but differ otherwise). §5.1 to note the three forms. |
| H25 | codex#30 | AC-1 “never throws” unrealistic | **CONFIRMED** | AC-1 scoped to **bounded** failure modes (caps on memory/recursion/time); `MemoryError`/OS-IO are out of the “structured-result” promise. §1.4 to footnote. |
| H26 | codex#29 | “99% MS-OXPROPS” ⇏ correctness | **CONFIRMED** | Axis-B already splits **type-code decode (100%)** from **tag naming** from **named-prop resolution**; add an explicit **message-class semantic** sub-axis so catalog coverage isn't oversold. §1.3 to footnote. |

### A.4 Net effect on the “100% / proven” claim

The honest, defensible claim is **not** "we parse every byte of every file perfectly." It is: **measured coverage on four gated axes (§1.3), every structural constant locked by a test vector (§0.5), differential-superset parity where other tools work, and confidence-scored recovery with explicit recovery classes for everything else.** The adversarial pass converted three "trust me" claims (universal 4K-OST, XOR free-space, full deleted-message reconstruction) into bounded, verifiable ones — which is what makes the remaining claims credible.

### A.5 Spec sources used for adjudication

- MS-PST HEADER §2.2.2.6 — https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/c9876f5a-664b-46a3-9887-ba63f113abf5
- MS-PST HID §2.3.1.1 — https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/85b9e985-ea53-447f-b70c-eb82bfbdcbc9
- MS-PST CRC Calculation §5.3 — https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/39c35207-130f-4d83-96f8-2b311a285a8f
- MS-OXMSG, MS-OXRTFCP, MS-OXOMSG, MS-OXCDATA, MS-OXPROPS (Exchange Server Protocols, learn.microsoft.com) — for MSG streams, compressed RTF, conversation index, EntryID/data types, and the property catalog.
- Plus the 262 sources cited by the research dossier (workflow `pst-ost-parser-research`).
