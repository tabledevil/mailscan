# PST/OST/PFF Forensic Parser Deep Dive

Status: research and architecture note. This is intentionally independent of
`matt`; the output should become a standalone forensic engine that `matt` can
consume selectively.

## Objective

Build a forensically sound parser and carver for Outlook Personal Folder File
family containers:

- PST, both ANSI and Unicode variants.
- OST where the on-disk structure is PFF/PST-like and sufficiently documented by
  the public MS-PST storage model.
- Corrupt, partially overwritten, truncated, and internally inconsistent files.

The parser must maximize recovered information while never hiding uncertainty.
Every emitted object must carry provenance, confidence, validation status, and
raw offsets. Output must be readable and machine-checkable.

## Non-Goals

- Do not start by integrating deeply with `matt`.
- Do not depend on Outlook, Windows Search, or GUI viewers as parser backends.
- Do not silently normalize broken records into clean-looking messages.
- Do not treat third-party tools as authoritative. They are comparison or
  fallback inputs only.

## Format Model

Public Microsoft documentation describes PST as a layered file format. The
forensic implementation should mirror these layers instead of jumping straight
from bytes to email messages.

### 1. Physical File Layer

Responsibilities:

- Identify file family and version.
- Parse the file header and root metadata.
- Decode layout parameters such as Unicode vs ANSI, crypt method, root pointers,
  and allocation metadata.
- Read pages, blocks, and trailers with bounds checking.
- Validate signatures, CRCs, BID/NID consistency, and alignment.

Forensic requirements:

- Never stop the entire parse because one page or block is invalid.
- Emit a validation record for every page/block read attempt.
- Preserve raw offsets and lengths for every object.
- Represent sparse, truncated, overlapping, and out-of-range references as facts.

Important structures to model:

- Header and root.
- Page map / allocation map where present.
- Page trailers and block trailers.
- BREF/BID/NID references.
- Block data and subnode data.
- Encryption/obfuscation mode where applicable.

### 2. NDB Layer

The Node Database layer is the key recovery layer. It provides object identity
and storage indirection.

Core concepts:

- BBT: Block B-tree, maps block IDs to byte ranges.
- NBT: Node B-tree, maps node IDs to data blocks and subnode blocks.
- NIDs identify logical objects such as folders, messages, attachments,
  recipients, search folders, and internal tables.
- BIDs identify physical blocks.
- Subnodes allow objects to be composed from additional child blocks.

Forensic parser behavior:

- Parse BBT and NBT from the header root when possible.
- Traverse B-trees tolerantly. If a page footer or node type is unsupported or
  corrupt, salvage valid entries from the page body when possible.
- Maintain an index-trust model:
  - `trusted_index`: reachable from root and validates structurally.
  - `damaged_index`: reachable but partially invalid.
  - `carved_index`: discovered by scanning, not reachable from root.
  - `conflict`: duplicate or contradictory entries.
- Continue with partial indexes rather than failing on one bad node page.

This directly addresses errors such as `unsupported index node type: 0x00` while
reading a descriptor index node. A strict parser aborts because it cannot create
the full item tree. A forensic parser should downgrade that page, salvage any
valid entries, and continue with other reachable or carved pages.

### 3. LTP Layer

The Lists, Tables, and Properties layer turns raw nodes into typed property
stores.

Core structures:

- HN: Heap-on-Node.
- BTH: B-tree-on-Heap.
- PC: Property Context, keyed by property tag.
- TC: Table Context, used for rows such as folder contents, recipients, and
  attachments.
- Subnode references for large values and multi-value properties.

Forensic parser behavior:

- Decode heaps with strict bounds checking.
- Parse BTH pages even when sibling links or heap allocations are inconsistent.
- Decode property values with type-specific parsers.
- Preserve raw property bytes alongside interpreted values.
- If a property cannot be decoded, emit the raw value and an error annotation.

Property decoding must cover at least:

- Integer types: PT_I2, PT_LONG, PT_I8, boolean.
- Time: PT_SYSTIME / FILETIME.
- String: PT_STRING8, PT_UNICODE, codepage-aware fallback.
- Binary: PT_BINARY.
- GUID / CLSID.
- Multi-value variants.
- Object/subnode references.

### 4. Messaging Layer

The Messaging layer interprets properties and tables as folders, messages,
recipients, and attachments.

Core objects:

- Folder records and hierarchy.
- Message records.
- Recipient table rows.
- Attachment table rows.
- Embedded messages.
- Message bodies: plain text, HTML, RTF compressed/uncompressed where present.
- Transport headers and internet message metadata.
- Outlook/MAPI metadata not expressible in RFC 5322.

Readable output should include:

- EML for internet-style messages when possible.
- JSON for complete MAPI object representation.
- Attachment files with hashes and provenance.
- Folder tree and recovered/orphan/carved object lists.
- A validation report explaining what was trusted, repaired, carved, or lost.

EML must be treated as a presentation/export format, not the authoritative data
model. Many PST properties cannot be faithfully represented in EML.

## Corruption and Recovery Strategy

A robust forensic parser needs multiple recovery passes.

### Pass 1: Header and Root Parse

- Read header only.
- Determine version, byte order assumptions, root BREFs, and crypt method.
- If header is damaged, attempt secondary heuristics but mark the file as
  `header_recovered`.

### Pass 2: Strict Index Parse

- Parse BBT/NBT from root pointers.
- Validate entries and page trailers.
- Build the best reachable logical tree.
- Do not abort on localized failures.

### Pass 3: Tolerant Index Salvage

- For damaged index pages, scan page-sized regions for plausible entries.
- Validate candidate entries by resolving referenced blocks/nodes.
- Add candidates with lower confidence and explicit reasons.

### Pass 4: Whole-File Carving

Scan the file for plausible PST structures independent of the root tree:

- Page trailers with plausible signatures/ptype/wSig/CRC.
- BBT-like and NBT-like entry arrays.
- Block trailers and valid block IDs.
- Heap-on-node signatures/headers.
- Property context records with valid property tags and types.
- Table contexts with plausible row matrices.
- Common message property patterns such as subject/body/header property tags.

Carved candidates should never overwrite trusted index data. They form a
separate evidence namespace:

- `live`: reachable through valid folder/message hierarchy.
- `orphan`: valid object not reachable from normal folder tree.
- `recovered`: object found through recovery indexes or tool fallback.
- `carved`: object inferred directly from bytes.
- `fragment`: partial object insufficient for complete message reconstruction.

### Pass 5: Object Reconstruction

- Rebuild folders, messages, recipients, and attachments from the best available
  properties and subnodes.
- Track missing dependencies.
- Emit partial messages if subject/body/headers are available but some tables are
  damaged.
- Preserve raw properties for independent review.

### Pass 6: Cross-Validation

Cross-check reconstructed data:

- Table row references point to existing nodes.
- Attachment rows match attachment subnodes.
- Message size properties approximately match block sizes where available.
- Internet headers agree with MAPI sender/recipient/date fields where possible.
- Duplicate blocks and conflicting NID/BID mappings are reported.

## Provenance Model

Every parsed output object should include provenance:

```json
{
  "object_id": "pst:nid:0x...",
  "kind": "message",
  "source_file": "case.pst",
  "classification": "live|orphan|recovered|carved|fragment",
  "confidence": "high|medium|low",
  "offsets": [
    {"role": "node_entry", "offset": 1234, "length": 32},
    {"role": "data_block", "offset": 5678, "length": 4096}
  ],
  "validation": [
    {"check": "block_crc", "status": "ok"},
    {"check": "property_decode", "status": "partial", "detail": "invalid unicode tail"}
  ]
}
```

Do not output clean EML without a sidecar provenance record.

## Correctness Rules

- Decode strictly first, then fallback heuristically.
- Keep raw bytes for every interpreted property.
- Use typed parsers for property values; avoid regex extraction except for final
  IOC/hunt layers.
- Never invent missing dates, senders, recipients, filenames, or message IDs.
- If a decoded value is repaired, label it repaired.
- If a value is ambiguous, preserve all candidates.
- Do not collapse duplicates unless byte-identical and provenance-preserved.

## Native Parser Package Shape

Suggested package name: `pffx` or `forensic_pst`.

```text
pffx/
  __init__.py
  errors.py
  provenance.py
  reader.py          # bounded file reads, mmap optional, no mutation
  physical.py        # header/page/block/trailer structures
  ndb.py             # BBT/NBT traversal and salvage
  ltp.py             # HN/BTH/PC/TC parsers
  props.py           # MAPI property tags/types/codepages
  messaging.py       # folders/messages/recipients/attachments
  rtf.py             # compressed RTF support
  carve.py           # whole-file scans and candidate validation
  export.py          # EML, JSON, attachment output
  validate.py        # invariants and consistency checks
  cli.py             # standalone forensic CLI
  tests/
```

### CLI Shape

```bash
pffx inspect case.pst --json report.json
pffx list case.pst --objects messages --include-carved
pffx export case.pst --out export/ --format eml,json --include-orphans --include-carved
pffx carve case.pst --out carved/ --max-fragments all
pffx validate case.pst --json validation.json
```

### Output Layout

```text
export/
  manifest.jsonl
  validation.json
  live/
    folders.json
    messages/000001.eml
    messages/000001.json
    attachments/000001/...
  orphan/
  recovered/
  carved/
  fragments/
```

`manifest.jsonl` is the source of truth. EML and attachment files are exports.

## Tooling Comparison Strategy

Use external tools only for comparison/fallback, never as the sole parser:

- libpff / pypff: normal structured traversal where it works.
- pffexport `-m all`: fallback to export allocated, orphan, and recovered items.
- readpst: comparison only; not enough for full forensic guarantees.
- Windows/Outlook/PST viewers: visual comparison only, not reproducible forensic
  parsing.

For each test corpus sample, collect:

- Native parser count by class: live/orphan/recovered/carved/fragment.
- pypff count.
- pffexport count.
- readpst count.
- Known expected counts where samples are synthetic.

## Test Corpus Plan

Synthetic corpus is mandatory because classified files cannot be used in CI.

Create or acquire:

- Empty PST.
- Small ANSI PST.
- Small Unicode PST.
- PST with nested folders.
- PST with recipients and multiple attachment types.
- PST with embedded message attachment.
- OST sample where legally permitted.
- Deleted-message/orphan sample.
- Truncated file.
- Corrupt NBT page.
- Corrupt BBT page.
- Bad CRC page.
- Overlapping block references.
- Duplicate NID/BID conflict.
- Encrypted/obfuscated content mode variants.

For synthetic corruption, generate base files and mutate copies with scripts that
record exact byte changes.

## Immediate Implementation Milestones

1. `pffx inspect-header`
   - Parse header/root.
   - Report version, size, root pointers, crypt method.
   - No message reconstruction yet.

2. `pffx scan-pages`
   - Identify page/block candidates across the file.
   - Validate page/block trailers.
   - Emit JSONL candidates.

3. `pffx parse-ndb`
   - Traverse BBT/NBT when valid.
   - Salvage damaged pages.
   - Emit node/block index with validation statuses.

4. `pffx parse-ltp`
   - Decode HN/BTH/PC/TC for selected nodes.
   - Emit raw and interpreted properties.

5. `pffx export-message`
   - Reconstruct messages from property contexts and tables.
   - Export JSON first, EML second.

6. `pffx carve`
   - Whole-file candidate carving for unreachable nodes/properties.
   - Confidence scoring and deduplication.

7. `matt` integration
   - `matt` calls `pffx` selectively.
   - `matt` consumes exported messages/attachments as children.
   - `matt` never becomes the authoritative PST parser.

## Risk Register

- OST support may include synchronization/cache-specific data that is not
  fully recoverable from MS-PST alone.
- Password/encryption semantics need separate research and test files.
- Compressed RTF must be decoded accurately or retained raw.
- Carving can produce false positives; confidence and validation are essential.
- Full support is large. Shipping incremental, verifiable layers is safer than
  trying to reconstruct messages first.

## References

- Microsoft Open Specifications, MS-PST: Outlook Personal Folders File Format.
  https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546
- Microsoft Open Specifications, MS-OXPROPS: Exchange Server Protocols Master
  Property List. https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/
- Microsoft Open Specifications, MS-OXCDATA: Data Structures. https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/
- libyal/libpff Personal Folder File format notes.
  https://github.com/libyal/libpff/blob/main/documentation/Personal%20Folder%20File%20%28PFF%29%20format.asciidoc
- Local tool reference: `pffexport -h` shows `-m all` exports allocated,
  orphan, and recovered items.
