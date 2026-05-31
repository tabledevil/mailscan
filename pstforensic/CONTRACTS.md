# pstforensic — build contracts (READ FIRST)

You are building one subpackage of a forensic PST/OST/MSG parser. The **foundation
is already written and FROZEN** — import it, do not modify it. The master design is
`docs/PST_OST_PARSER_PLAN.md`; **Appendix A is authoritative for every byte-level
constant**. Governing rule (PLAN §0.5): **no byte-level constant is correct until a
test vector locks it** — every struct you parse needs a unit test with a known-answer
fixture and a spec citation in a comment.

## Frozen foundation API (import, don't change)

- `pstforensic.exceptions`: `PstForensicError`, `NotAPstError`, `NotAMsgError`,
  `EncryptedStoreError`, `UnsupportedStoreError`, `ParseWarning`, `WarnCode` (string
  codes), `WarningSink` (`.warn(code, detail, where)`, `.warnings`, `.codes()`).
  **Recovery-first:** structural defects call `sink.warn(...)` and continue; only
  "not a store" / WIP-encrypted raise.
- `pstforensic.proptypes`: `PropType` (IntEnum), `MV_FLAG=0x1000`, `FIXED_SIZES`,
  `is_multivalue`, `base_type`, `fixed_size`, `is_inline_in_pc` (≤4B only — H5),
  `make_tag`, `split_tag`, `tag_str`.
- `pstforensic.variant`: `Variant` dataclass, instances `ANSI`, `UNICODE`,
  `UNICODE_4K` (`.verified is False`), `classify(wver)`, `wver_is_wip_capable`,
  `MAGIC`, `MAGIC_CLIENT`, `CRYPT_NONE/PERMUTE/CYCLIC/EDPCRYPTED`.
  **Offsets (verified):** Unicode `root`@0xB4(72B) `bCryptMethod`@0x201;
  ANSI `root`@0xA4(40B) `bCryptMethod`@0x1CD.
- `pstforensic.fileio.FileReader(source, sink=None)`: `.read(off,len)` (clamped,
  never raises), `.read_exact`, `.u8/.u16/.u32/.u64`, `.size`, context manager.
- `pstforensic.mapi`: `MapiValue(tag, raw, elements=None, encoding=None)` with
  `.prop_id/.prop_type/.decoded/.set_decoded`; `MapiObject(props, flags, nid)` with
  `.add(v)/.has(id)/.by_id(id)/.get_tag(tag)/.raw_of(id)/.render(id)`; subclasses
  `MapiMessage(recipients,attachments,embedded_messages,recovery)`,
  `MapiRecipient(recipient_type)`, `MapiAttachment(method,embedded,open_data)`.
- `pstforensic.ndb.crc`: `compute_crc(data,seed=0)` (MS-PST CRC-32, seed0 no-invert),
  `compute_crc_bitwise` (oracle), `compute_sig(ib,bid)` (XOR-fold §5.5).

## Test fixtures: the synth builders (the shared oracle)

`pstforensic/tests/synth.py` (built by the NDB agent in tier 1) MUST expose:
- `build_unicode_pst(*, messages, crypt=CRYPT_NONE, folders=None) -> bytes`
- `build_ansi_pst(*, messages, crypt=CRYPT_NONE) -> bytes`
- `build_msg(*, props, recipients=(), attachments=()) -> bytes`  (CFBF/OLE)
where `messages` is a list of dicts like
`{"subject": "...", "sender": "...", "to": "...", "body": "...", "props": {tag:int -> bytes}}`.
These produce **byte-accurate** stores so every higher layer can round-trip against a
known item set. If you need a corruption variant, add `corrupt=` kwargs (truncate,
flip header CRC, zero AMap, drop an NBT entry) — used by the recovery agent.

## Public interfaces your subpackage MUST provide

(Other tiers depend on these exact signatures — keep them stable.)

- **ndb** → `pstforensic.ndb.nodedb.NodeDatabase(reader, *, sink)`:
  `.open(reader)` classmethod or constructor that parses header→variant→ROOT→NBT/BBT;
  `.variant`, `.crypt_method`, `.node(nid) -> NodeRef | None`, `.iter_nbt()`,
  `.iter_bbt()`. `NodeRef` has `.nid`, `.data_stream() -> bytes` (decoded, reassembled
  across XBLOCK/XXBLOCK), `.subnodes() -> dict[int, NodeRef]`. Decode (NONE/PERMUTE/
  CYCLIC) applied to data blocks only. CRC/sig advisory (warn, never abort).
- **ltp** → `pstforensic.ltp`: `HeapOnNode(noderef)`, `BTreeOnHeap(...)`,
  `PropertyContext.from_node(noderef) -> MapiObject` (populates MapiValues, MV split
  into `.elements`), `TableContext.from_node(noderef) -> Iterator[MapiObject]` (one
  per row, RowIndex via dwRowID, CEB respected). HID `hidIndex` is **1-based**.
- **render** → `pstforensic.render`: pure functions, no I/O:
  `filetime(b)->datetime|None`, `guid(b)->str`, `entryid(b)->dict`,
  `decompress_rtf(b)->bytes`, `conversation_index(b)->dict`,
  `decode_string(raw, prop_type, *, codepage=None)->str`, and a `render_value(mapi_obj,
  tag)->Any` dispatcher. Plus `install_renderer(mapi_obj)` to wire `MapiObject._renderer`.
- **catalog** → `pstforensic.catalog`: `oxprops.name_for(prop_id)->str|None`,
  `oxprops.PROPS` (id→{name,types,set}), `namedprops.WELL_KNOWN_SETS` (GUID→name),
  `namedprops.lid_name(guid, lid)->str|None`. Ship data as package JSON, no runtime
  download. Include the common PidTag* an analyst needs (envelope/body/times/headers).
- **msg** → `pstforensic.msg.parser.open_msg(source) -> MapiMessage` (recipients,
  attachments, embedded recursion). CFBF via `olefile` (optional dep) in
  `pstforensic.msg.cfbf`, plus orphan-storage carve hook (may be a stub w/ TODO).
  Stream naming `__substg1.0_%08X` (full tag); `__properties_version1.0` entries 16B,
  header 8B top / 24B embedded-recip-attach.
- **messaging** → `pstforensic.messaging.store.open_store(source) -> Store`:
  `.root_folder`, `.folders()` (recursive), `Folder(.name, .messages(), .subfolders(),
  .path)`, each message a `MapiMessage`. Resolve NID_MESSAGE_STORE 0x21, name-to-id
  map 0x61 (→ provide `NamedPropMap`), folders (PC + hierarchy/contents TC), messages,
  recipients (TC 0x692), attachments (TC 0x671), embedded msgs.
- **recovery** → `pstforensic.recovery.engine.RecoveryEngine(reader, *, sink)`:
  `.recover() -> list[RecoveredItem]` running the cascade (trusted walk → sig carve →
  BBT/NBT rebuild → encode brute force) and the deleted/orphan/slack engine with
  `RecoveryMeta(method, confidence, deleted_on, attributed_folder, truncated, flags)`.
  Free space = NOT-in-rebuilt-BBT (not AMap XOR — H14). Confidence-scored.

## Rules

1. Pure-Python, stdlib only (plus `olefile` for msg, optional). No network. No code exec.
2. Every public function typed and docstringed with the `[MS-PST]`/`[MS-OXxxx]` §.
3. Write tests under `pstforensic/tests/test_<sub>.py`. Run them
   (`python3 -m pytest pstforensic/tests/test_<sub>.py -q`) and report pass counts.
4. Do NOT edit files outside your assigned subpackage + your one test file (+ synth.py
   only if you are the NDB agent). The integration agent reconciles seams.
5. If a constant is genuinely unverifiable without a real sample, implement it, mark the
   constant `# UNVERIFIED` and `sink.warn(WarnCode.UNVERIFIED_CONST, ...)`, and add a
   test that documents the assumption. Never silently guess.
