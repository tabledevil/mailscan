# pstforensic

A forensic-grade, host-static-safe **PST / OST / MSG** parser with a shared MAPI
object model. Reads corrupted stores, reconstructs deleted/orphaned items, and
renders every MAPI property human-readably. Standalone (not yet wired into MATT —
that is the final gate, taken only once it is proven against real samples).

> Design: [`docs/PST_OST_PARSER_PLAN.md`](../docs/PST_OST_PARSER_PLAN.md)
> (Appendix A is authoritative for byte-level constants).
> Honest coverage scorecard: [`STATUS.md`](STATUS.md).
> Build contracts: [`CONTRACTS.md`](CONTRACTS.md).

## Layout

```
pstforensic/
├── exceptions.py proptypes.py variant.py fileio.py   # frozen foundation
├── mapi/         # shared MapiObject / MapiMessage / Recipient / Attachment
├── ndb/          # header · bref · btree · block · crypt · subnode · nodedb
├── ltp/          # heap · bth · pc · tc
├── render/       # filetime · guid · entryid · rtf(LZFu) · convindex · strings
├── catalog/      # oxprops (MS-OXPROPS) · namedprops
├── msg/          # cfbf · parser · nameid   (native MSG, embedded recursion)
├── messaging/    # store · folder · message · recipient · attachment · nameid
├── recovery/     # carve · rebuild · encode_detect · orphan · dedup · engine
└── tests/        # 224 self-oracle tests + the sealed real-sample harness
```

## Public API

```python
import pstforensic

store = pstforensic.open_store("mailbox.pst")          # or bytes
for folder in store.folders():
    for msg in folder.messages():
        print(msg.render(0x0037))                      # subject (human-readable)

msg = pstforensic.open_msg("message.msg")              # native MSG, no extract_msg

from pstforensic.recovery import RecoveryEngine
for item in RecoveryEngine("mailbox.pst").recover():   # deleted/orphaned items
    print(item.meta.method, item.meta.confidence)
```

## Run the tests

No external dependencies for the synthetic suite (pure stdlib; `olefile` only if
you exercise the MSG round-trip writer).

```bash
# from the repo root
python3 -m pytest pstforensic/tests -q          # → 224 passed, 7 skipped
```

The 7 skipped are the **content-sealed real-sample harness** — they run only when
you point them at a real file and they never let its contents leak into any
output. See **[`tests/REAL_SAMPLE_TESTING.md`](tests/REAL_SAMPLE_TESTING.md)**:

```bash
PSTFORENSIC_PRIVATE_SAMPLE=/secure/path/evidence.pst \
  python3 -m pytest pstforensic/tests/test_real_sample.py -q --tb=line -p no:cacheprovider
```

Optional independent oracle for the sealed differential (Axis D):

```bash
pip install libpff-python    # provides `pypff`
```

## Status in one line

Foundation + NDB + LTP + render + catalog + MSG + messaging + recovery are built
and pass 224 known-answer tests. What still needs a **real** sample to lock:
PERMUTE/CYCLIC decode-direction, 4K-OST geometry, and the differential parity
check — all flagged `# UNVERIFIED` and reported by the sealed harness.
