# pstforensic

> **Blind test — run it like this** (Linux, Python ≥ 3.10):
> ```bash
> git clone -b pstforensic-parser https://github.com/tabledevil/mailscan.git && cd mailscan
> pip install numpy                     # fast scan; without it, much slower
> # 1. Kernel-style folder tree next to Kernel PST Viewer (content, your screen only):
> python3 -m pstforensic.tools.tree /path/store.pst --items | less -S
> # 2. Shareable, content-free: redacted tree + diagnostics + CPU profile:
> python3 -m pstforensic.tools.tree /path/store.pst --redact --json \
>     --checkpoint cp.json --profile prof.txt --debug-log debug.log > tree.json
> python3 -m pstforensic.tools.summary /path/store.pst --json > summary.json
> # 3. Folders whose count differs from Kernel (content-free, shareable):
> python3 -m pstforensic.tools.tree /path/store.pst --redact | grep -A1 '!'
> ```
> Folder lines: `declared` = folder's own count, `hier` = count in the parent's
> hierarchy row, `listed` = items found. The indented line under a folder
> explains the difference: provenance (`scan_nbt` = resolved from stale NBT
> copies), row reconciliation (`nid_parent_elsewhere`, `unresolved`) and findings.
> Second runs reuse the structural cache in `~/.cache/pstforensic` (`--no-cache`
> to disable). Shareable: `tree.json` (redacted), `summary.json`, `cp.json`,
> `prof.txt`, `debug.log`. Never the non-redacted output. MATT:
> `python3 matt.py --max-file-size 16G --cache-path ~/.cache/matt /path/store.pst`.

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

### Everything the file holds (PLAN §14)

```python
store = pstforensic.open_store("mailbox.pst")
for item in store.iter_items():     # streams; store.items() returns a list
    print(item.state, item.provenance, item.folder_path, item.subject,
          sorted(item.integrity.codes))
print(store.integrity.codes)        # header / B-tree / scan findings

salvage = item.recover()            # verified copies, older versions, text fragments
```

States: `live`, `live_damaged`, `soft_deleted`, `orphan`, `deleted`,
`superseded`, `carved`, `lost`.

Reading never stops on a bad header, CRC or signature; every such verdict is a
finding on the object it affects.

## Check a store

Count-only summary (states, finding codes, scan statistics — no content):

```bash
python3 -m pstforensic.tools.summary --progress /path/to/mailbox.pst
python3 -m pstforensic.tools.summary --json /path/to/mailbox.pst
```

Field report for debugging (`diagnostics` section: versions + git commit,
timings, failures grouped by exception type and code location with sample
NIDs, warning codes with locations, finding offsets, scan/inventory stats,
peak memory). Never raises — a failing phase is reported, with a header
fingerprint if the store does not even open:

```bash
python3 -m pstforensic.tools.summary --json --debug-log run.log /path/to/mailbox.pst > report.json
```

Folder tree for a side-by-side comparison with Kernel PST Viewer: per folder
the count it declares (`PidTagContentCount`) next to what was found, by state;
items no folder lists go under `~orphan folders/folder 0x…` (by parent NID),
`~lost`, `~carved`. Progress per phase on stderr (checked / remaining / found /
ETA). `--items` lists date, sender, subject per folder — **content, for your own
screen**. `--redact` replaces names by NIDs and drops item text (shareable);
`--checkpoint` writes content-free progress JSON:

```bash
python3 -m pstforensic.tools.tree /path/to/mailbox.pst
python3 -m pstforensic.tools.tree /path/to/mailbox.pst --items | less -S
python3 -m pstforensic.tools.tree /path/to/mailbox.pst --redact --json --checkpoint cp.json > tree.json
```

Install numpy for multi-GB stores (`pip install numpy` or the `pst` extra) —
the pure-Python scan is far slower.

## Cache, random access, background carving

`open_store(path, cache_dir=...)` (or `PSTFORENSIC_CACHE_DIR`) keeps the
expensive structural work across runs: B-tree walk, full-file scan, carving
result, item index. Content-free, keyed by content (never by file name; pass
`cache_key=` with your own SHA-256 in a pipeline), size-capped with LRU
eviction, safe for parallel processes. Details:
[`docs/PST_CACHE_AND_LAZY_ACCESS.md`](../docs/PST_CACHE_AND_LAZY_ACCESS.md).

```python
store = open_store(path, cache_dir="~/.cache/pstforensic")
for item in store.iter_items(carving="background", on_carved=examine):  # hook per find
    ...                                   # live / deleted / orphan … arrive first
carved = store.carved_items()             # blocks until carving is complete
idx = store.item_index()                  # structural records (instant from cache)
msg = store.item(idx[42]).message         # reads just that one message
```

## Debug logging

The library logs under the `pstforensic` logger and is silent unless the host
configures it. INFO = phases with counts/timings; DEBUG = every decision
(variant evidence, crypt ladder, damaged/skipped pages, every parser warning,
every item's state and findings, every swallowed failure with its code
frames). All log records and diagnostics are **content-free**: ids, offsets,
sizes, codes, exception *types* — never values, names or exception messages.

```python
import logging, pstforensic
from pstforensic.log import enable_debug_log
enable_debug_log("pst-debug.log")            # or configure logging.getLogger("pstforensic")
store = pstforensic.open_store(path)
items = list(store.iter_items())
report = store.diagnostics()                 # JSON-serialisable field report
```

In MATT the verbosity follows MATT: `-v` → INFO, `-vv`/`-d` → DEBUG; the
`pst_diagnostics` report (JSON output) carries `store.diagnostics()`.

Header and root-page structure only (stdlib-only, copyable as a single file):

```bash
python3 pstforensic/tools/fingerprint.py --scan /path/to/mailbox.pst
```

## Run the tests

No external dependencies for the synthetic suite (pure stdlib; `olefile` only if
you exercise the MSG round-trip writer).

```bash
# from the repo root
python3 -m pytest pstforensic/tests -q          # → 283 passed, 10 skipped
```

The 7 skipped are the **content-sealed real-sample harness** — they run only when
you point them at a real file and they never let its contents leak into any
output. See **[`tests/REAL_SAMPLE_TESTING.md`](tests/REAL_SAMPLE_TESTING.md)**:

```bash
PSTFORENSIC_PRIVATE_SAMPLE=/secure/path/evidence.pst \
  python3 -m pytest pstforensic/tests/test_real_sample.py -q --tb=line -p no:cacheprovider
```

Regression against real Outlook stores (the public java-libpst test files
`dist-list.pst`, `passworded.pst`, `example-2013.ost` in one directory):

```bash
PSTFORENSIC_REAL_CORPUS=/path/to/dir python3 -m pytest pstforensic/tests/test_real_corpus.py -q
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
