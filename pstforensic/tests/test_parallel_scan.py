"""Issue #1 — parallel scan workers give exactly the serial result."""
import multiprocessing as mp

import pytest

from pstforensic.fileio import FileReader
from pstforensic.ndb.nodedb import NodeDatabase
from pstforensic.ndb.scan import scan_file
from pstforensic.tests import synth
from pstforensic.variant import ANSI, UNICODE, UNICODE_4K

pytestmark = pytest.mark.skipif("fork" not in mp.get_all_start_methods(),
                                reason="parallel scan needs fork")


def _scan(img, workers, **kw):
    db = NodeDatabase(FileReader(img))
    return scan_file(db.reader, db.variant, live_nbt=db._nbt, live_bbt=db._bbt,
                     live_page_ibs=set(db.page_verdicts), workers=workers,
                     chunk=4096, **kw)


def _key(ix):
    return (ix.pages, ix.slots, ix.bbt_entries,
            {b: c for b, c in sorted(ix.blocks.items())}, ix.stats)


@pytest.mark.parametrize("deep", [False, True])
def test_parallel_equals_serial(deep):
    img = synth.build_unicode_pst_tree(hard_deleted=True, slack_deleted=True,
                                       superseded=True, carvable=True, extra_messages=60)
    kw = dict(variants=(ANSI, UNICODE, UNICODE_4K), page_stride=64) if deep else {}
    serial, par = _scan(img, 1, **kw), _scan(img, 4, **kw)
    assert len(serial.slots) > 0 and len(serial.blocks) > 0
    assert _key(serial) == _key(par)


def test_parallel_progress_reaches_end():
    img = synth.build_unicode_pst_tree(extra_messages=60)
    seen = []
    _scan(img, 3, progress=lambda d, t: seen.append((d, t)))
    assert seen[-1][0] == seen[-1][1]
    assert [d for d, _ in seen] == sorted(d for d, _ in seen)
