"""Issue #3 — folder membership from multi-block tables.

Outlook stores a big contents table as a multi-block heap (one HNPAGEMAP per
block), a multi-level RowIndex BTH, and a row matrix whose full data blocks end
in padding (rows never span a block).  Reading the matrix as one contiguous
array shifts every row after the first block → messages become orphans.
"""
import pytest

from pstforensic import open_store
from pstforensic.ltp.tc import TableContext
from pstforensic.messaging.inventory import Inventory  # noqa: F401  (import check)
from pstforensic.ndb.bref import make_nid
from pstforensic.tests.synth import NID_TYPE_CONTENTS_TABLE
from pstforensic.tests import synth

INBOX_INDEX = 10


def _contents_ref(store):
    return store.nodedb.node(make_nid(NID_TYPE_CONTENTS_TABLE, INBOX_INDEX))


@pytest.mark.parametrize("extra", [0, 40, 1200, 2500])
def test_every_contents_row_in_index_order(extra):
    img = synth.build_unicode_pst_tree(extra_messages=extra)
    store = open_store(img)
    ref = _contents_ref(store)
    rows = list(TableContext.from_node(ref, store.nodedb.variant))
    ids = [r.raw_of(0x67F2) for r in rows]
    expected = [synth.make_nid(synth.NID_TYPE_NORMAL_MESSAGE, 1),
                synth.make_nid(synth.NID_TYPE_NORMAL_MESSAGE, 2)] + [
        synth.make_nid(synth.NID_TYPE_NORMAL_MESSAGE, 0x100 + i) for i in range(extra)]
    got = [int.from_bytes(bytes(x), "little") for x in ids]
    assert got == expected


def test_fixture_really_is_multi_block():
    """Guard against the self-oracle: the big fixture must exercise padding,
    a multi-block heap and a multi-level RowIndex."""
    store = open_store(synth.build_unicode_pst_tree(extra_messages=1200))
    ref = _contents_ref(store)
    assert len(ref.data_segments()) > 1                     # heap blocks
    (matrix,) = ref.subnodes().values()
    segs = matrix.data_segments()
    assert len(segs) > 1 and segs[0].endswith(synth.MATRIX_PAD * 4)


def test_big_folder_has_no_orphans():
    store = open_store(synth.build_unicode_pst_tree(extra_messages=1200))
    states = {}
    for it in store.iter_items():
        states[it.state] = states.get(it.state, 0) + 1
    assert states == {"live": 1202}


def test_bth_little_endian_keys_are_in_order():
    from pstforensic.exceptions import WarningSink
    sink = WarningSink()
    store = open_store(synth.build_unicode_pst_tree(extra_messages=1200), sink=sink)
    list(TableContext.from_node(_contents_ref(store), store.nodedb.variant, sink=sink))
    assert not [w for w in sink.warnings if "out of order" in (w.detail or "")]


def test_folder_reconstruction_counts():
    store = open_store(synth.build_unicode_pst_tree(extra_messages=1200, deleted=True))
    list(store.iter_items())
    st = store.inventory_stats
    assert st.folder_rows == 1202 and st.folder_rows_unresolved == 0
    assert st.folder_rows_duplicate == 0 and st.orphans == 1
    assert st.folders_walked >= 2 and st.contents_tables_missing == 0
