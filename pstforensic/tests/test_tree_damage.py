"""Issue #4 — NBT and BBT damage are tracked separately."""
import pytest

from pstforensic import open_store
from pstforensic.ndb.nodedb import NodeDatabase
from pstforensic.fileio import FileReader
from pstforensic.tests import synth

N = 2 + 40


def _leaf_pages(img):
    db = NodeDatabase(FileReader(img))
    by_tree = {"NBT": [], "BBT": []}
    for ib, v in db.page_verdicts.items():
        if v.depth > 0:
            by_tree[v.tree].append(ib)
    return by_tree


def _zero(img, ibs, size=512):
    buf = bytearray(img)
    for ib in ibs:
        buf[ib:ib + size] = b"\x00" * size
    return bytes(buf)


@pytest.fixture(scope="module")
def healthy():
    img = synth.build_unicode_pst_tree(extra_messages=40)
    pages = _leaf_pages(img)
    assert pages["NBT"] and pages["BBT"], "fixture must have multi-level trees"
    return img, pages


def _states(store):
    out = {}
    for it in store.iter_items():
        out[it.state] = out.get(it.state, 0) + 1
    return out


def test_bbt_only(healthy):
    img, pages = healthy
    store = open_store(_zero(img, pages["BBT"][:1]))
    db = store.nodedb
    assert db.bbt_damaged and not db.nbt_damaged
    st = _states(store)
    assert "lost" not in st
    assert st.get("live", 0) + st.get("live_damaged", 0) == N
    dmg = store.diagnostics()["btree_damage"]
    assert dmg["BBT"]["pages_zeroed"] == 1 and dmg["NBT"]["pages_damaged"] == 0
    assert dmg["BBT"]["skipped_samples"][0]["zeroed"] is True


def _readable(st):
    return sum(n for k, n in st.items() if k in ("live", "live_damaged", "orphan", "lost"))


def test_nbt_only(healthy):
    img, pages = healthy
    store = open_store(_zero(img, pages["NBT"][:1]))
    db = store.nodedb
    assert db.nbt_damaged and not db.bbt_damaged
    st = _states(store)
    # The zeroed leaf held the folder nodes and some messages: messages whose
    # entry survived are orphans, the rest come back from their live blocks.
    assert _readable(st) == N and st.get("lost", 0) > 0
    assert store.inventory_stats.lost_unreferenced == st["lost"]
    labels = {it.folder_label for it in store.iter_items() if it.state == "orphan"}
    assert labels == {"/~orphan folders/folder 0x2a2"} or all(
        l.startswith("/~orphan folders/") for l in labels)
    dmg = store.diagnostics()["btree_damage"]
    assert dmg["NBT"]["pages_zeroed"] == 1 and dmg["BBT"]["pages_damaged"] == 0


def test_both_trees(healthy):
    img, pages = healthy
    store = open_store(_zero(img, pages["NBT"][:1] + pages["BBT"][:1]))
    db = store.nodedb
    assert db.nbt_damaged and db.bbt_damaged
    st = _states(store)
    assert _readable(st) == N
    codes = {f.code for f in store.integrity.findings}
    assert "PAGE_ZEROED" in codes and "PAGE_TYPE_BAD" not in codes


def test_healthy_reports_no_damage(healthy):
    img, _ = healthy
    db = open_store(img).nodedb
    assert not db.nbt_damaged and not db.bbt_damaged
