"""Background carving with hooks, blocking complete list, random access."""
import threading

from pstforensic import open_store
from pstforensic.tests import synth


def _img():
    return synth.build_unicode_pst_tree(hard_deleted=True, carvable=True, extra_messages=20)


def _key(it):
    return (it.state, it.provenance, it.nid, it.bid, it.subject)


def test_background_carving_matches_inline():
    inline = [_key(i) for i in open_store(_img()).iter_items()]
    store = open_store(_img())
    hooked, threads = [], set()
    head = [_key(i) for i in store.iter_items(
        carving="background",
        on_carved=lambda it: (hooked.append(_key(it)), threads.add(threading.current_thread().name)))]
    assert all(k[0] != "carved" for k in head)
    carved = store.carved_items()                # blocks until complete
    assert store.carving.done
    assert sorted(head + [_key(i) for i in carved]) == sorted(inline)
    assert sorted(hooked) == sorted(_key(i) for i in carved) and hooked
    assert threads == {"pstforensic-carving"}


def test_skip_then_on_demand():
    store = open_store(_img())
    head = list(store.iter_items(carving="skip"))
    assert not any(i.state == "carved" for i in head)
    carved = store.carved_items()
    assert [i.subject for i in carved] == ["Only in free space"]


def test_inline_carved_items_rebuilt():
    store = open_store(_img())
    list(store.iter_items())
    assert [i.subject for i in store.carved_items()] == ["Only in free space"]


def test_hook_failure_does_not_stop_carving():
    store = open_store(_img())
    list(store.iter_items(carving="background", on_carved=lambda it: 1 / 0))
    assert len(store.carved_items()) == 1
    fails = store.diagnostics()["failures"]
    assert fails and fails[0]["phase"] == "on_carved_hook"


def test_random_access_from_index(tmp_path):
    p = tmp_path / "s.pst"
    p.write_bytes(_img())
    cdir = str(tmp_path / "c")
    full = {(_key(i)) for i in open_store(str(p), cache_dir=cdir).iter_items()}
    store = open_store(str(p), cache_dir=cdir)      # fresh process-like reopen
    idx = store.item_index()                        # from cache: no enumeration
    assert store.inventory is None and len(idx) == len(full)
    rebuilt = {_key(store.item(r)) for r in idx}
    assert rebuilt == full
    one = store.item(nid=synth.make_nid(synth.NID_TYPE_NORMAL_MESSAGE, 1))
    assert one.subject == "Wire transfer" and one.folder_path.endswith("/Inbox")
    assert one.message.attachments
