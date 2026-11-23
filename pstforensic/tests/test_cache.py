"""Persistent structural index cache."""
import os
import pickle

import pytest

from pstforensic import open_store
from pstforensic.ndb import scan as scan_mod
from pstforensic.tests import synth


def _states(store):
    out = {}
    for it in store.iter_items():
        out[it.state] = out.get(it.state, 0) + 1
    return out


@pytest.fixture
def damaged(tmp_path):
    p = tmp_path / "secret-name.pst"
    from pstforensic.tests.test_tree_damage import _leaf_pages, _zero
    img = synth.build_unicode_pst_tree(hard_deleted=True, carvable=True, extra_messages=40)
    img = _zero(img, _leaf_pages(img)["NBT"][1:2])   # NBT damage: scan at open
    p.write_bytes(img)
    return str(p)


def test_second_open_uses_cache_and_matches(damaged, tmp_path, monkeypatch):
    cdir = str(tmp_path / "cache")
    first = _states(open_store(damaged, cache_dir=cdir))
    calls = []
    real = scan_mod.scan_file
    monkeypatch.setattr(scan_mod, "scan_file", lambda *a, **k: calls.append(1) or real(*a, **k))
    second = _states(open_store(damaged, cache_dir=cdir))
    assert second == first and calls == []
    assert first == _states(open_store(damaged))          # no cache: same answer


def test_cache_is_content_free_and_not_named_after_file(damaged, tmp_path):
    cdir = tmp_path / "cache"
    _states(open_store(damaged, cache_dir=str(cdir)))
    files = [os.path.join(r, f) for r, _, fs in os.walk(cdir) for f in fs]
    assert files
    blob = b"".join(open(f, "rb").read() for f in files)
    for word in ("secret-name", "Wire transfer", "Lunch", "Inbox", "Mallory", "Oscar"):
        assert word.encode() not in blob and word.encode("utf-16-le") not in blob, word
    assert not any("secret" in f for f in files)


def test_changed_file_invalidates(damaged, tmp_path):
    cdir = str(tmp_path / "cache")
    open_store(damaged, cache_dir=cdir)
    with open(damaged, "r+b") as fh:          # touch the tail
        fh.seek(-8, 2)
        fh.write(b"\x01" * 8)
    assert len(os.listdir(cdir)) == 1
    open_store(damaged, cache_dir=cdir)
    assert len(os.listdir(cdir)) == 2


def test_tampered_cache_is_refused(damaged, tmp_path):
    cdir = tmp_path / "cache"
    first = _states(open_store(damaged, cache_dir=str(cdir)))
    (key,) = os.listdir(cdir)

    class Evil:
        def __reduce__(self):
            return (os.system, ("echo pwned",))
    for part in ("btree", "scan"):
        with open(cdir / key / f"{part}.pkl", "wb") as fh:
            pickle.dump({"params": None, "data": Evil()}, fh)
    assert _states(open_store(damaged, cache_dir=str(cdir))) == first


def test_same_name_different_store_no_collision(tmp_path):
    cdir = str(tmp_path / "cache")
    a, b = tmp_path / "a" / "mail.pst", tmp_path / "b" / "mail.pst"
    a.parent.mkdir(); b.parent.mkdir()
    a.write_bytes(synth.build_unicode_pst_tree(extra_messages=3))
    b.write_bytes(synth.build_unicode_pst_tree(extra_messages=7))
    assert _states(open_store(str(a), cache_dir=cdir)) == {"live": 5}
    assert _states(open_store(str(b), cache_dir=cdir)) == {"live": 9}
    assert _states(open_store(str(a), cache_dir=cdir)) == {"live": 5}
    assert len(os.listdir(cdir)) == 2


def test_identical_copies_share_an_entry(damaged, tmp_path):
    import shutil
    cdir = str(tmp_path / "cache")
    copy = tmp_path / "elsewhere" / "other-name.pst"
    copy.parent.mkdir()
    shutil.copyfile(damaged, copy)               # new path, new mtime
    open_store(damaged, cache_dir=cdir)
    open_store(str(copy), cache_dir=cdir)
    assert len([d for d in os.listdir(cdir) if not d.startswith(".")]) == 1


def test_caller_key_and_eviction(tmp_path):
    from pstforensic import cache as C
    cdir = tmp_path / "cache"
    for i in range(5):
        p = tmp_path / f"s{i}.pst"
        p.write_bytes(synth.build_unicode_pst_tree(extra_messages=i))
        open_store(str(p), cache_dir=str(cdir), cache_key=f"sha-{i}")
    entries = [d for d in os.listdir(cdir) if not d.startswith(".")]
    assert len(entries) == 5
    one = C._du(str(cdir / entries[0]))
    C.evict(str(cdir), limit=2 * one + 1)
    left = [d for d in os.listdir(cdir) if not d.startswith(".")]
    assert 1 <= len(left) <= 3


def _worker(args):
    path, cdir = args
    return _states(open_store(path, cache_dir=cdir))


def test_parallel_processes_share_cache(damaged, tmp_path):
    import multiprocessing as mp
    if "fork" not in mp.get_all_start_methods():
        pytest.skip("needs fork")
    cdir = str(tmp_path / "cache")
    with mp.get_context("fork").Pool(4) as pool:
        res = pool.map(_worker, [(damaged, cdir)] * 8)
    assert all(r == res[0] for r in res)
    assert _states(open_store(damaged, cache_dir=cdir)) == res[0]
