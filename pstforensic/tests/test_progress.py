"""Issue #1 — per-phase progress with exact carving totals, counts only."""
from pstforensic import open_store
from pstforensic.tests import synth


def test_phases_and_carving_totals():
    calls = []
    img = synth.build_unicode_pst_tree(hard_deleted=True, carvable=True,
                                       extra_messages=40)
    store = open_store(img, progress=lambda *a: calls.append(a))
    items = list(store.iter_items())
    phases = [c[0] for c in calls]
    for p in ("scan_pages", "scan_blocks", "folders", "live_items", "orphans", "carving"):
        assert p in phases, p
    carving = [c for c in calls if c[0] == "carving"]
    total = len(store.scan().blocks)
    assert carving[-1][1] == carving[-1][2] == total          # finished == total
    assert carving[-1][3] == sum(1 for i in items if i.state == "carved")
    # counts only: every argument after the phase name is an int or None
    assert all(isinstance(x, (int, type(None))) for c in calls for x in c[1:])
    t = store.diagnostics()["timings_s"]
    assert {"scan", "open", "folder_walk", "live_items", "carving"} <= set(t)


def test_scan_at_open_reports_progress():
    calls = []
    img = bytearray(synth.build_unicode_pst_tree())
    img[0:0x400] = b"\x00" * 0x400          # headerless → scan during open
    open_store(bytes(img), progress=lambda *a: calls.append(a[0]))
    assert "scan_pages" in calls and "scan_blocks" in calls
