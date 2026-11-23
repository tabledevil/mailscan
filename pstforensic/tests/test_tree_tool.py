"""tools.tree — Kernel-style folder tree; --redact leaves no content."""
import io
import json

from pstforensic.tests import synth
from pstforensic.tools import tree as T


def _img(tmp_path, **kw):
    p = tmp_path / "s.pst"
    p.write_bytes(synth.build_unicode_pst_tree(**kw))
    return str(p)


def test_tree_counts_and_buckets(tmp_path):
    t = T.build_tree(_img(tmp_path, hard_deleted=True, carvable=True), items=True)
    paths = {f["path"]: f for f in t["folders"]}
    assert paths["/Personal Folders/Inbox"]["found"] == {"live": 2, "deleted": 1}
    assert paths["/~carved"]["found"] == {"carved": 1}
    out = io.StringIO()
    T.render_text(t, items=True, out=out)
    assert "Wire transfer" in out.getvalue()


def test_redacted_tree_has_no_content(tmp_path):
    t = T.build_tree(_img(tmp_path, hard_deleted=True, carvable=True), items=True,
                     redact=True)
    blob = json.dumps(t, default=str)
    for word in ("Inbox", "Personal Folders", "Wire transfer", "Mallory", "Oscar",
                 "invoice", "s.pst"):
        assert word not in blob, word
    assert t["totals"] == {"live": 2, "deleted": 1, "carved": 1}


def test_checkpoint_is_content_free(tmp_path):
    cp = tmp_path / "cp.json"
    prog = T.Progress(enabled=False, checkpoint=str(cp), every=0)
    T.build_tree(_img(tmp_path, carvable=True), progress=prog)
    prog.finish()
    d = json.loads(cp.read_text())
    assert d["status"] == "complete" and set(d) == {
        "status", "phase", "done", "total", "found", "elapsed_s", "phase_elapsed_s"}


def test_redact_path_rules():
    nids = {"/~root/Reminders": 0x2223, "/Top/Inbox": 0x8042, "/Top": 0x8022}
    assert T.redact_path("/~root/Reminders", nids) == "/~root/folder 0x2223"
    assert T.redact_path("/Top/Inbox", nids) == "/folder 0x8022/folder 0x8042"
    assert T.redact_path("/~orphan folders/folder 0x2a2", nids) == "/~orphan folders/folder 0x2a2"
    assert T.redact_path("/~carved", nids) == "/~carved"
    assert T.redact_path("/(deleted folder)/Secret", nids) == "/folder ?/folder ?"
