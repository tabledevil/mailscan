"""Regression against public, real Outlook stores (opt-in).

The three test stores of java-libpst (Apache-2.0) are real Outlook output:
two Unicode PSTs and an Outlook 2013 4K OST.  They locked bugs the synthetic
self-oracle could not see (PidTagLtpRowId 0x67F2, PtypObject {dwNid, ulSize},
subject prefix, 4K block/BBT geometry, reused block locations).

    export PSTFORENSIC_REAL_CORPUS=/path/to/dir   # holds the three files
    python3 -m pytest pstforensic/tests/test_real_corpus.py -q

Fetch: https://github.com/rjohnsondev/java-libpst/tree/develop/src/test/resources
(dist-list.pst, passworded.pst, example-2013.ost)
"""
from __future__ import annotations

import os
from collections import Counter

import pytest

from pstforensic import open_store

CORPUS = os.environ.get("PSTFORENSIC_REAL_CORPUS")


def _store(name):
    if not CORPUS:
        pytest.skip("PSTFORENSIC_REAL_CORPUS not set")
    path = os.path.join(CORPUS, name)
    if not os.path.exists(path):
        pytest.skip(f"{name} not in corpus")
    return open_store(path)


def _by_state(items):
    out: dict[str, list] = {}
    for i in items:
        out.setdefault(i.state, []).append((i.folder_path, i.subject))
    return {k: sorted(v, key=str) for k, v in out.items()}


def test_passworded_pst():
    st = _store("passworded.pst")
    assert st.has_password
    assert len(list(st.folders())) == 13
    assert _by_state(st.items()) == {"live": sorted([
        ("/Top of Personal Folders/Contacts", "contact name 1"),
        ("/Top of Personal Folders/Contacts", "test dist list"),
        ("/~root/Freebusy Data", "LocalFreebusy"),
    ], key=str)}
    assert st.integrity.ok


def test_dist_list_pst_recurring_exceptions_and_old_version():
    st = _store("dist-list.pst")
    items = st.items()
    states = Counter(i.state for i in items)
    assert states == {"live": 4, "superseded": 1}
    appt = next(i for i in items if i.state == "live" and i.subject == "Test appointment")
    assert appt.folder_path == "/Top of Personal Folders/Calendar"
    assert len(appt.message.embedded_messages) == 2      # recurrence exceptions
    old = next(i for i in items if i.state == "superseded")
    assert old.supersedes == appt.nid
    assert len(old.message.embedded_messages) == 2


def test_outlook_2013_4k_ost():
    st = _store("example-2013.ost")
    assert st.variant.name == "unicode4k"
    assert st.nodedb.header.variant_evidence == {"unicode4k": "verified"}
    by = _by_state(st.items())
    assert by["live"] == sorted([
        ("/Root - Mailbox/IPM_SUBTREE/Inbox", "Microsoft Outlook Test Message"),
        ("/Root - Mailbox/IPM_SUBTREE/Inbox", "Microsoft Outlook Test Message"),
        ("/Root - Mailbox/IPM_SUBTREE/Sent Items", "Test 2"),
    ], key=str)
    assert {s for _f, s in by["deleted"]} == {
        "Test 3", "FW: Test 2", "Test 2", "Test1", "Test Attachment"}
    assert len(by["carved"]) == 1
    live = [i for i in st.items() if i.state == "live"]
    assert all(i.integrity.ok for i in live)
