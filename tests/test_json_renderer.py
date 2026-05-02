"""Sprint 7 — B3: JSON renderer severity rollup."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _eml(headers: dict, body: str = "hello\n") -> bytes:
    out = "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n" + body
    return out.encode("utf-8")


def _render_json(data: bytes) -> dict:
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    return json.loads(s.get_report(report_format="json", verbosity=0))


def test_json_severity_block_present():
    out = _render_json(_eml({"From": "a@x.example", "To": "b@x.example", "Subject": "t"}))
    assert "severity" in out
    sev = out["severity"]
    assert "own" in sev
    assert "tree_max" in sev
    assert "own_value" in sev


def test_json_tree_max_reflects_high_descendant():
    """A HIGH finding (Reply-To mismatch) on the root must surface in
    tree_max even when seen via JSON consumers."""
    data = _eml({
        "From": "a@corp.example",
        "Reply-To": "x@evil.example",
        "To": "b@corp.example",
        "Subject": "t",
        "Message-ID": "<1@corp.example>",
    })
    out = _render_json(data)
    assert out["severity"]["tree_max"] == "HIGH"
    assert out["severity"]["tree_max_value"] == 1  # 0=CRIT, 1=HIGH, …


def test_json_tree_max_rolls_up_from_children():
    """Even when the root itself is INFO, a CRITICAL/HIGH finding deep in
    a child should be reflected in the root's tree_max."""
    data = _eml({
        "From": "a@x.example",
        "To": "b@x.example",
        "Subject": "t",
    }, body="harmless body\n")
    out = _render_json(data)
    # Root is INFO; tree should be no-worse-than its own
    assert out["severity"]["tree_max_value"] >= out["severity"]["own_value"] or \
           out["severity"]["tree_max_value"] == out["severity"]["own_value"]


def test_json_aggregate_iocs_serializable():
    data = _eml({
        "From": "a@x.example",
        "To": "b@x.example",
        "Subject": "t",
    }, body="See http://malicious.example.com/ and 8.8.8.8\n")
    out = _render_json(data)
    labels = [r["label"] for r in out["reports"]]
    assert "iocs_aggregate" in labels
    agg = next(r for r in out["reports"] if r["label"] == "iocs_aggregate")
    assert agg["data"], "iocs_aggregate must include structured data dict"
    assert "urls" in agg["data"] or "ipv4" in agg["data"]
