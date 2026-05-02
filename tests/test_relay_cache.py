"""Sprint 7 — A5: mail-relay annotation cache."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils.relay_cache import RelayCache


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path):
    cache_path = tmp_path / "relay_cache.json"
    RelayCache.reset(str(cache_path))
    yield cache_path
    RelayCache.reset()  # restore default for other tests


# ---------------------------------------------------------------
# Static rules
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("AMS1EPF0000008E.eurprd05.prod.outlook.com", "microsoft-365"),
        ("mx.protection.outlook.com", "microsoft-365 (EOP)"),
        ("mail-edge.google.com", "google"),
        ("smtp-out.amazonses.com", "aws-ses"),
        ("eu-smtp-1.mimecast.com", "mimecast"),
        ("mxout.pphosted.com", "proofpoint"),
        ("a.barracudanetworks.com", "barracuda"),
        ("relay1.iphmx.com", "cisco-ironport"),
    ],
)
def test_static_rules_match_well_known_hosts(host, expected):
    labels = RelayCache.annotate(host)
    assert expected in labels, f"got {labels}"


def test_static_rules_no_match_for_random_host():
    assert RelayCache.annotate("mail.example.com") == []


def test_static_rules_case_insensitive_and_trailing_dot():
    assert "google" in RelayCache.annotate("MAIL.GOOGLE.COM.")


# ---------------------------------------------------------------
# Persistent cache
# ---------------------------------------------------------------


def test_observe_persists_first_seen_and_last_seen(_isolated_cache):
    RelayCache.observe("mta.corp.example", "10.0.0.1")
    entries = RelayCache.all_entries()
    assert "mta.corp.example" in entries
    e = entries["mta.corp.example"]
    assert e["first_seen"] <= e["last_seen"]
    assert "10.0.0.1" in e["ips"]


def test_observe_writes_json_file(_isolated_cache):
    RelayCache.observe("mta.corp.example", "10.0.0.1")
    assert _isolated_cache.exists()
    on_disk = json.loads(_isolated_cache.read_text())
    assert "mta.corp.example" in on_disk


def test_label_persists_user_label(_isolated_cache):
    RelayCache.label("mta.corp.example", "internal-relay")
    assert "internal-relay" in RelayCache.annotate("mta.corp.example")
    on_disk = json.loads(_isolated_cache.read_text())
    assert "internal-relay" in on_disk["mta.corp.example"]["labels"]


def test_label_survives_reload(_isolated_cache):
    RelayCache.label("mta.corp.example", "internal-relay")
    # Simulate process restart by resetting state but keeping the file
    RelayCache.reset(str(_isolated_cache))
    assert "internal-relay" in RelayCache.annotate("mta.corp.example")


# ---------------------------------------------------------------
# Integration: annotations land on hops
# ---------------------------------------------------------------


def test_received_parser_annotates_microsoft_365_hop(_isolated_cache):
    pytest.importorskip("dateutil")
    from Utils.received_parser import parse_received_headers, build_hop_display_data

    received_headers = [
        "from a.example (a.example. [203.0.113.5]) "
        "by AMS1EPF0000008E.eurprd05.prod.outlook.com "
        "(Postfix) with ESMTPS id ABC for <to@x>; "
        "Mon, 1 Jan 2026 00:00:00 +0000"
    ]
    hops = parse_received_headers(received_headers)
    display = build_hop_display_data(hops)
    assert display, "no hops in display data"
    found = False
    for hop in display:
        if any("microsoft-365" in a for a in hop.get("annotations", [])):
            found = True
            break
    assert found, f"no microsoft-365 annotation in {[h.get('annotations') for h in display]}"
