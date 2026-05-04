"""Audit follow-up — VT enrichment must not leak internal IOCs.

Audit finding (codex_security_2; MEDIUM): rendering triggered
``enrich_iocs(summary)`` which submitted every domain + every IPv4
+ every IPv6 to VirusTotal with no internal-network filter. Only
IPv4 had a private-range filter (and only inside extract_iocs,
not at the enrichment boundary). IPv6 link-local, ULAs, loopback,
.local domains, single-label hosts all leaked.

These tests pin the corrected filter so future cleanup can't
silently restore the leakage path.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils import advanced_analysis as adv


# ---------------------------------------------------------------
# Internal-IP filter
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",            # RFC 1918 / private
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",           # loopback
        "169.254.1.1",         # IPv4 link-local
        "::1",                 # IPv6 loopback
        "fe80::1",             # IPv6 link-local
        "fc00::1",             # IPv6 ULA (RFC 4193)
        "::",                  # unspecified
        "ff02::1",             # IPv6 multicast
        "",                    # malformed
        "not-an-ip",           # malformed
    ],
)
def test_internal_ips_filtered(ip):
    assert adv._is_internal_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2001:4860:4860::8888",
    ],
)
def test_public_ips_pass(ip):
    assert adv._is_internal_ip(ip) is False


# ---------------------------------------------------------------
# Internal-domain filter
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        "host.local",
        "fileserver.lan",
        "intranet.corp",
        "system.intranet",
        "machine.home",
        "server.localdomain",
        "host.internal",
        "singlelabel",        # no dot
        "",                   # empty
    ],
)
def test_internal_domains_filtered(domain):
    assert adv._is_internal_domain(domain) is True


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "phish.attacker.example",
        "foo.org.uk",
    ],
)
def test_external_domains_pass(domain):
    assert adv._is_internal_domain(domain) is False


# ---------------------------------------------------------------
# enrich_iocs end-to-end — internal items never reach the lookup
# ---------------------------------------------------------------


def test_enrich_iocs_skips_internals(monkeypatch):
    """When network policy and key are set, enrich_iocs would call
    lookup_virustotal_*. Track which IOCs reach the lookup and confirm
    only public ones do."""
    monkeypatch.setattr(adv, "_vt_is_online", lambda: True)
    monkeypatch.setattr(adv, "_vt_api_key", lambda: "fake-key")

    seen = {"domains": [], "ips": []}

    def fake_dom(d):
        seen["domains"].append(d)
        return {"malicious": 0}

    def fake_ip(i):
        seen["ips"].append(i)
        return {"malicious": 0}

    monkeypatch.setattr(adv, "lookup_virustotal_domain", fake_dom)
    monkeypatch.setattr(adv, "lookup_virustotal_ip", fake_ip)

    ioc_data = {
        "domains": [
            "evil.example.com",     # public — should query
            "host.local",           # internal — must skip
            "internal.corp",        # internal — must skip
            "singlelabel",          # no dot — must skip
        ],
        "ipv4": [
            "8.8.8.8",              # public — should query
            "10.0.0.1",             # private — must skip
            "127.0.0.1",            # loopback — must skip
        ],
        "ipv6": [
            "fe80::1",              # link-local — must skip
            "::1",                  # loopback — must skip
        ],
    }
    adv.enrich_iocs(ioc_data)

    assert seen["domains"] == ["evil.example.com"], seen
    assert seen["ips"] == ["8.8.8.8"], seen
