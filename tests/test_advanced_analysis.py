"""Tests for Sprint 5 advanced analysis features and analyzer cache.

Covers: entropy, fuzzy hashing, YARA scanning, VirusTotal lookup,
MITRE ATT&CK mapping, timeline collection, and analyzer cache.
"""

import io
import json
import os
import sys
import tempfile
import textwrap
import time
import zipfile
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Config.config import flags, Flags
from structure import Structure, Severity, Report, Analyzer
from Utils.advanced_analysis import (
    shannon_entropy,
    entropy_assessment,
    fuzzy_hashes,
    scan_yara,
    lookup_virustotal,
    lookup_virustotal_domain,
    lookup_virustotal_ip,
    enrich_iocs,
    mitre_attack_techniques,
    collect_timeline_events,
    _parse_timestamp,
)
from Utils.analyzer_cache import AnalyzerCache
from Utils.password_broker import PasswordBroker


def make_struct(data: bytes, *, mime_type=None, filename=None, metadata=None):
    """Create a Structure from raw bytes, optionally forcing MIME type."""
    return Structure.create(data=data, filename=filename, mime_type=mime_type, metadata=metadata)


@pytest.fixture(autouse=True)
def _clear_caches():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


# ===================================================================
# Entropy
# ===================================================================
class TestShannonEntropy:
    def test_empty_data(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte(self):
        assert shannon_entropy(b"\x00") == 0.0

    def test_uniform_bytes(self):
        # All same byte → 0 entropy
        assert shannon_entropy(b"\xAA" * 1024) == 0.0

    def test_two_equal_symbols(self):
        # 50/50 split → entropy of 1.0
        data = b"\x00" * 512 + b"\xFF" * 512
        assert abs(shannon_entropy(data) - 1.0) < 0.01

    def test_high_entropy_random(self):
        # All 256 byte values equally → entropy ~8.0
        data = bytes(range(256)) * 4
        assert shannon_entropy(data) > 7.9

    def test_text_has_moderate_entropy(self):
        data = b"The quick brown fox jumps over the lazy dog." * 10
        ent = shannon_entropy(data)
        assert 3.0 < ent < 5.0


class TestEntropyAssessment:
    def test_returns_dict(self):
        result = entropy_assessment(b"hello world")
        assert isinstance(result, dict)
        assert "entropy" in result
        assert "severity" in result
        assert "summary" in result

    def test_low_entropy_is_info(self):
        result = entropy_assessment(b"\x00" * 256)
        assert result["severity"] == "INFO"

    def test_high_entropy_is_medium(self):
        data = bytes(range(256)) * 4
        result = entropy_assessment(data)
        assert result["severity"] == "MEDIUM"

    def test_empty_data_is_info(self):
        result = entropy_assessment(b"")
        assert result["severity"] == "INFO"
        assert result["entropy"] == 0.0

    def test_mime_type_passthrough(self):
        result = entropy_assessment(b"data", mime_type="application/zip")
        assert result["mime_type"] == "application/zip"


# ===================================================================
# Fuzzy Hashes
# ===================================================================
class TestFuzzyHashes:
    def test_empty_data(self):
        assert fuzzy_hashes(b"") == {}

    def test_nonempty_data(self):
        # Result depends on whether ssdeep/tlsh are installed
        data = b"A" * 200
        result = fuzzy_hashes(data)
        assert isinstance(result, dict)

    def test_short_data_skips_tlsh(self):
        # TLSH requires >= 50 bytes
        data = b"short"
        result = fuzzy_hashes(data)
        assert "tlsh" not in result


# ===================================================================
# YARA
# ===================================================================
class TestYaraScan:
    def test_no_rules_returns_empty(self):
        # With default dirs (no rules present), should return empty
        result = scan_yara(b"some random data")
        # May or may not be empty depending on builtin rules
        assert isinstance(result, list)

    @pytest.fixture
    def yara_rule_dir(self, tmp_path):
        """Create a temp dir with a simple YARA rule."""
        rule = textwrap.dedent("""\
            rule TestRule {
                meta:
                    description = "Test rule for MATT"
                strings:
                    $magic = "YARA_TEST_MARKER"
                condition:
                    $magic
            }
        """)
        rule_file = tmp_path / "test_rule.yar"
        rule_file.write_text(rule)
        return str(tmp_path)

    def test_matching_rule(self, yara_rule_dir):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        old_dir = flags.yara_rules_dir
        flags.yara_rules_dir = yara_rule_dir
        try:
            result = scan_yara(b"prefix YARA_TEST_MARKER suffix")
            assert len(result) >= 1
            rules_found = [m["rule"] for m in result]
            assert "TestRule" in rules_found
        finally:
            flags.yara_rules_dir = old_dir

    def test_non_matching(self, yara_rule_dir):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        old_dir = flags.yara_rules_dir
        flags.yara_rules_dir = yara_rule_dir
        try:
            result = scan_yara(b"this data does not match anything")
            # Should not match TestRule
            rules_found = [m["rule"] for m in result]
            assert "TestRule" not in rules_found
        finally:
            flags.yara_rules_dir = old_dir


# ===================================================================
# VirusTotal
# ===================================================================
class TestVirusTotal:
    def test_offline_returns_none(self):
        old = flags.network_policy
        flags.network_policy = "offline"
        try:
            assert lookup_virustotal("abc123") is None
        finally:
            flags.network_policy = old

    def test_passive_returns_none(self):
        old = flags.network_policy
        flags.network_policy = "passive"
        try:
            assert lookup_virustotal("abc123") is None
        finally:
            flags.network_policy = old

    def test_no_api_key_returns_none(self):
        old_policy = flags.network_policy
        old_key = flags.vt_api_key
        flags.network_policy = "online"
        flags.vt_api_key = None
        try:
            with mock.patch.dict(os.environ, {}, clear=True):
                assert lookup_virustotal("abc123") is None
        finally:
            flags.network_policy = old_policy
            flags.vt_api_key = old_key

    def test_successful_lookup(self):
        old_policy = flags.network_policy
        old_key = flags.vt_api_key
        flags.network_policy = "online"
        flags.vt_api_key = "test-key"

        mock_response = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 4,
                        "timeout": 0,
                    },
                    "last_analysis_date": 1700000000,
                    "reputation": -10,
                }
            }
        }).encode()

        try:
            with mock.patch("Utils.advanced_analysis.urlrequest.urlopen") as mock_urlopen:
                mock_resp = mock.MagicMock()
                mock_resp.read.return_value = mock_response
                mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
                mock_resp.__exit__ = mock.Mock(return_value=False)
                mock_urlopen.return_value = mock_resp

                # Clear LRU cache first
                from Utils.advanced_analysis import _lookup_virustotal_cached
                _lookup_virustotal_cached.cache_clear()

                result = lookup_virustotal("abc123sha256")
                assert result is not None
                assert result["malicious"] == 5
                assert result["suspicious"] == 1
                assert result["harmless"] == 60
                assert "permalink" in result
        finally:
            flags.network_policy = old_policy
            flags.vt_api_key = old_key
            _lookup_virustotal_cached.cache_clear()


class TestVirusTotalDomain:
    def test_offline_returns_none(self):
        old = flags.network_policy
        flags.network_policy = "offline"
        try:
            assert lookup_virustotal_domain("evil.com") is None
        finally:
            flags.network_policy = old

    def test_successful_domain_lookup(self):
        old_policy = flags.network_policy
        old_key = flags.vt_api_key
        flags.network_policy = "online"
        flags.vt_api_key = "test-key"

        mock_response = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 2,
                    },
                    "reputation": -5,
                }
            }
        }).encode()

        try:
            with mock.patch("Utils.advanced_analysis.urlrequest.urlopen") as mock_urlopen:
                mock_resp = mock.MagicMock()
                mock_resp.read.return_value = mock_response
                mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
                mock_resp.__exit__ = mock.Mock(return_value=False)
                mock_urlopen.return_value = mock_resp

                from Utils.advanced_analysis import _lookup_vt_domain_cached
                _lookup_vt_domain_cached.cache_clear()

                result = lookup_virustotal_domain("evil.com")
                assert result is not None
                assert result["domain"] == "evil.com"
                assert result["malicious"] == 3
                assert "permalink" in result
        finally:
            flags.network_policy = old_policy
            flags.vt_api_key = old_key
            _lookup_vt_domain_cached.cache_clear()


class TestVirusTotalIP:
    def test_offline_returns_none(self):
        old = flags.network_policy
        flags.network_policy = "offline"
        try:
            assert lookup_virustotal_ip("1.2.3.4") is None
        finally:
            flags.network_policy = old

    def test_successful_ip_lookup(self):
        old_policy = flags.network_policy
        old_key = flags.vt_api_key
        flags.network_policy = "online"
        flags.vt_api_key = "test-key"

        mock_response = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 80,
                        "undetected": 0,
                    },
                    "reputation": 0,
                    "as_owner": "Example ISP",
                    "country": "US",
                }
            }
        }).encode()

        try:
            with mock.patch("Utils.advanced_analysis.urlrequest.urlopen") as mock_urlopen:
                mock_resp = mock.MagicMock()
                mock_resp.read.return_value = mock_response
                mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
                mock_resp.__exit__ = mock.Mock(return_value=False)
                mock_urlopen.return_value = mock_resp

                from Utils.advanced_analysis import _lookup_vt_ip_cached
                _lookup_vt_ip_cached.cache_clear()

                result = lookup_virustotal_ip("1.2.3.4")
                assert result is not None
                assert result["ip"] == "1.2.3.4"
                assert result["malicious"] == 2
                assert result["as_owner"] == "Example ISP"
                assert "permalink" in result
        finally:
            flags.network_policy = old_policy
            flags.vt_api_key = old_key
            _lookup_vt_ip_cached.cache_clear()


class TestEnrichIOCs:
    def test_offline_returns_empty(self):
        old = flags.network_policy
        flags.network_policy = "offline"
        try:
            result = enrich_iocs({"domains": ["evil.com"], "ipv4": ["1.2.3.4"]})
            assert result == {}
        finally:
            flags.network_policy = old

    def test_no_key_returns_empty(self):
        old_policy = flags.network_policy
        old_key = flags.vt_api_key
        flags.network_policy = "online"
        flags.vt_api_key = None
        try:
            with mock.patch.dict(os.environ, {}, clear=True):
                result = enrich_iocs({"domains": ["evil.com"]})
                assert result == {}
        finally:
            flags.network_policy = old_policy
            flags.vt_api_key = old_key

    def test_enriches_domains_and_ips(self):
        old_policy = flags.network_policy
        old_key = flags.vt_api_key
        flags.network_policy = "online"
        flags.vt_api_key = "test-key"

        mock_vt = {"malicious": 1, "suspicious": 0, "harmless": 50, "undetected": 0}

        try:
            with mock.patch("Utils.advanced_analysis.lookup_virustotal_domain") as mock_domain, \
                 mock.patch("Utils.advanced_analysis.lookup_virustotal_ip") as mock_ip:
                mock_domain.return_value = {**mock_vt, "domain": "evil.com", "permalink": "..."}
                mock_ip.return_value = {**mock_vt, "ip": "1.2.3.4", "permalink": "..."}

                result = enrich_iocs({"domains": ["evil.com"], "ipv4": ["1.2.3.4"]})
                assert "evil.com" in result
                assert "1.2.3.4" in result
        finally:
            flags.network_policy = old_policy
            flags.vt_api_key = old_key


# ===================================================================
# MITRE ATT&CK
# ===================================================================
class _MockStruct:
    """Minimal Structure-like object for MITRE tests."""
    def __init__(self, filename="test.bin"):
        self.filename = filename


class _MockAnalyzer:
    """Minimal Analyzer-like object for MITRE tests."""
    def __init__(self, reports=None):
        self.reports = reports or {}


class TestMitreAttack:
    def test_js_filename_triggers_javascript(self):
        struct = _MockStruct(filename="payload.js")
        analyzer = _MockAnalyzer(reports={
            "script_type": Report("JavaScript", label="script_type"),
        })
        analyzer.__class__ = type("ScriptAnalyzer", (), {})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1059.007" in ids

    def test_ps1_filename_triggers_powershell(self):
        struct = _MockStruct(filename="dropper.ps1")
        analyzer = _MockAnalyzer(reports={
            "script_type": Report("PowerShell", label="script_type"),
        })
        analyzer.__class__ = type("ScriptAnalyzer", (), {})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1059.001" in ids

    def test_vbs_triggers_vbscript(self):
        struct = _MockStruct(filename="evil.vbs")
        analyzer = _MockAnalyzer(reports={
            "script_type": Report("VBScript", label="script_type"),
        })
        analyzer.__class__ = type("ScriptAnalyzer", (), {})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1059.005" in ids

    def test_bat_triggers_command_shell(self):
        struct = _MockStruct(filename="run.bat")
        analyzer = _MockAnalyzer(reports={
            "script_type": Report("", label="script_type"),
        })
        analyzer.__class__ = type("ScriptAnalyzer", (), {})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1059.003" in ids

    def test_encryption_label_triggers_obfuscation(self):
        struct = _MockStruct()
        report = Report("Encrypted", label="encryption")
        analyzer = _MockAnalyzer(reports={"encryption": report})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1027.013" in ids

    def test_remote_template_triggers_injection(self):
        struct = _MockStruct()
        report = Report("Remote template", label="remote_template")
        analyzer = _MockAnalyzer(reports={"rt": report})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1221" in ids

    def test_vba_label_triggers_user_execution(self):
        struct = _MockStruct()
        report = Report("VBA macros", label="vba_macros")
        analyzer = _MockAnalyzer(reports={"vba": report})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1204.002" in ids

    def test_no_labels_no_techniques(self):
        struct = _MockStruct(filename="readme.txt")
        analyzer = _MockAnalyzer()
        techniques = mitre_attack_techniques(struct, analyzer)
        assert techniques == []

    def test_script_analyzer_check(self):
        # Verifying ScriptAnalyzer name triggers script checks
        struct = _MockStruct(filename="payload.hta")
        analyzer = _MockAnalyzer(reports={
            "script_type": Report("", label="script_type"),
        })
        analyzer.__class__ = type("ScriptAnalyzer", (), {})
        techniques = mitre_attack_techniques(struct, analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1059.007" in ids


# ===================================================================
# Timeline
# ===================================================================
class TestTimeline:
    def test_parse_timestamp_none(self):
        assert _parse_timestamp(None) is None

    def test_parse_timestamp_string(self):
        result = _parse_timestamp("2024-01-15T10:30:00Z")
        assert result is not None
        assert result.year == 2024

    def test_parse_timestamp_epoch(self):
        result = _parse_timestamp(1700000000)
        assert result is not None

    def test_parse_timestamp_invalid(self):
        assert _parse_timestamp("not a date") is None

    def test_timeline_from_email(self):
        eml = textwrap.dedent("""\
            From: sender@test.example.com
            To: recipient@test.example.com
            Subject: Timeline Test
            Date: Mon, 15 Jan 2024 10:30:00 +0000
            MIME-Version: 1.0
            Content-Type: text/plain; charset="utf-8"

            Test body for timeline.
        """).encode("utf-8")

        Structure.clear_cache()
        s = Structure.create(data=eml, mime_type="message/rfc822")
        events = collect_timeline_events(s)
        # Timeline events depend on EmailAnalyzer producing date/route reports
        # with structured data — if present, they should be valid
        for event in events:
            assert "timestamp" in event
            assert "event" in event
        Structure.clear_cache()

    def test_events_sorted_chronologically(self):
        eml = textwrap.dedent("""\
            From: sender@test.example.com
            To: recipient@test.example.com
            Subject: Timeline Sort Test
            Date: Mon, 15 Jan 2024 10:30:00 +0000
            Received: from relay2.example.com by mx.example.com; Mon, 15 Jan 2024 10:29:55 +0000
            Received: from relay1.example.com by relay2.example.com; Mon, 15 Jan 2024 10:29:50 +0000
            MIME-Version: 1.0
            Content-Type: text/plain; charset="utf-8"

            Test body.
        """).encode("utf-8")

        Structure.clear_cache()
        s = Structure.create(data=eml, mime_type="message/rfc822")
        events = collect_timeline_events(s)
        # Verify sorted
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps)
        Structure.clear_cache()


# ===================================================================
# Finalize Analysis Integration
# ===================================================================
class TestFinalizeAnalysis:
    def test_entropy_report_present(self):
        Structure.clear_cache()
        data = b"Hello, this is test data for entropy measurement." * 5
        s = make_struct(data, mime_type="text/plain")
        assert "entropy" in s.analyzer.reports
        entropy_report = s.analyzer.reports["entropy"]
        assert entropy_report.label == "entropy"
        assert "entropy" in entropy_report.data
        Structure.clear_cache()

    def test_mitre_only_when_applicable(self):
        Structure.clear_cache()
        # Plain text without any script/macro indicators
        data = b"Simple test content with nothing special."
        s = make_struct(data, mime_type="text/plain")
        # MITRE report should not appear for plain text with no indicators
        if "mitre_attack" in s.analyzer.reports:
            techniques = s.analyzer.reports["mitre_attack"].data["techniques"]
            # Should not have script-related techniques for plain text
            ids = [t["id"] for t in techniques]
            assert "T1059.007" not in ids
        Structure.clear_cache()


# ===================================================================
# Analyzer Cache
# ===================================================================
class TestAnalyzerCache:
    def test_get_set(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            cache.set("key1", "value1")
            assert cache.get("key1") == "value1"

    def test_get_default(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            assert cache.get("missing") is None
            assert cache.get("missing", "default") == "default"

    def test_delete(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            cache.set("key1", "value1")
            assert cache.delete("key1") is True
            assert cache.get("key1") is None
            assert cache.delete("key1") is False

    def test_has(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            assert cache.has("key1") is False
            cache.set("key1", "value1")
            assert cache.has("key1") is True

    def test_increment(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            # New key
            result = cache.increment("relay:mx.google.com", "seen")
            assert result == 1
            # Increment again
            result = cache.increment("relay:mx.google.com", "seen")
            assert result == 2
            # Check stored value
            entry = cache.get("relay:mx.google.com")
            assert entry["seen"] == 2

    def test_increment_custom_amount(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            result = cache.increment("counter", "hits", amount=5)
            assert result == 5

    def test_keys_and_items(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            cache.set("a", 1)
            cache.set("b", 2)
            assert sorted(cache.keys()) == ["a", "b"]
            assert len(cache.items()) == 2

    def test_clear(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            cache.set("a", 1)
            cache.set("b", 2)
            cache.clear()
            assert cache.size == 0
            assert cache.keys() == []

    def test_size(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            assert cache.size == 0
            cache.set("a", 1)
            assert cache.size == 1

    def test_persistence(self, tmp_path):
        """Cache should persist to JSON and reload."""
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache1 = AnalyzerCache("persist")
            cache1.set("key", {"name": "test", "count": 42})

            # New instance should load from disk
            cache2 = AnalyzerCache("persist")
            result = cache2.get("key")
            assert result is not None
            assert result["name"] == "test"
            assert result["count"] == 42

    def test_touch(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            cache.set("relay", {"provider": "Google", "seen": 1})
            cache.touch("relay")
            entry = cache.get("relay")
            assert "last_seen" in entry
            assert isinstance(entry["last_seen"], float)

    def test_touch_nondict_noop(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("test")
            cache.set("scalar", "just a string")
            cache.touch("scalar")
            # Should not crash, value unchanged
            assert cache.get("scalar") == "just a string"

    def test_separate_namespaces(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache_a = AnalyzerCache("email")
            cache_b = AnalyzerCache("zip")
            cache_a.set("key", "from_email")
            cache_b.set("key", "from_zip")
            assert cache_a.get("key") == "from_email"
            assert cache_b.get("key") == "from_zip"

    def test_json_file_created(self, tmp_path):
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            cache = AnalyzerCache("myns")
            cache.set("x", 1)
            assert (tmp_path / "myns.json").is_file()
            data = json.loads((tmp_path / "myns.json").read_text())
            assert data["x"] == 1

    def test_corrupt_file_handled(self, tmp_path):
        """Corrupt JSON file should not crash — starts fresh."""
        with mock.patch("Utils.analyzer_cache._cache_dir", return_value=tmp_path):
            (tmp_path / "broken.json").write_text("not valid json{{{")
            cache = AnalyzerCache("broken")
            assert cache.size == 0
            cache.set("recovery", True)
            assert cache.get("recovery") is True
