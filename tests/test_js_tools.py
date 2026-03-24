"""Tests for Utils/js_tools.py — subprocess wrappers for box-js, JStillery, de4js."""

import json
import os
import subprocess
from unittest import mock

import pytest

from Utils.js_tools import (
    boxjs_available,
    de4js_available,
    jstillery_available,
    run_boxjs,
    run_de4js,
    run_jstillery,
)


# ===================================================================
# Availability checks
# ===================================================================


class TestAvailability:
    def test_boxjs_available_true(self):
        with mock.patch("shutil.which", return_value="/usr/bin/box-js"):
            assert boxjs_available() is True

    def test_boxjs_available_false(self):
        with mock.patch("shutil.which", return_value=None):
            assert boxjs_available() is False

    def test_jstillery_available_true_cli(self):
        def which_side(name):
            return "/usr/bin/jstillery_cli.js" if name == "jstillery_cli.js" else None
        with mock.patch("shutil.which", side_effect=which_side):
            assert jstillery_available() is True

    def test_jstillery_available_true_alias(self):
        def which_side(name):
            return "/usr/bin/jstillery" if name == "jstillery" else None
        with mock.patch("shutil.which", side_effect=which_side):
            assert jstillery_available() is True

    def test_jstillery_available_false(self):
        with mock.patch("shutil.which", return_value=None):
            assert jstillery_available() is False

    def test_de4js_available_true(self):
        with mock.patch("shutil.which", return_value="/usr/bin/de4js"):
            assert de4js_available() is True

    def test_de4js_available_false(self):
        with mock.patch("shutil.which", return_value=None):
            assert de4js_available() is False


# ===================================================================
# box-js
# ===================================================================


class TestRunBoxjs:
    def test_parses_output_files(self, tmp_path):
        """Mock subprocess + tempdir to verify box-js output parsing."""
        js_data = b'var x = new ActiveXObject("WScript.Shell");'

        def mock_run(cmd, **kwargs):
            # Simulate box-js creating output in the results dir
            results_dir = None
            for i, arg in enumerate(cmd):
                if arg == "--output-dir" and i + 1 < len(cmd):
                    results_dir = cmd[i + 1]
                    break
            if results_dir:
                os.makedirs(results_dir, exist_ok=True)
                with open(os.path.join(results_dir, "urls.json"), "w") as f:
                    json.dump(["http://evil.example.com/payload.exe"], f)
                with open(os.path.join(results_dir, "active_urls.json"), "w") as f:
                    json.dump(["http://evil.example.com/payload.exe"], f)
                with open(os.path.join(results_dir, "IOC.json"), "w") as f:
                    json.dump(["evil.example.com"], f)
                with open(os.path.join(results_dir, "snippets.json"), "w") as f:
                    json.dump(["cmd /c whoami"], f)
                with open(os.path.join(results_dir, "resources.json"), "w") as f:
                    json.dump([{"filename": "payload.exe", "type": "PE"}], f)
                # Write a fake payload
                with open(os.path.join(results_dir, "payload.exe"), "wb") as f:
                    f.write(b"MZfakepayload")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        with mock.patch("Utils.js_tools.subprocess.run", side_effect=mock_run):
            result = run_boxjs(js_data)

        assert result is not None
        assert result["urls"] == ["http://evil.example.com/payload.exe"]
        assert result["active_urls"] == ["http://evil.example.com/payload.exe"]
        assert result["ioc"] == ["evil.example.com"]
        assert result["snippets"] == ["cmd /c whoami"]
        assert result["resources"] == [{"filename": "payload.exe", "type": "PE"}]
        assert len(result["payloads"]) == 1
        assert result["payloads"][0]["filename"] == "payload.exe"
        assert result["payloads"][0]["data"] == b"MZfakepayload"

    def test_timeout_returns_none(self):
        with mock.patch(
            "Utils.js_tools.subprocess.run",
            side_effect=subprocess.TimeoutExpired("box-js", 30),
        ):
            assert run_boxjs(b"var x = 1;") is None

    def test_missing_tool_returns_none(self):
        with mock.patch(
            "Utils.js_tools.subprocess.run",
            side_effect=FileNotFoundError("box-js not found"),
        ):
            assert run_boxjs(b"var x = 1;") is None

    def test_no_results_dir_returns_none(self):
        """box-js runs but produces no output dir."""
        with mock.patch(
            "Utils.js_tools.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, b"", b"error"),
        ):
            assert run_boxjs(b"var x = 1;") is None

    def test_fallback_to_sample_js_results(self, tmp_path):
        """Test fallback path: sample.js.results instead of --output-dir."""
        js_data = b"var x = 1;"

        def mock_run(cmd, **kwargs):
            # Don't create the --output-dir, simulate box-js default behavior
            cwd = kwargs.get("cwd", "")
            sample_results = os.path.join(cwd, "sample.js.results")
            os.makedirs(sample_results, exist_ok=True)
            with open(os.path.join(sample_results, "urls.json"), "w") as f:
                json.dump(["http://test.example.com"], f)
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        with mock.patch("Utils.js_tools.subprocess.run", side_effect=mock_run):
            result = run_boxjs(js_data)

        assert result is not None
        assert "urls" in result


# ===================================================================
# JStillery
# ===================================================================


class TestRunJStillery:
    def test_returns_deobfuscated(self):
        deobfuscated = 'var url = "http://evil.example.com";'
        with mock.patch("shutil.which", return_value="/usr/bin/jstillery_cli.js"):
            with mock.patch(
                "Utils.js_tools.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout=deobfuscated, stderr=""
                ),
            ):
                result = run_jstillery("eval(obfuscated_stuff)")
        assert result == deobfuscated

    def test_same_output_returns_none(self):
        source = "var x = 1;"
        with mock.patch("shutil.which", return_value="/usr/bin/jstillery_cli.js"):
            with mock.patch(
                "Utils.js_tools.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout=source, stderr=""
                ),
            ):
                result = run_jstillery(source)
        assert result is None

    def test_timeout_returns_none(self):
        with mock.patch("shutil.which", return_value="/usr/bin/jstillery_cli.js"):
            with mock.patch(
                "Utils.js_tools.subprocess.run",
                side_effect=subprocess.TimeoutExpired("jstillery", 15),
            ):
                assert run_jstillery("eval(x)") is None

    def test_nonzero_exit_returns_none(self):
        with mock.patch("shutil.which", return_value="/usr/bin/jstillery_cli.js"):
            with mock.patch(
                "Utils.js_tools.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 1, stdout="", stderr="SyntaxError"
                ),
            ):
                assert run_jstillery("eval(x)") is None


# ===================================================================
# de4js
# ===================================================================


class TestRunDe4js:
    def test_returns_unpacked(self):
        unpacked = 'alert("hello world");'
        with mock.patch(
            "Utils.js_tools.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout=unpacked, stderr=""
            ),
        ):
            result = run_de4js("eval(packed_stuff)")
        assert result == unpacked

    def test_same_output_returns_none(self):
        source = "var x = 1;"
        with mock.patch(
            "Utils.js_tools.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout=source, stderr=""
            ),
        ):
            assert run_de4js(source) is None

    def test_timeout_returns_none(self):
        with mock.patch(
            "Utils.js_tools.subprocess.run",
            side_effect=subprocess.TimeoutExpired("de4js", 15),
        ):
            assert run_de4js("eval(x)") is None

    def test_nonzero_exit_returns_none(self):
        with mock.patch(
            "Utils.js_tools.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 1, stdout="", stderr="error"
            ),
        ):
            assert run_de4js("eval(x)") is None
