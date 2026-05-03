"""Audit follow-up — box-js sandbox gate.

Audit finding (codex_security_1, codex_security_2, severity CRITICAL):
the dynamic-JS path detonates attacker-controlled bytes on whatever
host has box-js on PATH. The Sprint-8 box-js wrapper recognized
``MATT_IN_DOCKER=1`` for test selection but still ran box-js on the
host when invoked through the analyzer pipeline.

These tests pin the corrected behavior so future cleanup can't
silently restore the host-detonation path.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils import js_tools


@pytest.fixture
def _no_sandbox_env(monkeypatch):
    monkeypatch.delenv("MATT_IN_DOCKER", raising=False)
    monkeypatch.delenv("MATT_ALLOW_HOST_SANDBOX", raising=False)
    yield


@pytest.fixture
def _docker_env(monkeypatch):
    monkeypatch.setenv("MATT_IN_DOCKER", "1")
    monkeypatch.delenv("MATT_ALLOW_HOST_SANDBOX", raising=False)
    yield


def test_run_boxjs_refuses_outside_sandbox(_no_sandbox_env, caplog):
    """On a plain host with neither env var set, run_boxjs MUST return
    None and MUST NOT shell out to box-js."""
    import logging
    with caplog.at_level(logging.WARNING, logger="matt"):
        result = js_tools.run_boxjs(b"alert('x')", timeout=5)
    assert result is None
    assert any("refused" in r.message.lower() for r in caplog.records)


def test_boxjs_available_returns_false_outside_sandbox(_no_sandbox_env, monkeypatch):
    """boxjs_available() must reflect the sandbox gate, not just binary
    presence — otherwise --check and the analyzer dispatch keep firing
    on the host."""
    # Pretend the binary is present
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/box-js")
    assert js_tools.boxjs_available() is False


def test_boxjs_available_true_with_docker_env(_docker_env, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/box-js")
    assert js_tools.boxjs_available() is True


def test_explicit_host_opt_in_unlocks_gate(monkeypatch):
    """MATT_ALLOW_HOST_SANDBOX=1 is the documented escape hatch for
    analysts on an isolated host who explicitly accept the risk."""
    monkeypatch.delenv("MATT_IN_DOCKER", raising=False)
    monkeypatch.setenv("MATT_ALLOW_HOST_SANDBOX", "1")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/box-js")
    assert js_tools.boxjs_available() is True
