"""VBA autoload trigger enumeration — unit tests for the regex helpers.

The full integration path runs olevba on a real OLE binary, which is
heavy to fixture for unit testing. The trigger enumerator is a pure
function over the source string so we can pin every case directly.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Analyzers.VBAProjectAnalyzer import _enumerate_autoload_triggers


# ---------------------------------------------------------------
# Word document events
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "Document_Open", "Document_Close", "Document_New",
        "Document_BeforeSave", "Document_BeforeClose",
        "AutoOpen", "AutoNew", "AutoClose", "AutoExec", "AutoExit",
    ],
)
def test_word_autoload_triggers_detected(name):
    src = f"Sub {name}()\n  MsgBox 1\nEnd Sub\n"
    found = _enumerate_autoload_triggers(src)
    assert len(found) == 1
    assert found[0]["name"] == name
    assert found[0]["kind"] == "autoload"


# ---------------------------------------------------------------
# Excel workbook events + Auto_Open/Close
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "Workbook_Open", "Workbook_BeforeClose", "Workbook_BeforeSave",
        "Workbook_AfterOpen", "Workbook_NewSheet",
        "Auto_Open", "Auto_Close",
    ],
)
def test_excel_autoload_triggers_detected(name):
    src = f"Private Sub {name}()\n  Shell \"calc.exe\"\nEnd Sub\n"
    found = _enumerate_autoload_triggers(src)
    assert len(found) == 1
    assert found[0]["name"] == name


# ---------------------------------------------------------------
# Control-event handlers
# ---------------------------------------------------------------


def test_control_click_handler_detected():
    src = """
Private Sub Image1_Click()
    Shell "cmd.exe /c whoami"
End Sub
"""
    found = _enumerate_autoload_triggers(src)
    assert len(found) == 1
    assert found[0]["name"] == "Image1_Click"
    assert found[0]["kind"] == "control_event"


def test_control_change_handler_detected():
    src = "Sub TextBox1_Change()\n  Call DoEvil\nEnd Sub\n"
    found = _enumerate_autoload_triggers(src)
    assert len(found) == 1
    assert found[0]["kind"] == "control_event"


# ---------------------------------------------------------------
# Multiple triggers in one module
# ---------------------------------------------------------------


def test_multiple_triggers_enumerated():
    src = """
Sub Document_Open()
End Sub

Private Sub Workbook_BeforeClose(Cancel As Boolean)
End Sub

Sub Image1_Click()
End Sub
"""
    found = _enumerate_autoload_triggers(src)
    names = {t["name"] for t in found}
    assert "Document_Open" in names
    assert "Workbook_BeforeClose" in names
    assert "Image1_Click" in names
    autoloads = [t for t in found if t["kind"] == "autoload"]
    events = [t for t in found if t["kind"] == "control_event"]
    assert len(autoloads) == 2
    assert len(events) == 1


# ---------------------------------------------------------------
# Negative cases — must not fire on user-defined non-trigger names
# ---------------------------------------------------------------


def test_user_defined_helper_not_flagged():
    """A normal helper sub must NOT be flagged as autoload — only the
    documented trigger names are recognised."""
    src = "Sub MyHelper(x As Integer)\n  Debug.Print x\nEnd Sub\n"
    found = _enumerate_autoload_triggers(src)
    assert found == []


def test_function_with_trigger_name_in_body_not_flagged():
    """Body text mentioning ``Document_Open`` must NOT cause a hit —
    only Sub/Function declarations qualify."""
    src = "Sub Other()\n  Call Something \" Document_Open is referenced\"\nEnd Sub\n"
    found = _enumerate_autoload_triggers(src)
    assert found == []


# ---------------------------------------------------------------
# Line numbers track the declaration site
# ---------------------------------------------------------------


def test_line_numbers_correct():
    src = """' header comment
Option Explicit

Sub Document_Open()
End Sub
"""
    found = _enumerate_autoload_triggers(src)
    assert len(found) == 1
    assert found[0]["line"] == 4


# ---------------------------------------------------------------
# Case insensitivity
# ---------------------------------------------------------------


def test_case_insensitive_match():
    """VBA is case-insensitive — ``DOCUMENT_OPEN``, ``document_open``,
    and ``Document_Open`` all bind to the same auto-exec slot."""
    src = "sub DOCUMENT_OPEN()\nend sub\n"
    found = _enumerate_autoload_triggers(src)
    assert len(found) == 1
    assert found[0]["name"].lower() == "document_open"
