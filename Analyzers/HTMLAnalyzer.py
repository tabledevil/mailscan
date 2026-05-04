"""HTML content analyzer using justhtml.

Replaces the old BeautifulSoup + lxml implementation with justhtml which is
pure-Python, zero-dependency, and has built-in sanitization, CSS selectors,
to_text(), and to_markdown().
"""

import logging
import re

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

try:
    import justhtml
    from justhtml.sanitize import sanitize_dom

    _JUSTHTML_AVAILABLE = True
except ImportError:
    _JUSTHTML_AVAILABLE = False

# Legacy fallback
try:
    from bs4 import BeautifulSoup as bs
except ImportError:
    bs = None


class HTMLAnalyzer(Analyzer):
    compatible_mime_types = ["text/html"]
    description = "HTML Analyser"
    specificity = 15
    optional_pip_dependencies = [("justhtml", "justhtml")]
    extra = "html"

    def analysis(self):
        super().analysis()

        raw = self.struct.rawdata

        if _JUSTHTML_AVAILABLE:
            self._analyze_justhtml(raw)
        elif bs is not None:
            log.info("justhtml not installed, falling back to BeautifulSoup")
            self._analyze_bs4(raw)
        else:
            log.warning("No HTML parser available. Install justhtml: pip install justhtml")
            self.text = raw.decode("utf-8", errors="replace")
            self.info = "no parser"
            return

        # Phishing heuristics work on the raw HTML so they fire whether
        # justhtml/bs4 is available or not. Each shape is independent
        # and scored separately.
        self._detect_phishing_indicators(raw)

    # ------------------------------------------------------------------
    # Phishing heuristics — independent of parser availability
    # ------------------------------------------------------------------

    # Form action posting to an external URL — relative URLs and
    # same-document anchors don't qualify.
    _FORM_TAG_RE = re.compile(rb"<form\b([^>]*)>", re.IGNORECASE)
    _FORM_ACTION_RE = re.compile(
        rb"""\baction\s*=\s*["']([^"']+)["']""", re.IGNORECASE,
    )

    # Password-style input → strong credential-harvest signal when paired
    # with an external form action.
    _PASSWORD_INPUT_RE = re.compile(
        rb"""<input\b[^>]*\btype\s*=\s*["']password["']""",
        re.IGNORECASE | re.DOTALL,
    )

    # Hidden inputs whose ``name`` resembles a credential field — common
    # in pages that collect credentials but mask them as something else.
    _HIDDEN_CRED_RE = re.compile(
        rb"""<input\b[^>]*\btype\s*=\s*["']hidden["'][^>]*"""
        rb"""\bname\s*=\s*["'](?:user(?:name)?|email|login|account|pin|"""
        rb"""password|passwd|pwd|token|csrf)["']""",
        re.IGNORECASE | re.DOTALL,
    )

    # <meta http-equiv="refresh" content="0; url=https://..."> redirects
    _META_REFRESH_RE = re.compile(
        rb"""<meta\b[^>]*http-equiv\s*=\s*["']refresh["'][^>]*"""
        rb"""content\s*=\s*["'][^"']*url\s*=\s*([^"';\s]+)""",
        re.IGNORECASE | re.DOTALL,
    )

    # JS-driven location change in <script> — narrow regex; doesn't try
    # to parse JS, just spots the most common stagers.
    _JS_LOCATION_RE = re.compile(
        rb"""(?:window\s*\.\s*location|document\s*\.\s*location|"""
        rb"""location\s*\.\s*(?:href|replace|assign))\s*"""
        rb"""(?:=|\(\s*)\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )

    @staticmethod
    def _is_external_url(url: bytes) -> bool:
        """True for absolute http(s)/ftp URLs; False for relative paths,
        anchors, mailto/tel/data, and same-document fragments."""
        u = url.strip().lower()
        if not u:
            return False
        if u.startswith((b"http://", b"https://", b"ftp://")):
            return True
        return False

    def _detect_phishing_indicators(self, raw: bytes) -> None:
        """Independent phishing-shape heuristics on the raw HTML."""
        # 1. Credential-harvesting forms — <form action=external> with a
        #    <input type="password"> nested inside.
        forms_with_password = []
        for m in self._FORM_TAG_RE.finditer(raw):
            attrs = m.group(1)
            action_m = self._FORM_ACTION_RE.search(attrs)
            if not action_m:
                continue
            action = action_m.group(1)
            if not self._is_external_url(action):
                continue
            # Check whether the form body (until matching </form>) has a
            # password input. Simple heuristic: scan from the form tag
            # to the next </form> close (or 8 KB cap).
            tail_start = m.end()
            close_idx = raw.lower().find(b"</form>", tail_start)
            if close_idx < 0:
                close_idx = min(tail_start + 8192, len(raw))
            body = raw[tail_start:close_idx]
            has_password = bool(self._PASSWORD_INPUT_RE.search(body))
            if has_password:
                forms_with_password.append(action.decode("utf-8",
                                                          errors="replace"))

        if forms_with_password:
            self.reports["phishing_credential_form"] = Report(
                "Credential-harvesting form posting to external URL:\n"
                + "\n".join(f"  - {a}" for a in forms_with_password),
                short=f"{len(forms_with_password)} cred-harvest form(s)",
                label="phishing_credential_form",
                severity=Severity.HIGH,
                verbosity=0,
                order=22,
                data={"actions": forms_with_password},
            )

        # 2. Hidden credential fields — flag separately even when no
        #    password field is present (many phishing pages mask
        #    credentials as ``hidden`` and submit via JS).
        hidden_hits = self._HIDDEN_CRED_RE.findall(raw)
        if hidden_hits:
            self.reports["phishing_hidden_cred_fields"] = Report(
                f"{len(hidden_hits)} hidden credential-style input(s) — "
                "common in pages that submit captured credentials via "
                "JavaScript without a visible password field",
                short=f"{len(hidden_hits)} hidden cred field(s)",
                label="phishing_hidden_cred_fields",
                severity=Severity.MEDIUM,
                verbosity=0,
                order=23,
                data={"count": len(hidden_hits)},
            )

        # 3. Meta-refresh / JS-only redirect to external URL.
        redirect_targets = []
        for m in self._META_REFRESH_RE.finditer(raw):
            target = m.group(1)
            if self._is_external_url(target):
                redirect_targets.append(
                    ("meta-refresh", target.decode("utf-8", errors="replace"))
                )
        for m in self._JS_LOCATION_RE.finditer(raw):
            target = m.group(1)
            if self._is_external_url(target):
                redirect_targets.append(
                    ("js-location", target.decode("utf-8", errors="replace"))
                )
        if redirect_targets:
            self.reports["phishing_redirect"] = Report(
                "External redirect detected:\n"
                + "\n".join(f"  - [{kind}] {url}"
                            for kind, url in redirect_targets),
                short=f"{len(redirect_targets)} external redirect(s)",
                label="phishing_redirect",
                severity=Severity.MEDIUM,
                verbosity=0,
                order=23,
                data={"redirects": [
                    {"kind": k, "url": u} for k, u in redirect_targets
                ]},
            )

    # ------------------------------------------------------------------
    # justhtml implementation
    # ------------------------------------------------------------------
    def _analyze_justhtml(self, raw: bytes):
        html_str = raw.decode("utf-8", errors="replace")
        doc = justhtml.JustHTML(html_str)

        # Sanitize: strips <script>, event handlers, etc.
        sanitize_dom(doc.root)

        self.text = doc.to_text()
        self._doc = doc

        # Count top-level body children for info
        body_nodes = doc.query("body > *")
        count = len(body_nodes) if body_nodes else 1
        self.info = f"{count} element(s)"

        # Extract links as reports
        links = doc.query("a[href]")
        if links:
            link_list = []
            for link in links:
                href = link.attrs.get("href", "")
                text = link.to_text().strip()
                if href:
                    display = f"{text} -> {href}" if text else href
                    link_list.append(display)
            if link_list:
                self.reports["links"] = Report(
                    text="\n".join(link_list),
                    short=f"{len(link_list)} link(s)",
                    label="links",
                    severity=Severity.INFO,
                    verbosity=2,
                )

        # Extract images (potential tracking pixels)
        images = doc.query("img[src]")
        if images:
            img_list = []
            for img in images:
                src = img.attrs.get("src", "")
                if src:
                    img_list.append(src)
            if img_list:
                self.reports["images"] = Report(
                    text="\n".join(img_list),
                    short=f"{len(img_list)} image(s)",
                    label="images",
                    severity=Severity.INFO,
                    verbosity=2,
                )

        # Extract forms (suspicious in email context)
        forms = doc.query("form")
        if forms:
            form_actions = []
            for form in forms:
                action = form.attrs.get("action", "(no action)")
                method = form.attrs.get("method", "GET").upper()
                form_actions.append(f"{method} {action}")
            self.reports["forms"] = Report(
                text="\n".join(form_actions),
                short=f"{len(forms)} form(s) found",
                label="forms",
                severity=Severity.MEDIUM,
                verbosity=0,
            )

    # ------------------------------------------------------------------
    # BeautifulSoup fallback (legacy)
    # ------------------------------------------------------------------
    def _analyze_bs4(self, raw: bytes):
        soup = bs(raw, features="lxml")
        self.text = soup.getText()
        self.info = len(soup.contents)

    def get_childitems(self) -> list:
        if hasattr(self, "text") and self.text:
            return [self.generate_struct(data=self.text.encode("utf-8"), mime_type="text/plain")]
        return []
