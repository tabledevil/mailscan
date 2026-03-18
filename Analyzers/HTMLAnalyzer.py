"""HTML content analyzer using justhtml.

Replaces the old BeautifulSoup + lxml implementation with justhtml which is
pure-Python, zero-dependency, and has built-in sanitization, CSS selectors,
to_text(), and to_markdown().
"""

import logging

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
