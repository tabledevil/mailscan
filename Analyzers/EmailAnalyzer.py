"""Email (RFC822) analyzer.

Parses email structure, headers, mail route, and authentication results.
Uses the Eml class for MIME parsing and the new Utils/received_parser module
for hop reconstruction and Auth-Results analysis.
"""

import logging

from structure import Analyzer, Report, Severity
from eml import Eml

log = logging.getLogger("matt")

# Import the new received_parser module
try:
    from Utils.received_parser import (
        parse_received_headers,
        format_mail_route,
        parse_auth_results,
        ReceivedParserError,
    )

    _RECEIVED_PARSER_AVAILABLE = True
except ImportError:
    _RECEIVED_PARSER_AVAILABLE = False


class EmailAnalyzer(Analyzer):
    # A1: removed 'application/octet-stream' — use can_handle() instead
    compatible_mime_types = ["message/rfc822"]
    description = "Email analyser"
    pip_dependencies = [
        ("dateutil", "python-dateutil"),
        ("pytz", "pytz"),
    ]

    # A1: content-based probe for application/octet-stream
    _RFC822_SIGNATURES = (
        b"From ",
        b"From:",
        b"Received:",
        b"Return-Path:",
        b"MIME-Version:",
        b"Date:",
        b"Subject:",
        b"Message-ID:",
    )

    @classmethod
    def can_handle(cls, struct) -> bool:
        """Check if raw data looks like an RFC822 email."""
        head = struct.rawdata[:8192] if struct.rawdata else b""
        matches = sum(1 for sig in cls._RFC822_SIGNATURES if sig in head)
        return matches >= 2

    def parse_mail(self):
        try:
            self.eml = Eml(filename=self.struct.filename, data=self.struct.rawdata)
            self.info = f"{','.join(self.eml.subject)}"
            summary = []
            for f in self.eml.froms:
                summary.append(f"From   : {f}\n")
            for t in self.eml.tos:
                summary.append(f"To     : {t}\n")
            if self.eml.date:
                summary.append(f"Date   : {self.eml.date}\n")
            for s in self.eml.subject:
                summary.append(f"Subject: {s}\n")
            self.reports["summary"] = Report("".join(summary), label="summary")

            # B5: Mail route extraction using new module
            self._extract_mail_route()

            # B5: Authentication-Results parsing
            self._extract_auth_results()

        except ImportError as e:
            log.warning(f"Could not parse email due to missing dependency: {e}")
        except Exception as e:
            log.error(f"Error parsing email: {e}")

    def _extract_mail_route(self):
        """Extract and report mail delivery route from Received headers."""
        if not hasattr(self, "eml") or not self.eml.received:
            return
        if not _RECEIVED_PARSER_AVAILABLE:
            log.debug("received_parser module not available, skipping mail route")
            return

        try:
            hops = parse_received_headers(self.eml.received)
            if hops:
                route_text = format_mail_route(hops, reverse=True)
                self.reports["mail_route"] = Report(
                    route_text,
                    short=f"{len(hops)} hop(s)",
                    label="mail_route",
                    severity=Severity.INFO,
                    verbosity=1,
                )

                # Check for missing TLS on any hop
                no_tls_hops = [h for h in hops if not h.has_tls and h.from_display != "?"]
                if no_tls_hops:
                    names = ", ".join(h.from_display for h in no_tls_hops[:3])
                    extra = f" (+{len(no_tls_hops) - 3} more)" if len(no_tls_hops) > 3 else ""
                    self.reports["no_tls"] = Report(
                        f"Hops without TLS: {names}{extra}",
                        label="no_tls",
                        severity=Severity.LOW,
                        verbosity=2,
                    )
        except Exception as e:
            log.debug(f"Mail route extraction failed: {e}")

    def _extract_auth_results(self):
        """Parse Authentication-Results headers for SPF/DKIM/DMARC status."""
        if not hasattr(self, "eml"):
            return
        if not _RECEIVED_PARSER_AVAILABLE:
            return

        try:
            auth_headers = list(self.eml.get_header_raw("Authentication-Results"))
            if not auth_headers:
                return

            for i, header in enumerate(auth_headers):
                auth = parse_auth_results(header)
                suffix = f"_{i}" if i > 0 else ""

                parts = []
                for method in ("spf", "dkim", "dmarc"):
                    if method in auth:
                        result = auth[method]
                        detail = auth.get(f"{method}_detail", "")
                        detail_str = f" ({detail})" if detail else ""
                        parts.append(f"{method.upper()}={result}{detail_str}")

                if parts:
                    text = ", ".join(parts)
                    # Determine severity based on results
                    sev = Severity.INFO
                    for method in ("spf", "dkim", "dmarc"):
                        result = auth.get(method, "")
                        if result in ("fail", "softfail"):
                            sev = min(sev, Severity.MEDIUM)
                        elif result == "none":
                            sev = min(sev, Severity.LOW)

                    self.reports[f"auth_results{suffix}"] = Report(
                        text,
                        label="auth",
                        severity=sev,
                        verbosity=0,
                    )

                    # DMARC alignment check
                    if "dkim_domain" in auth and self.eml.froms:
                        from_domain = ""
                        for f in self.eml.froms:
                            if "@" in f:
                                from_domain = f.split("@")[-1].strip(">").lower()
                                break
                        dkim_domain = auth["dkim_domain"].lower()
                        if from_domain and dkim_domain != from_domain:
                            self.reports[f"dmarc_alignment{suffix}"] = Report(
                                f"DKIM domain ({dkim_domain}) != From domain ({from_domain})",
                                label="dmarc_align",
                                severity=Severity.MEDIUM,
                                verbosity=0,
                            )
        except Exception as e:
            log.debug(f"Auth-Results parsing failed: {e}")

    def extract_parts(self):
        if not hasattr(self, "eml"):
            return
        for idx, part in enumerate(x for x in self.eml.flat_struct if x["data"]):
            self.childitems.append(
                self.generate_struct(
                    filename=part["filename"],
                    data=part["data"],
                    mime_type=part["content_type"],
                    index=idx,
                )
            )

    def analysis(self):
        self.modules["emailparser"] = self.parse_mail
        self.modules["extract_parts"] = self.extract_parts
        self.run_modules()
