import logging
import re
from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")


class ICSAnalyzer(Analyzer):
    """Analyzer for iCalendar (.ics) files.

    Parses calendar invites to extract URLs, organizer information,
    and detect phishing patterns commonly delivered via calendar invites.
    """

    compatible_mime_types = [
        "text/calendar",
        "application/ics",
    ]
    description = "ICS Calendar Analyser"
    specificity = 20

    # URL pattern for extracting links from calendar data
    URL_PATTERN = re.compile(
        rb"https?://[^\s\r\n;\"'<>\\]+",
        re.IGNORECASE,
    )

    # Suspicious patterns in calendar invites
    PHISHING_KEYWORDS = [
        rb"(?i)verify\s+your\s+account",
        rb"(?i)click\s+here\s+(?:to|immediately|now|urgently)",
        rb"(?i)urgent\s+(?:action|update|notice|meeting)",
        rb"(?i)password\s+(?:reset|expire|update|change)",
        rb"(?i)suspended\s+account",
        rb"(?i)security\s+alert",
        rb"(?i)unusual\s+(?:sign.in|activity|login)",
        rb"(?i)confirm\s+(?:your\s+)?identity",
    ]

    def analysis(self):
        self.modules["parse_ics"] = self._parse_ics
        self.modules["extract_urls"] = self._extract_urls
        self.modules["detect_phishing"] = self._detect_phishing_patterns
        super().analysis()

    def _parse_ics(self):
        data = self.struct.rawdata

        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")

        # Verify it looks like an ICS file
        if "BEGIN:VCALENDAR" not in text:
            self.reports["format"] = Report(
                "File does not contain BEGIN:VCALENDAR header",
                severity=Severity.LOW,
            )
            return

        events = text.count("BEGIN:VEVENT")
        self.info = f"iCalendar with {events} event(s)"

        # Extract key fields
        fields = {
            "SUMMARY": "Summary",
            "ORGANIZER": "Organizer",
            "DTSTART": "Start time",
            "DTEND": "End time",
            "LOCATION": "Location",
            "DESCRIPTION": "Description",
            "ATTENDEE": "Attendee",
        }

        for field_key, label in fields.items():
            values = self._extract_field(text, field_key)
            if values:
                if field_key == "ATTENDEE":
                    self.reports["attendees"] = Report(
                        f"{len(values)} attendee(s):\n" + "\n".join(values),
                        short=f"{len(values)} attendee(s)",
                        label="Attendees",
                    )
                elif field_key == "DESCRIPTION":
                    desc = values[0]
                    # Unfold ICS line continuations
                    desc = desc.replace("\\n", "\n").replace("\\,", ",")
                    self.reports["description"] = Report(
                        desc,
                        short=desc[:100] + "..." if len(desc) > 100 else desc,
                        label=label,
                    )
                    # Pass description text for IOC extraction
                    self.childitems.append(
                        self.generate_struct(
                            data=desc.encode("utf-8"),
                            filename="calendar_description.txt",
                            mime_type="text/plain",
                        )
                    )
                else:
                    display = values[0] if len(values) == 1 else "\n".join(values)
                    self.reports[field_key.lower()] = Report(
                        display, label=label
                    )

        # Detect METHOD (REQUEST can be used to auto-add events)
        methods = self._extract_field(text, "METHOD")
        if methods:
            method = methods[0]
            self.reports["method"] = Report(method, label="Method")
            if method.upper() == "REQUEST":
                self.reports["auto_add"] = Report(
                    "METHOD:REQUEST — this invite may be automatically added "
                    "to the recipient's calendar by some clients",
                    label="Auto-add risk",
                    severity=Severity.LOW,
                )

        # Check for alarms (VALARM) — can be used for social engineering
        alarms = text.count("BEGIN:VALARM")
        if alarms:
            self.reports["alarms"] = Report(
                f"{alarms} alarm(s) defined",
                label="Alarms",
                severity=Severity.LOW,
            )

    def _extract_field(self, text, field_name):
        """Extract values for a given ICS field, handling line folding."""
        values = []
        # ICS fields can have parameters like ORGANIZER;CN=Name:mailto:...
        pattern = re.compile(
            rf"^{re.escape(field_name)}(?:;[^\r\n:]*)?:(.+?)(?=\r?\n[^\s]|\r?\nEND:|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        for match in pattern.finditer(text):
            value = match.group(1).strip()
            # Unfold continuation lines (lines starting with space/tab)
            value = re.sub(r"\r?\n[ \t]", "", value)
            values.append(value)
        return values

    def _extract_urls(self):
        data = self.struct.rawdata
        urls = list(set(self.URL_PATTERN.findall(data)))

        if not urls:
            return

        decoded_urls = []
        for url in urls:
            try:
                decoded_urls.append(url.decode("utf-8", errors="replace"))
            except Exception:
                decoded_urls.append(url.decode("latin-1"))

        self.reports["urls"] = Report(
            "\n".join(decoded_urls),
            short=f"{len(decoded_urls)} URL(s) found",
            label="URLs in calendar invite",
            severity=Severity.LOW,
        )

        # Flag shortened / suspicious URLs
        suspicious_domains = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "bl.ink",
        ]
        suspicious = [
            u for u in decoded_urls
            if any(d in u.lower() for d in suspicious_domains)
        ]
        if suspicious:
            self.reports["shortened_urls"] = Report(
                "\n".join(suspicious),
                short=f"{len(suspicious)} shortened URL(s)",
                label="Shortened/suspicious URLs",
                severity=Severity.MEDIUM,
            )

    def _detect_phishing_patterns(self):
        data = self.struct.rawdata
        findings = []

        for pattern in self.PHISHING_KEYWORDS:
            if re.search(pattern, data):
                match = re.search(pattern, data)
                findings.append(match.group(0).decode("utf-8", errors="replace"))

        if findings:
            self.reports["phishing_indicators"] = Report(
                "Suspicious phrases detected:\n" + "\n".join(f"- {f}" for f in findings),
                short=f"{len(findings)} phishing indicator(s)",
                label="Phishing indicators",
                severity=Severity.HIGH,
            )
