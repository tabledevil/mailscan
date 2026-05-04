"""Email (RFC822) analyzer.

Parses email structure, headers, mail route, and authentication results.
Uses the Eml class for MIME parsing and the new Utils/received_parser module
for hop reconstruction and Auth-Results analysis.
"""

import logging
import re

from structure import Analyzer, Report, Severity
from eml import Eml

log = logging.getLogger("matt")

# Import the new received_parser module
try:
    from Utils.received_parser import (
        parse_received_headers,
        format_mail_route,
        build_hop_display_data,
        parse_auth_results,
        check_chain_continuity,
        detect_latency_anomalies,
        ReceivedParserError,
    )

    _RECEIVED_PARSER_AVAILABLE = True
except ImportError:
    _RECEIVED_PARSER_AVAILABLE = False


class EmailAnalyzer(Analyzer):
    # A1: removed 'application/octet-stream' — use can_handle() instead
    compatible_mime_types = ["message/rfc822"]
    description = "Email analyser"
    specificity = 20
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
        """Content-based probe for ambiguous MIME types only.

        Quoted/forwarded email bodies inside `text/plain` parts trivially
        contain `From:`/`To:`/`Subject:` lines — claiming those would re-run
        the email parser on every nested forward and recurse to depth limit.
        Only probe when the MIME type is genuinely ambiguous (octet-stream)."""
        if struct.mime_type != "application/octet-stream":
            return False
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
            if self.eml.id:
                for mid in self.eml.id:
                    summary.append(f"Msg-ID : {mid}\n")
            self.reports["summary"] = Report("".join(summary), label="summary")

            # Emit date report for timeline
            if self.eml.date:
                date_str = str(self.eml.date)
                self.reports["email_date"] = Report(
                    date_str,
                    label="date",
                    severity=Severity.INFO,
                    verbosity=1,
                    order=2,
                    data={"timestamp": date_str},
                )

            # Reply-To / Return-Path extraction and mismatch detection
            self._check_reply_to_mismatch()
            self._check_return_path_mismatch()
            self._check_message_id_mismatch()
            self._check_undisclosed_recipients()
            self._check_received_spf_softfail()
            self._check_arc_chain()
            self._check_bcc_leakage()

            # B5: Mail route extraction using new module
            self._extract_mail_route()

            # B5: Authentication-Results parsing
            self._extract_auth_results()

        except ImportError as e:
            log.warning(f"Could not parse email due to missing dependency: {e}")
        except Exception as e:
            log.error(f"Error parsing email: {e}")

    _LIST_HEADERS = (
        "List-Id", "List-Post", "List-Unsubscribe", "List-Help",
        "List-Archive", "List-Subscribe", "Mailing-List",
    )

    def _is_mailing_list(self) -> bool:
        """True if this looks like mailing-list traffic. Reply-To /
        Return-Path / Message-ID mismatches are routine and benign for
        list-distributed mail and would otherwise drown out real findings."""
        if not hasattr(self, "eml"):
            return False
        for h in self._LIST_HEADERS:
            if list(self.eml.get_header(h)):
                return True
        # VERP bounce addresses on the Sender header are another tell
        for s in self.eml.get_header("Sender"):
            if s and ("-bounces@" in s.lower() or "-owner@" in s.lower()
                      or "-request@" in s.lower()):
                return True
        return False

    def _check_reply_to_mismatch(self):
        """Flag Reply-To domain mismatch with From (BEC indicator)."""
        if not hasattr(self, "eml"):
            return
        if self._is_mailing_list():
            return  # mailing lists routinely set Reply-To to the list address
        reply_tos = list(self.eml.get_header("Reply-To"))
        if not reply_tos or not self.eml.froms:
            return
        from_domain = ""
        for f in self.eml.froms:
            if "@" in f:
                from_domain = f.split("@")[-1].strip(">").strip().lower()
                break
        if not from_domain:
            return
        for rt in reply_tos:
            if "@" in rt:
                rt_domain = rt.split("@")[-1].strip(">").strip().lower()
                if rt_domain and rt_domain != from_domain:
                    self.reports["reply_to_mismatch"] = Report(
                        f"Reply-To ({rt}) domain differs from From domain ({from_domain})",
                        label="reply_to_mismatch",
                        severity=Severity.HIGH,
                        verbosity=0,
                    )
                    break

    def _check_return_path_mismatch(self):
        """Flag Return-Path domain mismatch with From."""
        if not hasattr(self, "eml"):
            return
        if self._is_mailing_list():
            return  # VERP bounce addresses are normal for list traffic
        return_paths = list(self.eml.get_header("Return-Path"))
        if not return_paths or not self.eml.froms:
            return
        from_domain = ""
        for f in self.eml.froms:
            if "@" in f:
                from_domain = f.split("@")[-1].strip(">").strip().lower()
                break
        if not from_domain:
            return
        for rp in return_paths:
            if "@" in rp:
                rp_domain = rp.split("@")[-1].strip(">").strip().lower()
                if rp_domain and rp_domain != from_domain:
                    self.reports["return_path_mismatch"] = Report(
                        f"Return-Path ({rp}) domain differs from From domain ({from_domain})",
                        label="return_path_mismatch",
                        severity=Severity.MEDIUM,
                        verbosity=0,
                    )
                    break

    def _from_domain(self) -> str:
        """Return the lowercased domain of the first parseable From address."""
        if not hasattr(self, "eml") or not self.eml.froms:
            return ""
        for f in self.eml.froms:
            if "@" in f:
                return f.split("@")[-1].strip(">").strip().lower()
        return ""

    def _check_message_id_mismatch(self):
        """Flag Message-ID right-hand side that doesn't share an organisational
        domain with From. Match if either side is a suffix of the other (covers
        subdomains like mta.corp.example vs corp.example)."""
        if not hasattr(self, "eml"):
            return
        if self._is_mailing_list():
            return  # list-stamped Message-IDs use the list domain, not the poster's
        msg_ids = list(self.eml.get_header("Message-ID"))
        if not msg_ids:
            return
        from_domain = self._from_domain()
        if not from_domain:
            return
        # Message-ID format: <local@domain>
        for mid in msg_ids:
            if "@" not in mid:
                continue
            mid_domain = mid.rsplit("@", 1)[-1].strip("<>").strip().lower()
            if not mid_domain:
                continue
            # Suffix match either direction (subdomain-tolerant)
            if (
                mid_domain == from_domain
                or mid_domain.endswith("." + from_domain)
                or from_domain.endswith("." + mid_domain)
            ):
                return
            self.reports["message_id_mismatch"] = Report(
                f"Message-ID domain ({mid_domain}) differs from From domain "
                f"({from_domain})",
                label="message_id_mismatch",
                severity=Severity.LOW,
                verbosity=0,
            )
            return

    def _check_undisclosed_recipients(self):
        """Flag To/Cc headers using `undisclosed-recipients` — common in mass
        phishing where a single message is BCC-blasted."""
        if not hasattr(self, "eml"):
            return
        for header in ("To", "Cc"):
            for value in self.eml.get_header(header):
                if value and "undisclosed-recipients" in value.lower():
                    self.reports["undisclosed_recipients"] = Report(
                        f"{header} contains 'undisclosed-recipients' — "
                        f"message was BCC-blasted to a hidden recipient list",
                        label="undisclosed_recipients",
                        severity=Severity.MEDIUM,
                        verbosity=0,
                    )
                    return

    def _check_received_spf_softfail(self):
        """Surface ``Received-SPF: softfail`` as its own LOW finding.

        SPF softfail means the sender's published SPF record explicitly
        says "this IP shouldn't be sending for this domain" but the
        record uses the soft-mark (``~all``) rather than hard-fail
        (``-all``). Mail servers typically accept the message but score
        it as suspicious. Currently this gets folded into the generic
        auth-results report; a separate finding makes it scannable."""
        if not hasattr(self, "eml"):
            return
        for raw in self.eml.get_header_raw("Received-SPF"):
            value = (raw or "").strip().lower()
            if not value:
                continue
            verdict = value.split(None, 1)[0]
            if verdict == "softfail":
                self.reports["spf_softfail"] = Report(
                    "Received-SPF: softfail — sender domain's SPF "
                    "record marks this source as 'should fail' "
                    "(``~all``). Mail accepted but flagged as "
                    "suspicious by the receiving server.",
                    short="SPF softfail",
                    label="spf_softfail",
                    severity=Severity.LOW,
                    verbosity=0,
                    order=5,
                )
                return

    def _check_arc_chain(self):
        """Inspect the ARC (Authenticated Received Chain) for depth +
        validation status. ARC is a forwarder-friendly extension to
        DKIM/SPF/DMARC that lets each hop seal the prior chain so the
        eventual recipient can verify the full path even when each hop
        breaks the original signatures.

        Findings:
          INFO  arc_chain — ``N`` ARC hops present (informational)
          MEDIUM arc_validation_failed — ``cv=fail`` anywhere in the
                 ARC-Seal chain (downstream verifier rejected the
                 chain — a real signal of forwarding tampering)
        """
        if not hasattr(self, "eml"):
            return
        seals = list(self.eml.get_header_raw("ARC-Seal"))
        if not seals:
            return

        # Each ARC-Seal carries an ``i=N`` instance counter. The hop
        # count is the highest ``i=`` value across all seals.
        max_i = 0
        cv_fail_seen = False
        for seal in seals:
            text = (seal or "").lower()
            # Match ``i=<digits>`` and ``cv=<word>``.
            m = re.search(r"\bi\s*=\s*(\d+)", text)
            if m:
                max_i = max(max_i, int(m.group(1)))
            cv = re.search(r"\bcv\s*=\s*(\w+)", text)
            if cv and cv.group(1) == "fail":
                cv_fail_seen = True

        depth = max_i if max_i else len(seals)
        self.reports["arc_chain"] = Report(
            f"ARC chain: {depth} hop(s)" + (
                " — ``cv=fail`` present (chain-validation failure)"
                if cv_fail_seen else ""
            ),
            short=f"ARC depth {depth}"
                  + (" cv=fail" if cv_fail_seen else ""),
            label="arc_chain",
            severity=Severity.MEDIUM if cv_fail_seen else Severity.INFO,
            verbosity=1,
            order=6,
            data={"depth": depth, "cv_fail": cv_fail_seen},
        )
        if cv_fail_seen:
            self.reports["arc_validation_failed"] = Report(
                "ARC-Seal chain reports ``cv=fail`` — at least one hop "
                "could not validate the prior chain. Forwarder tampering "
                "or spoofing across the ARC path is the typical cause.",
                short="ARC cv=fail",
                label="arc_validation_failed",
                severity=Severity.MEDIUM,
                verbosity=0,
                order=5,
            )

    def _check_bcc_leakage(self):
        """Flag the BCC-bulk-send shape: To/Cc resolves to
        ``undisclosed-recipients`` AND the Received chain shows multiple
        distinct envelope-To values (Acme.com -> Bob; Acme.com -> Alice;
        ...). This is the signature of mass-bcc'd phishing where the
        sender used the To/Cc as a mask while the actual recipient list
        leaks through ``for <addr>;`` clauses on the way through MTAs."""
        if not hasattr(self, "eml"):
            return

        # Only fire when the visible recipient is masked
        masked = False
        for header in ("To", "Cc"):
            for value in self.eml.get_header(header):
                if value and "undisclosed-recipients" in value.lower():
                    masked = True
                    break
            if masked:
                break
        if not masked:
            return

        # Harvest envelope-To from Received headers — the ``for <addr>;``
        # clause leaks the actual delivery target on each hop.
        envelope_tos: set[str] = set()
        for received in self.eml.get_header_raw("Received"):
            text = received or ""
            for m in re.finditer(
                r"\bfor\s+<?([\w.+\-]+@[\w.\-]+)>?\s*;",
                text,
                re.IGNORECASE,
            ):
                envelope_tos.add(m.group(1).lower())

        if len(envelope_tos) >= 2:
            self.reports["bcc_leakage"] = Report(
                f"BCC bulk-send shape: To/Cc was masked "
                f"(``undisclosed-recipients``) but Received headers leak "
                f"{len(envelope_tos)} distinct envelope-To values: "
                + ", ".join(sorted(envelope_tos)[:5])
                + ("..." if len(envelope_tos) > 5 else ""),
                short=f"BCC bulk-send ({len(envelope_tos)} envelope targets)",
                label="bcc_leakage",
                severity=Severity.MEDIUM,
                verbosity=0,
                order=4,
                data={"envelope_to_count": len(envelope_tos),
                      "envelope_tos": sorted(envelope_tos)},
            )

    def _extract_mail_route(self):
        """Extract and report mail delivery route from Received headers."""
        if not hasattr(self, "eml") or not self.eml.received:
            return
        if not _RECEIVED_PARSER_AVAILABLE:
            log.debug("received_parser module not available, skipping mail route")
            return

        try:
            hops = parse_received_headers(self.eml.received)
            if not hops:
                return

            ordered = list(reversed(hops))  # oldest first

            # Collect gateway findings as structured data for inline placement
            gateway_findings = self._collect_gateway_findings()

            # Build enriched hop display data
            hop_display = build_hop_display_data(hops, gateway_findings=gateway_findings, reverse=True)

            # Compact fallback text for non-hop-aware renderers
            route_text = format_mail_route(hops, reverse=True)

            self.reports["mail_route"] = Report(
                route_text,
                short=f"{len(hops)} hop(s)",
                label="mail_route",
                severity=Severity.INFO,
                verbosity=1,
                content_type="application/x-matt-hops",
                data={"hops": hop_display},
            )

            # Origin summary at v0 — skip loopback/private IPs
            self._report_origin(ordered, hops)

            # First-external-hop callout — boundary between external infra
            # and the receiving org's mail gateway. Uses relay_cache to
            # identify well-known gateways (M365 EOP, Mimecast, Proofpoint…).
            self._report_boundary_hop(hop_display)

            # Emit route data for timeline collection
            route_data = []
            for hop in hops:
                hop_data = {
                    "from": hop.from_display,
                    "by": hop.by_display,
                }
                if hop.timestamp:
                    hop_data["timestamp"] = str(hop.timestamp)
                route_data.append(hop_data)
            self.reports["mail_route_data"] = Report(
                "",
                label="route",
                severity=Severity.INFO,
                verbosity=99,  # hidden from normal display
                data=route_data,
            )

            # Chain continuity check
            breaks = check_chain_continuity(hops, reverse=True)
            if breaks:
                break_lines = [b["description"] for b in breaks]
                self.reports["chain_breaks"] = Report(
                    "\n".join(break_lines),
                    short=f"{len(breaks)} chain break(s)",
                    label="chain_break",
                    severity=Severity.LOW,
                    verbosity=1,
                    data={"breaks": breaks},
                )

            # Latency anomaly detection
            anomalies = detect_latency_anomalies(hops, reverse=True)
            if anomalies:
                anomaly_lines = [a["description"] for a in anomalies]
                worst = min(a["delta_seconds"] for a in anomalies)
                sev = Severity.MEDIUM if worst < -300 else Severity.LOW
                self.reports["latency_anomalies"] = Report(
                    "\n".join(anomaly_lines),
                    short=f"{len(anomalies)} timing anomaly(ies)",
                    label="timing_anomaly",
                    severity=sev,
                    verbosity=1,
                    data={"anomalies": anomalies},
                )

            # Check for missing TLS on any hop (skip internal loopback hops)
            no_tls_hops = [h for h in hops if not h.has_tls and h.from_display != "?"
                          and not (h.from_display == h.by_display)]
            if no_tls_hops:
                hop_details = []
                for h in no_tls_hops[:5]:
                    detail = f"{h.from_display} -> {h.by_display}"
                    if h.is_internal:
                        detail += " (internal)"
                    hop_details.append(detail)
                self.reports["no_tls"] = Report(
                    "Hops without TLS:\n  " + "\n  ".join(hop_details),
                    short=f"{len(no_tls_hops)} hop(s) without TLS",
                    label="no_tls",
                    severity=Severity.LOW,
                    verbosity=2,
                )

            # Gateway headers as a separate report (for non-hop-aware renderers)
            if gateway_findings:
                gw_labels = [g["label"] for g in gateway_findings]
                self.reports["gateway_headers"] = Report(
                    "\n".join(gw_labels),
                    short=f"{len(gateway_findings)} gateway header(s)",
                    label="gateway",
                    severity=Severity.INFO,
                    verbosity=2,
                    data={"findings": gateway_findings},
                )

        except Exception as e:
            log.debug(f"Mail route extraction failed: {e}")

    def _report_origin(self, ordered, hops):
        """Report the origin of the email, skipping loopback/private IPs."""
        # Find first hop with a public (non-internal) IP
        origin = None
        for hop in ordered:
            if not hop.is_internal and (hop.from_ip or hop.from_ipv6):
                origin = hop
                break
        if origin is None and ordered:
            origin = ordered[0]  # fall back to first hop

        if not origin:
            return

        origin_ip = origin.from_ip or origin.from_ipv6 or ""
        origin_name = origin.from_display
        tls_status = "TLS" if all(h.has_tls for h in hops) else "partial TLS" if any(h.has_tls for h in hops) else "no TLS"
        origin_text = f"Origin: {origin_name}"
        if origin_ip and origin_ip != origin_name:
            origin_text += f" ({origin_ip})"
        origin_text += f" via {len(hops)} hop(s), {tls_status}"
        self.reports["mail_origin"] = Report(
            origin_text,
            short=f"Origin: {origin_name}",
            label="origin",
            severity=Severity.INFO,
            verbosity=0,
            order=3,
        )

    def _report_boundary_hop(self, hop_display: list[dict]) -> None:
        """Find the first hop (chronological) whose `by` server is a known
        external mail-receiving gateway, and surface it as a separate finding.

        ``hop_display`` is already chronological (oldest first) when produced
        with ``reverse=True``. Annotations like ``microsoft-365 (EOP)`` or
        ``mimecast`` mark the boundary where the message entered the
        receiving org's perimeter."""
        if not hop_display:
            return

        # Annotations that indicate "this is the receiving org's gateway".
        # 'internal' / 'self-loop' are intra-relay markers, not boundary.
        _ignore = {"internal", "self-loop"}

        for hop in hop_display:
            ann = [a for a in hop.get("annotations", []) if a not in _ignore
                   and not a.startswith("from:")]
            if not ann:
                continue
            by_host = hop.get("by_hostname", "?")
            self.reports["mail_boundary"] = Report(
                f"First external gateway: {by_host} "
                f"({', '.join(ann)}) at hop {hop.get('hop')}",
                short=f"Gateway: {by_host}",
                label="mail_boundary",
                severity=Severity.INFO,
                verbosity=0,
                order=4,
            )
            return

    def _collect_gateway_findings(self) -> list[dict]:
        """Collect gateway header findings as structured data for hop integration."""
        if not hasattr(self, "eml"):
            return []

        findings = []

        # X-IronPort-AV — Cisco Secure Email gateway
        ironport = list(self.eml.get_header_raw("X-IronPort-AV"))
        if ironport:
            findings.append({
                "type": "ironport",
                "label": "Cisco IronPort/Secure Email gateway — no Received header added",
            })

        # X-Forefront-Antispam-Report — Microsoft EOP
        forefront = list(self.eml.get_header_raw("X-Forefront-Antispam-Report"))
        for ff in forefront:
            cip_match = re.search(r"CIP:([^;]+)", ff)
            ctry_match = re.search(r"CTRY:([^;]+)", ff)
            helo_match = re.search(r"H:([^;]+)", ff)
            ptr_match = re.search(r"PTR:([^;]+)", ff)
            scl_match = re.search(r"SCL:([^;]+)", ff)
            parts = []
            data = {}
            if cip_match:
                cip = cip_match.group(1).strip()
                parts.append(f"CIP:{cip}")
                data["cip"] = cip
            if ctry_match:
                parts.append(f"Country:{ctry_match.group(1).strip()}")
            if helo_match:
                parts.append(f"HELO:{helo_match.group(1).strip()}")
            if ptr_match:
                parts.append(f"PTR:{ptr_match.group(1).strip()}")
            if scl_match:
                parts.append(f"SCL:{scl_match.group(1).strip()}")
            if parts:
                findings.append({
                    "type": "forefront",
                    "label": f"EOP/Forefront: {', '.join(parts)}",
                    "data": data,
                })

        # X-MS-Exchange-Organization-AuthSource — internal Exchange
        auth_source = list(self.eml.get_header_raw("X-MS-Exchange-Organization-AuthSource"))
        if auth_source:
            findings.append({
                "type": "exchange_auth",
                "label": f"Exchange AuthSource: {auth_source[0].strip()}",
            })

        # User-Agent / X-Mailer — MUA fingerprint
        user_agent = list(self.eml.get_header_raw("User-Agent")) or list(self.eml.get_header_raw("X-Mailer"))
        if user_agent:
            findings.append({
                "type": "mua",
                "label": f"MUA: {user_agent[0].strip()}",
            })

        # X-Originating-IP
        orig_ip = list(self.eml.get_header_raw("X-Originating-IP"))
        if orig_ip:
            findings.append({
                "type": "originating_ip",
                "label": f"X-Originating-IP: {orig_ip[0].strip()}",
            })

        return findings

    def _extract_auth_results(self):
        """Parse Authentication-Results headers for SPF/DKIM/DMARC status.

        Prefers the outermost gateway header (last in document order) over
        internal relay headers to avoid false positives on forwarded mail.
        Also checks ARC-Authentication-Results as an authoritative override.
        """
        if not hasattr(self, "eml"):
            return
        if not _RECEIVED_PARSER_AVAILABLE:
            return

        try:
            auth_headers = list(self.eml.get_header_raw("Authentication-Results"))
            arc_headers = list(self.eml.get_header_raw("ARC-Authentication-Results"))

            # Parse ARC results first (authoritative for forwarded mail)
            arc_auth = None
            if arc_headers:
                # Use the highest ARC instance (last in list typically has highest i=)
                for ah in arc_headers:
                    parsed = parse_auth_results(ah)
                    if parsed:
                        arc_auth = parsed

            if not auth_headers:
                return

            # Process in reverse order: last header = outermost gateway (most authoritative)
            # Report only the most authoritative (gateway) result at v0
            auth_headers_reversed = list(reversed(auth_headers))

            for i, header in enumerate(auth_headers_reversed):
                auth = parse_auth_results(header)
                suffix = f"_{i}" if i > 0 else ""

                # For non-primary headers, use higher verbosity
                verbosity = 0 if i == 0 else 1

                parts = []
                for method in ("spf", "dkim", "dmarc"):
                    if method in auth:
                        result = auth[method]
                        detail = auth.get(f"{method}_detail", "")
                        detail_str = f" ({detail})" if detail else ""

                        # ARC override: if gateway says dkim=none but ARC says dkim=pass,
                        # note the ARC result
                        if arc_auth and method in arc_auth and result == "none" and arc_auth[method] == "pass":
                            detail_str += f" [ARC: {method}=pass]"

                        parts.append(f"{method.upper()}={result}{detail_str}")

                if parts:
                    text = ", ".join(parts)
                    sev = Severity.INFO
                    for method in ("spf", "dkim", "dmarc"):
                        result = auth.get(method, "")
                        # If ARC shows pass, don't escalate severity for none
                        if result in ("fail", "softfail"):
                            sev = min(sev, Severity.MEDIUM)
                        elif result == "none":
                            if arc_auth and arc_auth.get(method) == "pass":
                                pass  # ARC override — don't escalate
                            else:
                                sev = min(sev, Severity.LOW)

                    self.reports[f"auth_results{suffix}"] = Report(
                        text,
                        label="auth",
                        severity=sev,
                        verbosity=verbosity,
                    )

                    # DMARC alignment check — only for primary (gateway) header
                    if i == 0 and "dkim_domain" in auth and self.eml.froms:
                        from_domain = ""
                        for f in self.eml.froms:
                            if "@" in f:
                                from_domain = f.split("@")[-1].strip(">").lower()
                                break
                        dkim_domain = auth["dkim_domain"].lower()
                        # Skip alignment warning if ARC shows pass
                        if from_domain and dkim_domain != from_domain:
                            if not (arc_auth and arc_auth.get("dkim") == "pass"):
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
