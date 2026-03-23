import logging
from structure import Analyzer, Report, Severity
from Utils.temp_manager import TempFileManager

try:
    import extract_msg
except ImportError:
    extract_msg = None

try:
    from Utils.received_parser import (
        parse_received_headers,
        format_mail_route,
        build_hop_display_data,
        parse_auth_results,
        check_chain_continuity,
        detect_latency_anomalies,
    )
    _RECEIVED_PARSER_AVAILABLE = True
except ImportError:
    _RECEIVED_PARSER_AVAILABLE = False

class MsgAnalyzer(Analyzer):
    compatible_mime_types = ['application/vnd.ms-outlook']
    description = "MSG Email Analyzer"
    specificity = 20
    optional_pip_dependencies = [('extract_msg', 'extract-msg')]
    extra = "msg"

    def analysis(self):
        super().analysis()
        if not extract_msg:
            logging.warning("extract-msg is not installed, cannot analyze MSG files.")
            return

        with TempFileManager() as temp_manager:
            tmp_file_path = temp_manager.create_temp_file(self.struct.rawdata)
            try:
                with extract_msg.Message(tmp_file_path) as msg:
                    self.info = msg.subject
                    summary_parts = []
                    summary_parts.append(f"From   : {msg.sender}\n")
                    summary_parts.append(f"To     : {msg.to}\n")
                    summary_parts.append(f"Date   : {msg.date}\n")
                    summary_parts.append(f"Subject: {msg.subject}\n")

                    # Extract Message-ID from headers if available
                    msg_id = msg.messageId if hasattr(msg, 'messageId') and msg.messageId else None
                    if msg_id:
                        summary_parts.append(f"Msg-ID : {msg_id}\n")

                    self.reports['summary'] = Report("".join(summary_parts), label='summary')

                    # Extract transport headers for auth/route analysis
                    self._extract_transport_headers(msg)

                    if msg.body:
                        self.childitems.append(self.generate_struct(data=msg.body.encode(), filename='email_body.txt', mime_type='text/plain'))

                    if msg.htmlBody:
                        self.childitems.append(self.generate_struct(data=msg.htmlBody, filename='email_body.html', mime_type='text/html'))

                    for idx, attachment in enumerate(msg.attachments):
                        data = attachment.data
                        filename = attachment.longFilename or attachment.shortFilename
                        self.childitems.append(self.generate_struct(data=data, filename=filename, index=idx))
            except Exception as e:
                logging.error(f"Failed to parse MSG file: {e}")

    def _extract_transport_headers(self, msg):
        """Extract and analyze transport headers from MSG file.

        MSG files store the original RFC822 transport headers in the
        PR_TRANSPORT_MESSAGE_HEADERS MAPI property.
        """
        if not _RECEIVED_PARSER_AVAILABLE:
            return

        # Try to get transport headers from the MSG
        transport_headers = None
        try:
            # extract_msg exposes header property which contains the transport headers
            if hasattr(msg, 'header') and msg.header:
                transport_headers = msg.header
            elif hasattr(msg, 'transportMessageHeaders') and msg.transportMessageHeaders:
                transport_headers = msg.transportMessageHeaders
        except Exception:
            pass

        if not transport_headers:
            return

        import email as email_mod
        try:
            # extract_msg's .header returns an email.message.Message object directly
            if isinstance(transport_headers, email_mod.message.Message):
                header_msg = transport_headers
            elif isinstance(transport_headers, str):
                header_msg = email_mod.message_from_string(transport_headers)
            elif isinstance(transport_headers, bytes):
                header_msg = email_mod.message_from_bytes(transport_headers)
            else:
                return
        except Exception:
            return

        # Extract Received headers for mail route
        received_headers = header_msg.get_all('Received') or []
        if received_headers:
            try:
                hops = parse_received_headers(received_headers)
                if hops:
                    ordered = list(reversed(hops))

                    # Collect gateway findings from transport headers
                    gateway_findings = self._collect_gateway_findings_from_headers(header_msg)

                    # Build enriched hop display data
                    hop_display = build_hop_display_data(hops, gateway_findings=gateway_findings, reverse=True)

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

                    # Origin summary — skip loopback/private IPs
                    origin = None
                    for hop in ordered:
                        if not hop.is_internal and (hop.from_ip or hop.from_ipv6):
                            origin = hop
                            break
                    if origin is None and ordered:
                        origin = ordered[0]
                    if origin:
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

                    # TLS check (skip loopback hops)
                    no_tls_hops = [h for h in hops if not h.has_tls and h.from_display != "?"
                                  and not (h.from_display == h.by_display)]
                    if no_tls_hops:
                        hop_details = [f"{h.from_display} -> {h.by_display}" for h in no_tls_hops[:5]]
                        self.reports["no_tls"] = Report(
                            "Hops without TLS:\n  " + "\n  ".join(hop_details),
                            short=f"{len(no_tls_hops)} hop(s) without TLS",
                            label="no_tls",
                            severity=Severity.LOW,
                            verbosity=2,
                        )

                    # Gateway headers as separate report (fallback for non-hop-aware renderers)
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

                    # Timeline events for MSG
                    route_data = []
                    for hop in hops:
                        hop_td = {"from": hop.from_display, "by": hop.by_display}
                        if hop.timestamp:
                            hop_td["timestamp"] = str(hop.timestamp)
                        route_data.append(hop_td)
                    self.reports["mail_route_data"] = Report(
                        "", label="route", severity=Severity.INFO,
                        verbosity=99, data=route_data,
                    )
            except Exception as e:
                logging.debug(f"MSG mail route extraction failed: {e}")

        # Extract Authentication-Results
        auth_header_values = header_msg.get_all('Authentication-Results') or []
        arc_header_values = header_msg.get_all('ARC-Authentication-Results') or []

        # Parse ARC results
        arc_auth = None
        for ah in arc_header_values:
            try:
                parsed = parse_auth_results(ah)
                if parsed:
                    arc_auth = parsed
            except Exception:
                pass

        if auth_header_values:
            # Process in reverse order (gateway first)
            for i, header_val in enumerate(reversed(auth_header_values)):
                try:
                    auth = parse_auth_results(header_val)
                    suffix = f"_{i}" if i > 0 else ""
                    verbosity = 0 if i == 0 else 1

                    parts = []
                    for method in ("spf", "dkim", "dmarc"):
                        if method in auth:
                            result = auth[method]
                            detail = auth.get(f"{method}_detail", "")
                            detail_str = f" ({detail})" if detail else ""
                            if arc_auth and method in arc_auth and result == "none" and arc_auth[method] == "pass":
                                detail_str += f" [ARC: {method}=pass]"
                            parts.append(f"{method.upper()}={result}{detail_str}")

                    if parts:
                        text = ", ".join(parts)
                        sev = Severity.INFO
                        for method in ("spf", "dkim", "dmarc"):
                            result = auth.get(method, "")
                            if result in ("fail", "softfail"):
                                sev = min(sev, Severity.MEDIUM)
                            elif result == "none":
                                if not (arc_auth and arc_auth.get(method) == "pass"):
                                    sev = min(sev, Severity.LOW)

                        self.reports[f"auth_results{suffix}"] = Report(
                            text,
                            label="auth",
                            severity=sev,
                            verbosity=verbosity,
                        )

                        # DMARC alignment check — only for primary header
                        if i == 0 and "dkim_domain" in auth:
                            from_domain = ""
                            sender = getattr(self, '_msg_sender', '') or ''
                            if "@" in sender:
                                from_domain = sender.split("@")[-1].strip(">").lower()
                            dkim_domain = auth["dkim_domain"].lower()
                            if from_domain and dkim_domain != from_domain:
                                if not (arc_auth and arc_auth.get("dkim") == "pass"):
                                    self.reports[f"dmarc_alignment{suffix}"] = Report(
                                        f"DKIM domain ({dkim_domain}) != From domain ({from_domain})",
                                        label="dmarc_align",
                                        severity=Severity.MEDIUM,
                                        verbosity=0,
                                    )
                except Exception as e:
                    logging.debug(f"MSG auth parsing failed for header {i}: {e}")

    @staticmethod
    def _collect_gateway_findings_from_headers(header_msg) -> list[dict]:
        """Collect gateway findings from parsed transport headers."""
        import re
        findings = []

        ironport = header_msg.get_all('X-IronPort-AV') or []
        if ironport:
            findings.append({
                "type": "ironport",
                "label": "Cisco IronPort/Secure Email gateway — no Received header added",
            })

        forefront = header_msg.get_all('X-Forefront-Antispam-Report') or []
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

        auth_source = header_msg.get_all('X-MS-Exchange-Organization-AuthSource') or []
        if auth_source:
            findings.append({
                "type": "exchange_auth",
                "label": f"Exchange AuthSource: {auth_source[0].strip()}",
            })

        user_agent = header_msg.get_all('User-Agent') or header_msg.get_all('X-Mailer') or []
        if user_agent:
            findings.append({
                "type": "mua",
                "label": f"MUA: {user_agent[0].strip()}",
            })

        orig_ip = header_msg.get_all('X-Originating-IP') or []
        if orig_ip:
            findings.append({
                "type": "originating_ip",
                "label": f"X-Originating-IP: {orig_ip[0].strip()}",
            })

        return findings
