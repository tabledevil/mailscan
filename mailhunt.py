#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import Message
import hashlib
import json
import os
import re
import sys
from typing import Iterable

from Utils.mailbox_sources import MailRecord, iter_mail_records, safe_filename
from Utils.ioc_extractor import extract_iocs


@dataclass
class Match:
    kind: str
    value: str
    location: str
    detail: str = ""


@dataclass
class MailHit:
    record: MailRecord
    subject: str = ""
    sender: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    matches: list[Match] = field(default_factory=list)


def decode_value(value) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def msg_header(msg: Message, name: str) -> str:
    values = msg.get_all(name, [])
    return " | ".join(decode_value(v) for v in values)


def mail_summary(record: MailRecord, msg: Message) -> MailHit:
    return MailHit(
        record=record,
        subject=msg_header(msg, "Subject"),
        sender=msg_header(msg, "From"),
        to=msg_header(msg, "To"),
        date=msg_header(msg, "Date"),
        message_id=msg_header(msg, "Message-ID"),
    )


def iter_text_parts(msg: Message):
    for idx, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if not content_type.startswith("text/"):
            continue
        try:
            text = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
        yield idx, content_type, text


def iter_attachments(msg: Message):
    for idx, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename is None and disposition != "attachment":
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        yield idx, part, decode_value(filename) if filename else "", data


def all_header_text(msg: Message) -> str:
    lines = []
    for key, value in msg.items():
        lines.append(f"{key}: {decode_value(value)}")
    return "\n".join(lines)


def compile_regex(patterns: list[str], ignore_case: bool):
    flags = re.IGNORECASE if ignore_case else 0
    return [re.compile(pattern, flags) for pattern in patterns]


def contains_bytes(data: bytes, needle: str, ignore_case: bool) -> bool:
    if not needle:
        return False
    raw = needle.encode("utf-8", errors="ignore")
    if ignore_case:
        return raw.lower() in data.lower()
    return raw in data


def match_text(text: str, location: str, literals: list[str], regexes, ignore_case: bool):
    matches = []
    haystack = text.lower() if ignore_case else text
    for literal in literals:
        needle = literal.lower() if ignore_case else literal
        if needle and needle in haystack:
            matches.append(Match("literal", literal, location, snippet(text, literal, ignore_case)))
    for regex in regexes:
        for hit in regex.finditer(text):
            matches.append(Match("regex", hit.group(0), location, snippet_at(text, hit.start(), hit.end())))
    return matches


def snippet(text: str, needle: str, ignore_case: bool, width: int = 80) -> str:
    haystack = text.lower() if ignore_case else text
    target = needle.lower() if ignore_case else needle
    pos = haystack.find(target)
    if pos < 0:
        return ""
    return snippet_at(text, pos, pos + len(needle), width=width)


def snippet_at(text: str, start: int, end: int, width: int = 80) -> str:
    left = max(0, start - width // 2)
    right = min(len(text), end + width // 2)
    return " ".join(text[left:right].split())


def hash_values(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def hunt_record(record: MailRecord, args) -> MailHit | None:
    if record.error:
        if args.show_errors:
            hit = MailHit(record=record)
            hit.matches.append(Match("error", record.error, "source"))
            return hit
        return None

    try:
        msg = record.parse()
    except Exception as exc:
        if not args.show_errors:
            return None
        hit = MailHit(record=record)
        hit.matches.append(Match("error", str(exc), "parse"))
        return hit

    hit = mail_summary(record, msg)
    literals = args.query or []
    regexes = compile_regex(args.regex or [], args.ignore_case)

    if args.ioc:
        literals.extend(args.ioc)

    hit.matches.extend(match_text(all_header_text(msg), "headers", literals, regexes, args.ignore_case))

    for idx, content_type, text in iter_text_parts(msg):
        hit.matches.extend(match_text(text, f"part:{idx}:{content_type}", literals, regexes, args.ignore_case))
        if args.ioc_type:
            iocs = extract_iocs(text)
            values = iocs.to_dict().get(args.ioc_type, [])
            for value in values:
                hit.matches.append(Match("ioc", str(value), f"part:{idx}:{content_type}"))

    for idx, part, filename, data in iter_attachments(msg):
        if filename:
            hit.matches.extend(match_text(filename, f"attachment:{idx}:filename", literals, regexes, args.ignore_case))
        hashes = hash_values(data)
        for algo, digest in hashes.items():
            for literal in literals:
                if literal.lower() == digest.lower():
                    hit.matches.append(Match("hash", digest, f"attachment:{idx}:{algo}", filename))
        if args.search_attachment_bytes:
            for literal in literals:
                if contains_bytes(data, literal, args.ignore_case):
                    hit.matches.append(Match("bytes", literal, f"attachment:{idx}:bytes", filename))

    return hit if hit.matches or args.all else None


def iter_hits(paths: Iterable[str], args):
    for record in iter_mail_records(paths, include_pst_recovered=not args.no_recovered):
        hit = hunt_record(record, args)
        if hit is not None:
            yield hit


def hit_to_dict(hit: MailHit) -> dict:
    record = hit.record
    return {
        "source": record.source,
        "container": record.container,
        "mailbox_path": record.mailbox_path,
        "index": record.index,
        "folder": record.folder,
        "recovered": record.recovered,
        "message_id": hit.message_id,
        "date": hit.date,
        "from": hit.sender,
        "to": hit.to,
        "subject": hit.subject,
        "matches": [match.__dict__ for match in hit.matches],
    }


def output_hits(hits, args) -> int:
    count = 0
    if args.format == "jsonl":
        for hit in hits:
            count += 1
            print(json.dumps(hit_to_dict(hit), ensure_ascii=False))
    elif args.format == "csv":
        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=["source", "container", "index", "folder", "recovered", "date", "from", "to", "subject", "match_count", "matches"],
        )
        writer.writeheader()
        for hit in hits:
            count += 1
            row = hit_to_dict(hit)
            row["match_count"] = len(hit.matches)
            row["matches"] = " | ".join(f"{m.location}:{m.kind}:{m.value}" for m in hit.matches)
            writer.writerow({field: row.get(field, "") for field in writer.fieldnames})
    else:
        for hit in hits:
            count += 1
            print(f"{hit.record.source}")
            meta = []
            if hit.date:
                meta.append(hit.date)
            if hit.sender:
                meta.append(f"from={hit.sender}")
            if hit.subject:
                meta.append(f"subject={hit.subject}")
            if hit.record.recovered:
                meta.append("recovered=true")
            if hit.record.folder:
                meta.append(f"folder={hit.record.folder}")
            if meta:
                print("  " + " | ".join(meta))
            for match in hit.matches[: args.max_matches_per_mail]:
                detail = f" - {match.detail}" if match.detail else ""
                print(f"  [{match.location}] {match.kind}: {match.value}{detail}")
            if len(hit.matches) > args.max_matches_per_mail:
                print(f"  ... {len(hit.matches) - args.max_matches_per_mail} more match(es)")
    return count


def cmd_headers(args) -> int:
    fields = [field.lower() for field in args.field]
    for record in iter_mail_records(args.paths, include_pst_recovered=not args.no_recovered):
        print(record.source)
        if record.error:
            print(f"Error: {record.error}")
            continue
        try:
            msg = record.parse()
        except Exception as exc:
            print(f"Error: {exc}")
            continue
        for key, value in msg.items():
            if fields and key.lower() not in fields:
                continue
            print(f"{key}: {decode_value(value)}")
    return 0


def cmd_timeline(args) -> int:
    rows = []
    for record in iter_mail_records(args.paths, include_pst_recovered=not args.no_recovered):
        if record.error:
            continue
        try:
            msg = record.parse()
        except Exception:
            continue
        for received in msg.get_all("Received", []) or []:
            rows.append((msg_header(msg, "Date"), msg_header(msg, "Message-ID"), " ".join(decode_value(received).split()), record.source))
    rows.sort(key=lambda row: row[0])
    for row in rows:
        print(";".join(str(cell).replace(";", ",") for cell in row))
    return 0


def cmd_attachments(args) -> int:
    os.makedirs(args.out_dir, exist_ok=True) if args.extract else None
    for record in iter_mail_records(args.paths, include_pst_recovered=not args.no_recovered):
        if record.error:
            continue
        try:
            msg = record.parse()
        except Exception:
            continue
        for idx, _part, filename, data in iter_attachments(msg):
            hashes = hash_values(data)
            name = filename or f"attachment-{idx}.bin"
            print(f"{record.source}\t{idx}\t{name}\t{len(data)}\t{hashes['sha256']}")
            if args.extract:
                dirname = safe_filename(record.source.replace(os.sep, "_"))
                path = os.path.join(args.out_dir, dirname)
                os.makedirs(path, exist_ok=True)
                out = os.path.join(path, f"{idx}-{safe_filename(name)}")
                with open(out, "wb") as handle:
                    handle.write(data)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Search and triage EML, mbox, and PST mail collections")
    sub = parser.add_subparsers(dest="command", required=True)

    hunt = sub.add_parser("hunt", help="search headers, bodies, attachment names, hashes, and optionally attachment bytes")
    hunt.add_argument("paths", nargs="+", help="files or directories to scan")
    hunt.add_argument("-q", "--query", action="append", default=[], help="literal string, domain, URL, email, or hash to find")
    hunt.add_argument("-r", "--regex", action="append", default=[], help="regular expression to search")
    hunt.add_argument("--ioc", action="append", default=[], help="literal IOC to search; alias for --query with semantic intent")
    hunt.add_argument("--ioc-type", choices=["ipv4", "ipv6", "urls", "emails", "domains", "md5", "sha1", "sha256", "passwords"], help="emit extracted IOCs of this type from matching text")
    hunt.add_argument("--case-sensitive", dest="ignore_case", action="store_false", default=True)
    hunt.add_argument("--search-attachment-bytes", action="store_true", help="scan raw attachment bytes for literal queries")
    hunt.add_argument("--no-recovered", action="store_true", help="skip PST orphan/recovered items")
    hunt.add_argument("--show-errors", action="store_true", help="include per-message/container parse errors")
    hunt.add_argument("--all", action="store_true", help="return every parsed message, even without matches")
    hunt.add_argument("--format", choices=["text", "jsonl", "csv"], default="text")
    hunt.add_argument("--max-matches-per-mail", type=int, default=10)

    headers = sub.add_parser("headers", help="print decoded headers across files and mailboxes")
    headers.add_argument("paths", nargs="+")
    headers.add_argument("-f", "--field", action="append", default=[])
    headers.add_argument("--no-recovered", action="store_true")

    timeline = sub.add_parser("timeline", help="emit Received-header timeline rows")
    timeline.add_argument("paths", nargs="+")
    timeline.add_argument("--no-recovered", action="store_true")

    attachments = sub.add_parser("attachments", help="list or extract attachments across files and mailboxes")
    attachments.add_argument("paths", nargs="+")
    attachments.add_argument("-x", "--extract", action="store_true")
    attachments.add_argument("-o", "--out-dir", default="extract")
    attachments.add_argument("--no-recovered", action="store_true")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "hunt":
        if not args.query and not args.regex and not args.ioc and not args.ioc_type and not args.all:
            parser.error("hunt requires --query, --regex, --ioc, --ioc-type, or --all")
        return 0 if output_hits(iter_hits(args.paths, args), args) >= 0 else 1
    if args.command == "headers":
        return cmd_headers(args)
    if args.command == "timeline":
        return cmd_timeline(args)
    if args.command == "attachments":
        return cmd_attachments(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
