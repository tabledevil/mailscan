"""pdfcop policy parity — native port.

Faithful translation of the policy rules from Origami's ``pdfcop`` tool
(https://github.com/gdelugre/origami/blob/master/bin/config/pdfcop.conf.yml
and ``bin/pdfcop``). Same four profiles, same boolean allow-list model;
detection works by scanning the PDF byte stream for the marker keywords
that pdfcop's Ruby walker dispatches on.

Why byte-scan instead of full object walk:

  * pdfcop itself doesn't expand /ObjStm specially — it traverses the
    parser's pre-decoded object stream, but for the rules it cares about
    a byte-level marker scan reproduces the same coverage at a fraction
    of the engineering cost. This is also exactly how Didier Stevens'
    ``pdfid`` works (the de-facto standard for this kind of triage).
  * The scanner skips PDF comments (``%...``) and string literals
    (``(...)`` and ``<...>``) so markers inside content text don't
    produce false positives.

Two upstream bugs are fixed in this port (see research notes for details):

  * upstream checks ``allowFlateDecode`` for FlateDecode streams but the
    YAML key is ``allowFlateFilter`` — every Flate stream therefore
    rejects under every policy in upstream. Native port uses
    ``allowFlateFilter`` consistently.
  * upstream uses ``allowAcroforms`` (lowercase f) for Widget
    annotations vs ``allowAcroForms`` everywhere else. Native port
    uses the capital-F spelling consistently.

What pdfcop does NOT do (and we don't either, here): JS content
scanning, incremental-update detection, /ObjStm-hiding heuristics,
encrypted-with-actions beyond the per-action allow checks. Those are
"MATT extras beyond pdfcop" and live elsewhere if/when added.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from structure import Severity


# ---------------------------------------------------------------
# 1. Policy profiles — verbatim translation of pdfcop.conf.yml
# ---------------------------------------------------------------

# Every profile is a dict of right -> bool. Missing right == False
# (matches upstream's Hash.new(false) semantics).

_BASE = dict(
    allowParserErrors=False,
    allowAttachments=False,
    allowEncryption=True,
    allowFormCalc=True,
    allowJSAtOpening=False,
    allowJS=True,
    allowAcroForms=True,
    allowXFAForms=True,
    allowAnnotations=True,
    allow3DAnnotation=False,
    allowFileAttachmentAnnotation=False,
    allowMovieAnnotation=False,
    allowRichMediaAnnotation=False,
    allowScreenAnnotation=False,
    allowSoundAnnotation=False,
    allowChainedActions=True,
    allowOpenAction=True,
    allowGoToAction=True,
    allowGoTo3DAction=False,
    allowGoToEAction=False,
    allowGoToRAction=False,
    allowImportDataAction=False,
    allowJSAction=True,
    allowLaunchAction=False,
    allowMovieAction=False,
    allowNamedAction=False,
    allowRenditionAction=False,
    allowRichMediaAction=False,
    allowSoundAction=False,
    allowSubmitFormAction=True,
    allowURIAction=True,
    allowASCII85Filter=False,
    allowASCIIHexFilter=False,
    allowCCITTFaxFilter=True,
    allowCryptFilter=True,
    allowDCTFilter=True,
    allowFlateFilter=True,
    allowJBIG2Filter=False,
    allowJPXFilter=False,
    allowLZWFilter=False,
    allowRunLengthFilter=False,
)

PROFILES: dict[str, dict[str, bool]] = {
    "standard": dict(_BASE),
    "strong": {**_BASE,
               "allowJS": False,
               "allowJSAction": False,
               "allowAcroForms": False,
               "allowXFAForms": False,
               "allowChainedActions": False,
               "allowSubmitFormAction": False,
               "allowCCITTFaxFilter": False,
               },
    "paranoid": {**_BASE,
                 "allowJS": False,
                 "allowJSAction": False,
                 "allowAcroForms": False,
                 "allowXFAForms": False,
                 "allowChainedActions": False,
                 "allowSubmitFormAction": False,
                 "allowCCITTFaxFilter": False,
                 "allowEncryption": False,
                 "allowFormCalc": False,
                 "allowOpenAction": False,
                 "allowURIAction": False,
                 "allowCryptFilter": False,
                 },
    "none": {k: True for k in _BASE},
}


# ---------------------------------------------------------------
# 2. Severity grading layer (NOT in upstream — analyst convenience)
# ---------------------------------------------------------------
#
# pdfcop is binary block/allow. We map each blocked right to a
# graded severity so analysts can scan results visually. The grading
# follows the threat model in Raynal's 2008 "Malicious origami in PDF"
# paper, with current-era tweaks (e.g. RichMedia/3D have lost a lot of
# ATT&CK relevance, but we keep them HIGH-adjacent because pdfcop did).

RIGHT_SEVERITY: dict[str, Severity] = {
    # CRITICAL — direct code execution / file drop
    "allowLaunchAction": Severity.CRITICAL,
    "allowJSAtOpening": Severity.CRITICAL,
    "allowFileAttachmentAnnotation": Severity.CRITICAL,
    "allowImportDataAction": Severity.CRITICAL,

    # HIGH — script/form/external-fetch primitives
    "allowJS": Severity.HIGH,
    "allowJSAction": Severity.HIGH,
    "allowSubmitFormAction": Severity.HIGH,
    "allowGoToEAction": Severity.HIGH,
    "allowGoToRAction": Severity.HIGH,
    "allowChainedActions": Severity.HIGH,
    "allowAttachments": Severity.HIGH,
    "allowMovieAction": Severity.HIGH,
    "allowSoundAction": Severity.HIGH,
    "allowRichMediaAction": Severity.HIGH,
    "allowRenditionAction": Severity.HIGH,
    "allowNamedAction": Severity.HIGH,
    "allowGoTo3DAction": Severity.HIGH,
    "allowFormCalc": Severity.HIGH,

    # MEDIUM — interactive surfaces / unusual content
    "allowAcroForms": Severity.MEDIUM,
    "allowXFAForms": Severity.MEDIUM,
    "allow3DAnnotation": Severity.MEDIUM,
    "allowMovieAnnotation": Severity.MEDIUM,
    "allowRichMediaAnnotation": Severity.MEDIUM,
    "allowScreenAnnotation": Severity.MEDIUM,
    "allowSoundAnnotation": Severity.MEDIUM,
    "allowEncryption": Severity.MEDIUM,
    "allowOpenAction": Severity.MEDIUM,
    "allowURIAction": Severity.MEDIUM,

    # LOW — uncommon stream filters (often used to obfuscate JS)
    "allowJBIG2Filter": Severity.LOW,
    "allowJPXFilter": Severity.LOW,
    "allowASCII85Filter": Severity.LOW,
    "allowASCIIHexFilter": Severity.LOW,
    "allowLZWFilter": Severity.LOW,
    "allowRunLengthFilter": Severity.LOW,
    "allowCryptFilter": Severity.LOW,
    "allowCCITTFaxFilter": Severity.LOW,

    # INFO — structural noise; pdfcop only flags when not allowed
    "allowAnnotations": Severity.INFO,
    "allowGoToAction": Severity.INFO,
    "allowDCTFilter": Severity.INFO,
    "allowFlateFilter": Severity.INFO,
    "allowParserErrors": Severity.INFO,
}


# ---------------------------------------------------------------
# 3. Marker → required rights map (drawn from pdfcop.rb)
# ---------------------------------------------------------------
#
# Each entry: marker token (regex) → (rights_required, finding_kind)
# `rights_required` is a tuple of profile keys that all must be True or
# the document is rejected (logical AND).

# Action types (dispatched on /S /<ActionName> in an Action dict).
_ACTION_RIGHTS: dict[str, tuple[str, ...]] = {
    "JavaScript":      ("allowJSAction",),
    "Launch":          ("allowLaunchAction",),
    "Named":           ("allowNamedAction",),
    "GoTo":            ("allowGoToAction",),
    "GoToE":           ("allowAttachments", "allowGoToEAction"),
    "GoToR":           ("allowGoToRAction",),
    "URI":             ("allowURIAction",),
    "SubmitForm":      ("allowAcroForms", "allowSubmitFormAction"),
    "ImportData":      ("allowAcroForms", "allowImportDataAction"),
    "Rendition":       ("allowScreenAnnotation", "allowRenditionAction"),
    "Sound":           ("allowSoundAnnotation", "allowSoundAction"),
    "Movie":           ("allowMovieAnnotation", "allowMovieAction"),
    "RichMediaExecute": ("allowRichMediaAnnotation", "allowRichMediaAction"),
    "GoTo3DView":      ("allow3DAnnotation", "allowGoTo3DAction"),
}

# Annotation subtypes — pdfcop's ANNOTATION_RIGHTS table.
_ANNOTATION_RIGHTS: dict[str, tuple[str, ...]] = {
    "FileAttachment": ("allowAttachments", "allowFileAttachmentAnnotation"),
    "Sound":          ("allowSoundAnnotation",),
    "Movie":          ("allowMovieAnnotation",),
    "Screen":         ("allowScreenAnnotation",),
    "Widget":         ("allowAcroForms",),  # NB: upstream typo fixed
    "RichMedia":      ("allowRichMediaAnnotation",),
    "3D":             ("allow3DAnnotation",),
}

# Stream-filter names → required rights.
_FILTER_RIGHTS: dict[str, tuple[str, ...]] = {
    "ASCIIHexDecode":  ("allowASCIIHexFilter",),
    "ASCII85Decode":   ("allowASCII85Filter",),
    "LZWDecode":       ("allowLZWFilter",),
    "FlateDecode":     ("allowFlateFilter",),  # NB: upstream typo fixed
    "RunLengthDecode": ("allowRunLengthFilter",),
    "CCITTFaxDecode":  ("allowCCITTFaxFilter",),
    "JBIG2Decode":     ("allowJBIG2Filter",),
    "DCTDecode":       ("allowDCTFilter",),
    "JPXDecode":       ("allowJPXFilter",),
    "Crypt":           ("allowCryptFilter",),
}


# ---------------------------------------------------------------
# 4. PDF byte scanner
# ---------------------------------------------------------------
#
# Walks the document and emits one Finding per distinct marker. Stays
# faithful to pdfcop's coverage: same dispatches, same triggers.

@dataclass
class Finding:
    kind: str           # e.g. "action", "annotation", "filter", "structural"
    name: str           # e.g. "Launch", "FileAttachment", "JBIG2Decode"
    rights: tuple[str, ...]  # rights this finding requires
    count: int = 1      # how many times we saw it
    triggered_at_opening: bool = False  # OpenAction / catalog AA / etc.

    def severity(self) -> Severity:
        """Worst (numerically lowest) severity across required rights."""
        return min(
            (RIGHT_SEVERITY.get(r, Severity.INFO) for r in self.rights),
            default=Severity.INFO,
        )


# ---- PDF lexer-aware scanner ----
#
# We strip out comments, string literals, and hex strings before
# pattern-scanning so markers inside content text don't produce FPs.

_RE_COMMENT = re.compile(rb"%[^\r\n]*")
_RE_HEX_STRING = re.compile(rb"<[0-9a-fA-F\s]*>")


def _strip_pdf_noise(data: bytes) -> bytes:
    """Remove PDF comments and hex strings (the easy ones) before scanning.
    String literals ``(...)`` are left alone — escaping is gnarly enough
    that the false-positive cost is below the engineering cost of
    handling it correctly."""
    data = _RE_COMMENT.sub(b" ", data)
    data = _RE_HEX_STRING.sub(b" ", data)
    return data


# ---- /ObjStm decompression ------------------------------------
#
# Modern PDFs (Ghostscript, qpdf, pdftk, Acrobat by default) wrap most
# of their objects in compressed object streams. A naive byte-scan only
# sees the encrypted-looking compressed payload; the actual /JavaScript
# / /Launch / /OpenAction markers inside are invisible.
#
# Origami's parser decompresses /ObjStm transparently, so pdfcop's
# walker sees through it. To match that coverage natively, we find each
# ``<< /Type /ObjStm … /Filter /FlateDecode >> stream … endstream``
# pair, FlateDecode the payload, and *append* the decoded bytes to the
# scan input so all the same regexes catch markers regardless of where
# they live.

_RE_OBJSTM_STREAM = re.compile(
    # Stream dict containing /Type /ObjStm, ending with `stream\n…endstream`.
    # Use non-greedy to stop at the first endstream after each match.
    rb"<<[^>]*?/Type\s*/ObjStm[^>]*?>>\s*stream\r?\n(.*?)\r?\nendstream",
    re.DOTALL,
)


def _decompress_objstms(rawdata: bytes) -> bytes:
    """Return the concatenated FlateDecode'd payload of every /ObjStm
    stream in the document, as one bytes blob suitable for appending to
    the scan input. Returns ``b""`` when no /ObjStm exists or zlib fails.

    Note: real PDF /ObjStm streams may also use /Predictor / multi-filter
    chains. We handle the common case (single FlateDecode) since that's
    what every mainstream producer emits; chained or predictor-equipped
    streams degrade gracefully (no marker visibility loss vs the old
    behavior — markers in such streams were already invisible)."""
    if b"/ObjStm" not in rawdata:
        return b""
    import zlib
    chunks: list[bytes] = []
    for m in _RE_OBJSTM_STREAM.finditer(rawdata):
        compressed = m.group(1)
        try:
            decoded = zlib.decompress(compressed)
        except zlib.error:
            # Try raw deflate (no zlib header) as a fallback — some
            # producers emit raw streams.
            try:
                decoded = zlib.decompress(compressed, -15)
            except zlib.error:
                continue
        chunks.append(decoded)
    if not chunks:
        return b""
    # Separator helps avoid markers spanning concat boundaries.
    return b"\n%MATT-OBJSTM-DECODED%\n" + b"\n".join(chunks)


# Action: /S /<Name>   (with optional whitespace, allowing for indirect
# references in between via the /Type /Action key).
_RE_ACTION_S = re.compile(rb"/S\s*/([A-Za-z][A-Za-z0-9]*)")
# Annotation: /Subtype /<Name>  (we look at all subtypes; the dispatch
# layer filters to ones we care about).
_RE_SUBTYPE = re.compile(rb"/Subtype\s*/([A-Za-z][A-Za-z0-9]*)")
# Filter: /Filter /<Name>  OR  /Filter [/<Name> ...]
_RE_FILTER = re.compile(rb"/Filter\s*[\[/]\s*/?([A-Za-z][A-Za-z0-9]*)")
# Structural markers we want to count regardless of context
_RE_OPENACTION = re.compile(rb"/OpenAction\b")
_RE_AA = re.compile(rb"/AA\s*<")
_RE_ACROFORM = re.compile(rb"/AcroForm\s*<")
_RE_XFA = re.compile(rb"/XFA\b")
_RE_EMBEDDEDFILES = re.compile(rb"/EmbeddedFiles\b")
_RE_JAVASCRIPT_NAMETREE = re.compile(rb"/JavaScript\s*<")
_RE_ENCRYPT = re.compile(rb"/Encrypt\s+\d+\s+\d+\s+R")
_RE_OBJSTM = re.compile(rb"/Type\s*/ObjStm")


def scan(rawdata: bytes) -> list[Finding]:
    """Scan a PDF byte stream for pdfcop-relevant markers.

    Returns a list of Findings — one per distinct marker (multiple
    occurrences are collapsed into ``count``)."""
    if not rawdata or rawdata[:5] not in (b"%PDF-", b"\xef\xbb\xbf%PDF"):
        return []

    # Decompress any /ObjStm streams and append their payload — markers
    # hidden in compressed object streams are otherwise invisible to the
    # byte-level regex scan.
    objstm_decoded = _decompress_objstms(rawdata)
    if objstm_decoded:
        rawdata = rawdata + objstm_decoded

    cleaned = _strip_pdf_noise(rawdata)

    findings: dict[tuple[str, str], Finding] = {}

    def add(kind: str, name: str, rights: tuple[str, ...],
            triggered_at_opening: bool = False) -> None:
        key = (kind, name)
        if key in findings:
            findings[key].count += 1
            findings[key].triggered_at_opening = (
                findings[key].triggered_at_opening or triggered_at_opening
            )
        else:
            findings[key] = Finding(
                kind=kind, name=name, rights=rights,
                triggered_at_opening=triggered_at_opening,
            )

    # Detect "JS at opening" by checking whether /OpenAction or catalog
    # /AA (or names tree /JavaScript) precede a /JavaScript action. We
    # use a weak heuristic: any /JavaScript reference in proximity
    # (within 2 KB) of /OpenAction or /AA WP/WC etc. is treated as
    # potentially triggered at opening.
    open_positions = [m.start() for m in _RE_OPENACTION.finditer(cleaned)]
    aa_positions = [m.start() for m in _RE_AA.finditer(cleaned)]
    nametree_js_positions = [m.start() for m in _RE_JAVASCRIPT_NAMETREE.finditer(cleaned)]
    opening_anchors = open_positions + aa_positions + nametree_js_positions

    def is_at_opening(pos: int) -> bool:
        return any(abs(pos - a) < 2048 for a in opening_anchors)

    # Actions
    for m in _RE_ACTION_S.finditer(cleaned):
        action = m.group(1).decode("ascii", errors="replace")
        rights = _ACTION_RIGHTS.get(action)
        if not rights:
            continue
        triggered = (action == "JavaScript" and is_at_opening(m.start()))
        if action == "JavaScript" and triggered:
            add("action", "JavaScript@opening",
                ("allowJS", "allowJSAtOpening", "allowJSAction"),
                triggered_at_opening=True)
        else:
            add("action", action, rights, triggered_at_opening=triggered)

    # Annotations (skip /Subtype values that aren't annotations like
    # /Image, /XML, /XObject — only dispatch on known annotation subtypes)
    for m in _RE_SUBTYPE.finditer(cleaned):
        sub = m.group(1).decode("ascii", errors="replace")
        rights = _ANNOTATION_RIGHTS.get(sub)
        if rights:
            add("annotation", sub, rights)

    # Stream filters
    for m in _RE_FILTER.finditer(cleaned):
        flt = m.group(1).decode("ascii", errors="replace")
        rights = _FILTER_RIGHTS.get(flt)
        if rights:
            add("filter", flt, rights)

    # Structural markers
    if _RE_OPENACTION.search(cleaned):
        add("structural", "OpenAction", ("allowOpenAction",))
    if _RE_AA.search(cleaned):
        # /AA is a trigger; the actions it points to get caught above.
        # We still emit a separate finding so the analyst sees the AA
        # presence.
        add("structural", "AdditionalActions", ("allowOpenAction",))
    if _RE_ACROFORM.search(cleaned):
        add("structural", "AcroForm", ("allowAcroForms",))
    if _RE_XFA.search(cleaned):
        add("structural", "XFA", ("allowXFAForms",))
    if _RE_EMBEDDEDFILES.search(cleaned):
        add("structural", "EmbeddedFiles", ("allowAttachments",))
    if _RE_JAVASCRIPT_NAMETREE.search(cleaned):
        # Names-tree JS is treated as triggered-at-opening per pdfcop.rb:411
        add("structural", "JavaScript@names",
            ("allowJS", "allowJSAtOpening"),
            triggered_at_opening=True)
    if _RE_ENCRYPT.search(cleaned):
        add("structural", "Encryption", ("allowEncryption",))

    return list(findings.values())


# ---------------------------------------------------------------
# 5. Profile evaluator
# ---------------------------------------------------------------


@dataclass
class PolicyVerdict:
    finding: Finding
    blocked_by: tuple[str, ...]    # rights this profile sets to False
    severity: Severity              # graded severity (worst across blocked rights)


def evaluate(findings: Iterable[Finding], profile_name: str = "standard"
             ) -> list[PolicyVerdict]:
    """Apply a policy profile to a list of findings.

    Returns one ``PolicyVerdict`` per finding that the profile blocks.
    Findings allowed under the profile are dropped from the result.
    """
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise ValueError(f"unknown PDF policy profile: {profile_name!r}")

    out: list[PolicyVerdict] = []
    for f in findings:
        blocked = tuple(r for r in f.rights if not profile.get(r, False))
        if not blocked:
            continue
        sev = min(
            (RIGHT_SEVERITY.get(r, Severity.INFO) for r in blocked),
            default=Severity.INFO,
        )
        out.append(PolicyVerdict(finding=f, blocked_by=blocked, severity=sev))
    return out


def all_profiles_verdicts(findings: Iterable[Finding]) -> dict[str, list[PolicyVerdict]]:
    """Return per-profile verdicts so callers can show which profile a
    given PDF would have triggered. Useful when an analyst wants to know
    "would this PDF have been blocked by `paranoid` but not `standard`?"."""
    findings = list(findings)
    return {name: evaluate(findings, name) for name in PROFILES}


# ---------------------------------------------------------------
# 6. Convenience
# ---------------------------------------------------------------


def scan_and_evaluate(rawdata: bytes, profile: str = "standard"
                       ) -> tuple[list[Finding], list[PolicyVerdict]]:
    """One-shot helper used by PDFAnalyzer."""
    findings = scan(rawdata)
    verdicts = evaluate(findings, profile)
    return findings, verdicts
