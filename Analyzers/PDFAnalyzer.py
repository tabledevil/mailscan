import logging
import io
import textwrap
import base64
import importlib
import importlib.util
import shutil
from structure import Analyzer, Report, Severity, AnalysisModuleException

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    from Utils import pdf_policy as _pdf_policy
    _PDF_POLICY_AVAILABLE = True
except ImportError:
    _PDF_POLICY_AVAILABLE = False


# Per-stream decompression budget for embedded PDF resources. Audit
# finding (codex_security_1, codex_security_2; HIGH): /JS, /EF,
# /XObject Image, and /FontFile* streams were materialized via
# ``get_data()`` without per-stream caps, so a small PDF carrying
# heavily-compressed resources could inflate to GBs of heap before
# the generic max_file_size ceiling kicked in.
_PDF_STREAM_MAX_BYTES = 32 * 1024 * 1024  # 32 MB per individual stream
_PDF_STREAM_MAX_CUMULATIVE = 256 * 1024 * 1024  # 256 MB across all extracts


def _bounded_get_data(stream, max_bytes: int = _PDF_STREAM_MAX_BYTES) -> bytes | None:
    """``stream.get_data()`` with a hard size ceiling.

    PyPDF2's StreamObject lazily decompresses on get_data(); we have
    no streaming API to peek the decoded length without paying for
    the full inflate. Compromise: ask for the data, then refuse if
    it's over budget. Memory still spikes briefly but caller can
    discard. Better than holding the bytes forever as a child
    Structure that recurses into the analysis tree."""
    try:
        data = stream.get_data()
    except Exception as e:
        logging.debug("PDF stream decompress failed: %s", e)
        return None
    if data is None:
        return None
    if len(data) > max_bytes:
        logging.debug(
            "PDF stream %d bytes exceeds budget %d — skipping",
            len(data), max_bytes,
        )
        return None
    return bytes(data)



class PDFAnalyzer(Analyzer):
    compatible_mime_types = ['application/pdf']
    description = 'PDF Analyser'
    specificity = 20
    optional_pip_dependencies = ['PyPDF2', 'pdf2image']
    optional_system_dependencies = ['pdftoppm']
    extra = "pdf"

    def parse_pdf(self):
        if not PyPDF2:
            raise AnalysisModuleException("PyPDF2 is not installed.")

        fileobj = io.BytesIO(self.struct.rawdata)
        try:
            self.pdfobj = PyPDF2.PdfReader(fileobj)
            self.page_count = len(self.pdfobj.pages)
            self.reports['pagecount'] = Report(f'{self.page_count}', label="Pages")

            info = self.pdfobj.metadata
            if info:
                if info.title:
                    self.reports['title'] = Report(f'{info.title}', label="title")
                if info.subject:
                    self.reports['subject'] = Report(f'{info.subject}', label="subject")
                if info.creator:
                    self.reports['creator'] = Report(f'{info.creator}', label="creator")
                if info.author:
                    self.reports['author'] = Report(f'{info.author}', label="Author")
                if info.producer:
                    self.reports['producer'] = Report(f'{info.producer}', label="producer")
        except PyPDF2.errors.PdfReadError as e:
            raise AnalysisModuleException(f"Error reading PDF file: {e}")


    def get_text(self):
        if hasattr(self,"pdfobj"):
            text = ""
            for page in range(self.page_count):
                try:
                    page_object = self.pdfobj.pages[page]
                    text += page_object.extract_text()
                except Exception as e:
                    logging.warning(f"Could not extract text from page {page}: {e}")
            if len(text) > 0:
                self.childitems.append(self.generate_struct(data=text.encode(), mime_type="text/plain"))
                self.reports['text'] = Report(text, short=textwrap.shorten(text, width=100))

    def extract_js(self):
        """Walk PDF objects and emit each /JS payload as a text/javascript
        child Structure so ScriptAnalyzer's full obfuscation/threat-detection
        pipeline runs on it.

        Covers two shapes:
          * Action dicts: ``<< /S /JavaScript /JS (...) >>`` and
            ``<< /S /JavaScript /JS <stream-ref> >>``.
          * Names tree: ``/Names /JavaScript /Names [<name> <action> …]``.
        Walks the trailer and every indirect object — the full PDF object
        graph PyPDF2 already enumerates."""
        if not hasattr(self, "pdfobj"):
            return

        try:
            from PyPDF2.generic import (
                IndirectObject, DictionaryObject, ArrayObject,
                StreamObject, TextStringObject, ByteStringObject,
            )
        except ImportError:
            return

        seen_objects: set[int] = set()
        seen_payloads: set[str] = set()
        emitted = 0

        def coerce_js(value) -> bytes | None:
            """Return the JS source bytes from a /JS value, or None.
            Stream payloads bounded at _PDF_STREAM_MAX_BYTES (security
            #3 — unbounded get_data() was a memory-exhaustion vector)."""
            try:
                if isinstance(value, IndirectObject):
                    value = value.get_object()
                if isinstance(value, StreamObject):
                    return _bounded_get_data(value)
                if isinstance(value, (TextStringObject, ByteStringObject, str, bytes)):
                    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
                    if len(raw) > _PDF_STREAM_MAX_BYTES:
                        logging.debug(
                            "PDF /JS string %d bytes exceeds budget — skipping",
                            len(raw),
                        )
                        return None
                    return raw
            except Exception as e:
                logging.debug("coerce_js failed: %s", e)
            return None

        def emit(js_bytes: bytes, source: str) -> None:
            nonlocal emitted
            if not js_bytes:
                return
            # Dedup by content — names-tree often references the same JS
            # object multiple times.
            digest = hash(bytes(js_bytes[:512]))
            key = f"{digest}:{len(js_bytes)}"
            if key in seen_payloads:
                return
            seen_payloads.add(key)
            emitted += 1
            try:
                self.childitems.append(
                    self.generate_struct(
                        data=bytes(js_bytes),
                        filename=f"pdf_js_{emitted}_{source}.js",
                        mime_type="application/javascript",
                    )
                )
            except Exception as e:
                logging.debug("emit JS child failed: %s", e)

        def visit(obj, source: str = "obj") -> None:
            if obj is None:
                return
            if isinstance(obj, IndirectObject):
                if obj.idnum in seen_objects:
                    return
                seen_objects.add(obj.idnum)
                try:
                    obj = obj.get_object()
                except Exception:
                    return
            if isinstance(obj, DictionaryObject):
                # Action: /S /JavaScript /JS <value>
                try:
                    if obj.get("/S") == "/JavaScript" and "/JS" in obj:
                        js = coerce_js(obj["/JS"])
                        if js is not None:
                            emit(js, "action")
                except Exception:
                    pass
                # Generic /JS key (some malformed PDFs put JS without /S)
                try:
                    if "/JS" in obj and obj.get("/S") in (None, "/JavaScript"):
                        js = coerce_js(obj["/JS"])
                        if js is not None:
                            emit(js, "JS")
                except Exception:
                    pass
                # Recurse into all values
                for v in list(obj.values()):
                    visit(v, source)
            elif isinstance(obj, ArrayObject):
                for v in obj:
                    visit(v, source)
            # Other primitive types — nothing to recurse into

        try:
            # Start from the trailer and the root catalog
            visit(self.pdfobj.trailer)
        except Exception as e:
            logging.debug("PDF JS walk failed: %s", e)

        if emitted:
            self.reports["embedded_js"] = Report(
                f"Extracted {emitted} embedded JavaScript payload(s) "
                f"for ScriptAnalyzer inspection",
                short=f"{emitted} JS payload(s)",
                label="embedded_js",
                severity=Severity.HIGH,
                verbosity=0,
                order=24,
                data={"count": emitted},
            )

    @staticmethod
    def _walk_name_tree(node, _seen=None):
        """Yield ``(name, value)`` pairs from a PDF name tree, descending
        through hierarchical ``/Kids`` nodes. Handles the three valid
        shapes:

          * leaf with ``/Names`` (flat array of [name, value, name, value …])
          * branch with ``/Kids`` (array of refs to sub-trees)
          * combined (some real-world PDFs put both)
        """
        if _seen is None:
            _seen = set()
        try:
            from PyPDF2.generic import IndirectObject
            if isinstance(node, IndirectObject):
                if node.idnum in _seen:
                    return
                _seen.add(node.idnum)
                node = node.get_object()
            if not hasattr(node, "get"):
                return
            names = node.get("/Names")
            if names:
                for i in range(0, len(names) - 1, 2):
                    yield names[i], names[i + 1]
            kids = node.get("/Kids")
            if kids:
                for kid in kids:
                    yield from PDFAnalyzer._walk_name_tree(kid, _seen)
        except Exception as e:
            logging.debug("name-tree walk failed: %s", e)

    @staticmethod
    def _filespec_payload(fs_dict):
        """Extract the payload bytes from a /Filespec dict's /EF stream.
        Returns ``(name, bytes)`` or ``None``."""
        try:
            from PyPDF2.generic import IndirectObject
            if isinstance(fs_dict, IndirectObject):
                fs_dict = fs_dict.get_object()
            ef = fs_dict.get("/EF") if hasattr(fs_dict, "get") else None
            if not ef:
                return None
            # /F is the canonical key; /UF (unicode) and /DOS / /Mac / /Unix
            # are platform-specific siblings — try them in order.
            for key in ("/F", "/UF", "/DOS", "/Mac", "/Unix"):
                stream = ef.get(key) if hasattr(ef, "get") else None
                if stream is None:
                    continue
                if isinstance(stream, IndirectObject):
                    stream = stream.get_object()
                if hasattr(stream, "get_data"):
                    name = (fs_dict.get("/F") or fs_dict.get("/UF")
                            or "embedded.bin")
                    payload = _bounded_get_data(stream)
                    if payload is None:
                        return None
                    return str(name), payload
        except Exception as e:
            logging.debug("filespec payload extract failed: %s", e)
        return None

    def getAttachments(self):
        """Recursively harvest every embedded file from a PDF.

        Covers four embedding paths:
          1. ``/Catalog/Names/EmbeddedFiles`` (flat OR hierarchical name tree)
          2. ``/Catalog/AF`` (Associated Files — PDF/A-3, PDF/UA)
          3. ``/Page/Annots`` with ``/Subtype /FileAttachment`` and ``/FS``
          4. ``/Catalog/AF`` per-page (some PDFs duplicate associated
             files at page granularity)
        """
        if not hasattr(self, 'pdfobj'):
            return

        seen_payload_keys: set[tuple] = set()
        attachments: list[tuple[str, bytes, str]] = []  # (name, data, source)

        def emit(name: str, data: bytes, source: str) -> None:
            if not data:
                return
            key = (len(data), data[:64])
            if key in seen_payload_keys:
                return
            seen_payload_keys.add(key)
            attachments.append((name, data, source))

        try:
            from PyPDF2.generic import IndirectObject as _Ind
            catalog = self.pdfobj.trailer["/Root"]
            if isinstance(catalog, _Ind):
                catalog = catalog.get_object()

            def _resolve(o):
                while isinstance(o, _Ind):
                    o = o.get_object()
                return o

            # 1. Names tree — full recursive walk (handles flat + Kids)
            try:
                names_dict = _resolve(catalog.get("/Names"))
                if names_dict is not None:
                    ef_tree = _resolve(names_dict.get("/EmbeddedFiles"))
                    if ef_tree is not None:
                        for name, value in self._walk_name_tree(ef_tree):
                            payload = self._filespec_payload(value)
                            if payload:
                                emit(str(name) or payload[0],
                                     payload[1], "names_tree")
            except Exception as e:
                logging.debug("names-tree harvest failed: %s", e)

            # 2. Catalog-level /AF (Associated Files)
            try:
                af = _resolve(catalog.get("/AF"))
                if af:
                    af_list = af if hasattr(af, "__iter__") else [af]
                    for fs in af_list:
                        payload = self._filespec_payload(fs)
                        if payload:
                            emit(payload[0], payload[1], "AF")
            except Exception as e:
                logging.debug("/AF harvest failed: %s", e)

            # 3. /Subtype /FileAttachment annotations across all pages
            try:
                from PyPDF2.generic import IndirectObject
                for page in self.pdfobj.pages:
                    annots = page.get("/Annots") or []
                    if isinstance(annots, IndirectObject):
                        annots = annots.get_object()
                    for annot in annots:
                        if isinstance(annot, IndirectObject):
                            annot = annot.get_object()
                        if (annot.get("/Subtype") == "/FileAttachment"
                                and annot.get("/FS")):
                            payload = self._filespec_payload(annot["/FS"])
                            if payload:
                                emit(payload[0], payload[1],
                                     "fileattachment_annot")
                        # Per-page /AF
                        page_af = page.get("/AF")
                        if page_af:
                            page_af_list = (page_af if hasattr(page_af, "__iter__")
                                            else [page_af])
                            for fs in page_af_list:
                                p = self._filespec_payload(fs)
                                if p:
                                    emit(p[0], p[1], "page_AF")
            except Exception as e:
                logging.debug("FileAttachment annotation walk failed: %s", e)

            # Emit Structures
            self.embedded_files = {n: d for n, d, _ in attachments}
            for name, data, source in attachments:
                self.childitems.append(
                    self.generate_struct(data=data, filename=name)
                )

            if attachments:
                by_source = {}
                for _, _, src in attachments:
                    by_source[src] = by_source.get(src, 0) + 1
                self.reports["embedded_files"] = Report(
                    f"Extracted {len(attachments)} embedded file(s): "
                    + ", ".join(f"{n}={c}" for n, c in by_source.items()),
                    short=f"{len(attachments)} embedded",
                    label="embedded_files",
                    severity=Severity.MEDIUM,
                    verbosity=0,
                    order=24,
                    data={"count": len(attachments), "by_source": by_source,
                          "names": [n for n, _, _ in attachments]},
                )

        except Exception as e:
            logging.error(f"Error extracting embedded files from PDF: {e}")

    def extract_resources(self):
        """Walk every page's /Resources and emit inline images and fonts
        as child Structures.

        Inline images matter because phishing increasingly embeds QR codes
        in PDFs as a static image — extracting them lets QRAnalyzer run on
        the bytes and surface the destination URL. Embedded fonts are
        included for completeness (Type 1 / TrueType / OpenType / CIDFont
        streams sometimes carry shellcode in older exploit chains).

        Quiet by design: no Report on the PDF for the extraction itself,
        only what downstream analyzers find on the resource bytes."""
        if not hasattr(self, "pdfobj"):
            return
        try:
            from PyPDF2.generic import IndirectObject
        except ImportError:
            return

        seen_payloads: set[tuple[int, bytes]] = set()
        emitted = 0

        def _resolve(o):
            while isinstance(o, IndirectObject):
                o = o.get_object()
            return o

        def emit(name: str, data: bytes, mime: str) -> None:
            nonlocal emitted
            if not data:
                return
            key = (len(data), data[:64])
            if key in seen_payloads:
                return
            seen_payloads.add(key)
            emitted += 1
            try:
                self.childitems.append(
                    self.generate_struct(
                        data=data, filename=name, mime_type=mime,
                    )
                )
            except Exception as e:
                logging.debug("emit resource child failed: %s", e)

        # XObject filter → MIME hint. PDF /Filter on an Image XObject is
        # the strongest signal — DCTDecode == JPEG, JPXDecode == JPEG2000,
        # JBIG2Decode == JBIG2, CCITTFaxDecode == G3/G4 fax (TIFF-able).
        _FILTER_TO_EXT = {
            "/DCTDecode":     ("jpg",  "image/jpeg"),
            "/JPXDecode":     ("jp2",  "image/jp2"),
            "/JBIG2Decode":   ("jb2",  "image/x-jbig2"),
            "/CCITTFaxDecode": ("tif", "image/tiff"),
            # FlateDecode'd images are usually raw pixel data — Pillow can
            # reconstruct them via .image accessor, but skip the bytes
            # heuristic and flag as octet-stream so analysts can inspect.
            "/FlateDecode":   ("bin",  "application/octet-stream"),
        }

        def _filter_to_extmime(filter_obj):
            try:
                if filter_obj is None:
                    return ("bin", "application/octet-stream")
                if hasattr(filter_obj, "__iter__") and not isinstance(filter_obj, str):
                    # /Filter chain — last filter is innermost; use the
                    # outermost (first) for naming since that's what the
                    # decoded bytes look like.
                    filter_obj = next(iter(filter_obj), None)
                key = str(filter_obj)
                return _FILTER_TO_EXT.get(key, ("bin", "application/octet-stream"))
            except Exception:
                return ("bin", "application/octet-stream")

        # ---- Walk every page ----
        try:
            for page_idx, page in enumerate(self.pdfobj.pages):
                resources = _resolve(page.get("/Resources"))
                if resources is None:
                    continue

                # 1. Inline images via /XObject (Subtype /Image)
                xobjs = _resolve(resources.get("/XObject"))
                if xobjs:
                    for key in list(xobjs.keys()):
                        try:
                            obj = _resolve(xobjs[key])
                            if (hasattr(obj, "get")
                                    and obj.get("/Subtype") == "/Image"):
                                ext, mime = _filter_to_extmime(obj.get("/Filter"))
                                # Bounded extract — refuses streams that
                                # would inflate past _PDF_STREAM_MAX_BYTES.
                                data = (
                                    _bounded_get_data(obj) or b""
                                    if hasattr(obj, "get_data") else b""
                                )
                                # Pillow-reconstructable images: try to get
                                # a real PNG out so QRAnalyzer can decode.
                                if ext == "bin":
                                    png_bytes = self._render_image_xobject(obj)
                                    if png_bytes:
                                        ext, mime = "png", "image/png"
                                        data = png_bytes
                                emit(
                                    f"page{page_idx + 1}_image_{key.lstrip('/')}.{ext}",
                                    bytes(data) if data else b"", mime,
                                )
                        except Exception as e:
                            logging.debug("XObject %s extract failed: %s", key, e)

                # 2. Embedded fonts via /Font /FontDescriptor /FontFileN
                fonts = _resolve(resources.get("/Font"))
                if fonts:
                    for key in list(fonts.keys()):
                        try:
                            font_obj = _resolve(fonts[key])
                            descriptor = _resolve(font_obj.get("/FontDescriptor"))
                            if descriptor is None:
                                continue
                            for fkey, ext in (("/FontFile", "pfb"),
                                              ("/FontFile2", "ttf"),
                                              ("/FontFile3", "otf")):
                                stream = _resolve(descriptor.get(fkey))
                                if stream is None or not hasattr(stream, "get_data"):
                                    continue
                                font_name = (descriptor.get("/FontName")
                                             or font_obj.get("/BaseFont")
                                             or key)
                                font_name = str(font_name).lstrip("/")
                                data = _bounded_get_data(stream)
                                if data is None:
                                    continue
                                emit(
                                    f"page{page_idx + 1}_font_{font_name}.{ext}",
                                    bytes(data) if data else b"",
                                    "application/font-sfnt"
                                    if ext != "pfb"
                                    else "application/x-font-type1",
                                )
                        except Exception as e:
                            logging.debug("Font %s extract failed: %s", key, e)
        except Exception as e:
            logging.debug("PDF resource walk failed: %s", e)

        # No Report emitted intentionally — keeps the default report quiet
        # for the common case where every PDF has fonts and a few images.
        # Analysts who care look at the analysis tree / manifest.json.

    @staticmethod
    def _render_image_xobject(xobj):
        """Try to reconstruct a non-DCT/JPX image XObject as PNG bytes via
        Pillow. Returns ``None`` if reconstruction isn't possible (no
        Pillow, unsupported colorspace, malformed object)."""
        try:
            from PIL import Image
        except ImportError:
            return None
        try:
            data = xobj.get_data()
            width = int(xobj.get("/Width", 0))
            height = int(xobj.get("/Height", 0))
            bits = int(xobj.get("/BitsPerComponent", 8))
            colorspace = str(xobj.get("/ColorSpace", "/DeviceRGB"))
            if not (width and height):
                return None
            if "DeviceRGB" in colorspace and bits == 8:
                mode = "RGB"
                expected = width * height * 3
            elif "DeviceGray" in colorspace and bits == 8:
                mode = "L"
                expected = width * height
            elif "DeviceCMYK" in colorspace and bits == 8:
                mode = "CMYK"
                expected = width * height * 4
            else:
                return None
            if len(data) < expected:
                return None
            img = Image.frombytes(mode, (width, height), data[:expected])
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except Exception:
            return None

    def detect_incremental_updates(self):
        """A PDF with more than one ``%%EOF`` carries one or more
        incremental updates — the file was modified after original
        signing/distribution, with new objects appended after the
        first %%EOF. Acrobat reads the latest xref, but the prior
        bytes are still in the file and may differ materially
        (added /JS, redefined catalog, etc.). This is a high-signal
        forensic indicator.

        We additionally byte-scan for any ``<id> <gen> obj`` whose
        (id, gen) pair has multiple distinct definitions, and emit
        each *non-final* version as a forensic child Structure so
        analysts can see what was changed."""
        raw = self.struct.rawdata
        eof_count = raw.count(b"%%EOF")
        if eof_count <= 1:
            return

        # Grade severity by what the post-EOF region contains. Incremental
        # updates by themselves are routine (signed PDFs, editor saves —
        # Amyuni / Adobe / etc. all use them). They become high-signal
        # only when the appended content adds active surfaces.
        first_eof = raw.index(b"%%EOF") + len(b"%%EOF")
        post = raw[first_eof:]
        active_markers = [
            (b"/JavaScript", "JavaScript"),
            (b"/JS ", "JS"),
            (b"/OpenAction", "OpenAction"),
            (b"/Launch", "Launch"),
            (b"/AA ", "AA"),
            (b"/AA<", "AA"),
            (b"/SubmitForm", "SubmitForm"),
            (b"/ImportData", "ImportData"),
        ]
        triggered = [name for marker, name in active_markers if marker in post]
        if triggered:
            severity = Severity.HIGH
            note = (f" — appended content adds active surface: "
                    f"{', '.join(sorted(set(triggered)))}")
        else:
            severity = Severity.INFO
            note = " — no active content in appended region (likely benign)"

        self.reports["incremental_updates"] = Report(
            f"PDF contains {eof_count - 1} incremental update(s) "
            f"(content was appended after the original %%EOF){note}",
            short=f"{eof_count - 1} incremental update(s)",
            label="incremental_updates",
            severity=severity,
            verbosity=0,
            order=22,
            data={"eof_count": eof_count, "updates": eof_count - 1,
                  "active_markers_in_appended_region": sorted(set(triggered))},
        )

        # Scan for multi-version objects
        import re
        obj_re = re.compile(
            rb"(?:^|\n)\s*(\d+)\s+(\d+)\s+obj\s*(.*?)\s*endobj",
            re.DOTALL,
        )
        versions: dict[tuple[int, int], list[bytes]] = {}
        for m in obj_re.finditer(raw):
            idnum = int(m.group(1))
            gen = int(m.group(2))
            body = m.group(3)
            versions.setdefault((idnum, gen), []).append(body)

        multi = [(k, vs) for k, vs in versions.items() if len(set(vs)) > 1]
        if not multi:
            return

        # Sort so the same (id, gen) groups together; emit non-final
        # versions as forensic children so they get analyzed too.
        for (idnum, gen), bodies in multi:
            unique = []
            seen = set()
            for b in bodies:
                if b not in seen:
                    seen.add(b)
                    unique.append(b)
            # Emit all but the last as historical versions
            for i, body in enumerate(unique[:-1]):
                try:
                    self.childitems.append(
                        self.generate_struct(
                            data=b"%PDF-fragment\n" + body + b"\n%%EOF\n",
                            filename=f"pdf_obj_{idnum}_{gen}_v{i}.bin",
                            mime_type="application/octet-stream",
                        )
                    )
                except Exception as e:
                    logging.debug("emit historical obj failed: %s", e)

        self.reports["redefined_objects"] = Report(
            f"{len(multi)} object(s) redefined across incremental updates: "
            + ", ".join(f"{k[0]} {k[1]}" for k in multi[:10])
            + (f" (+{len(multi) - 10} more)" if len(multi) > 10 else ""),
            short=f"{len(multi)} redefined object(s)",
            label="redefined_objects",
            severity=Severity.HIGH,
            verbosity=0,
            order=22,
            data={"objects": [{"id": k[0], "gen": k[1],
                               "versions": len(set(v))}
                              for k, v in multi]},
        )


    # Preview render budget — caps the work Poppler is willing to do
    # against attacker-controlled PDFs. Audit finding (codex_security_1,
    # codex_security_2): unbounded ``convert_from_bytes`` is a reliable
    # CPU/RAM exhaustion path against any deployment with poppler-utils
    # installed.
    _PREVIEW_TIMEOUT_S = 15        # pdftoppm spawn budget
    _PREVIEW_DPI = 72              # screen-resolution; 1 inch ~= 1 inch
    _PREVIEW_MAX_INPUT_BYTES = 50 * 1024 * 1024  # don't render PDFs > 50 MB
    _PREVIEW_MAX_PIXELS = 4_000_000  # ~2000×2000 ceiling on output

    def generate_preview(self):
        if importlib.util.find_spec("pdf2image") is None:
            logging.warning("pdf2image is not installed, cannot generate PDF preview.")
            return
        if not shutil.which("pdftoppm"):
            logging.warning("poppler (pdftoppm) is not installed, cannot generate PDF preview.")
            return

        # Refuse to render large attacker PDFs — pdftoppm is happy to
        # spend minutes on multi-hundred-MB inputs that have no useful
        # preview anyway.
        if self.struct.size > self._PREVIEW_MAX_INPUT_BYTES:
            logging.debug(
                "PDF preview skipped: input %d bytes exceeds budget %d",
                self.struct.size, self._PREVIEW_MAX_INPUT_BYTES,
            )
            return

        convert_from_bytes = importlib.import_module("pdf2image").convert_from_bytes
        try:
            images = convert_from_bytes(
                self.struct.rawdata,
                first_page=1, last_page=1, fmt='png',
                dpi=self._PREVIEW_DPI,
                # pdf2image forwards the timeout flag to pdftoppm via
                # subprocess; if missing on older pdf2image versions, the
                # outer subprocess.TimeoutExpired guard catches it.
                timeout=self._PREVIEW_TIMEOUT_S,
            )
            if not images:
                return
            image = images[0]
            # Reject pathological page geometry (e.g. crafted MediaBox
            # 100000×100000) that slips past pdftoppm's own checks.
            w, h = image.size
            if w * h > self._PREVIEW_MAX_PIXELS:
                logging.debug(
                    "PDF preview skipped: page %dx%d exceeds %d-pixel budget",
                    w, h, self._PREVIEW_MAX_PIXELS,
                )
                return
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            encoded_string = base64.b64encode(buffer.getvalue()).decode('ascii')
            self.reports['preview'] = Report(
                text="First page preview",
                label="Preview",
                content_type='image/png',
                data=encoded_string,
            )
        except Exception as e:
            logging.warning(f"Could not generate PDF preview: {e}")

    def policy_check(self):
        """Run the pdfcop-parity policy scan and emit verdicts.

        Always runs even when PyPDF2 isn't available — the scan is byte-level
        and doesn't depend on the parser. Two kinds of reports are emitted:

          * one ``pdf_<kind>_<name>`` Report per Finding (action / annotation /
            filter / structural marker), with the worst graded severity
            across the rights it requires
          * a single rollup Report ``pdfcop_policy`` summarising which
            profile(s) (standard / strong / paranoid) would block, with a
            per-profile listing of blocking findings in its ``data`` field

        Audit fix #43: the previous docstring claimed "one report per
        profile" — that wasn't accurate, only the rollup is per-profile."""
        if not _PDF_POLICY_AVAILABLE:
            return
        try:
            findings = _pdf_policy.scan(self.struct.rawdata)
        except Exception as e:
            logging.debug("pdf_policy scan failed: %s", e)
            return
        if not findings:
            return

        # Per-finding reports — graded by the worst right involved.
        worst = Severity.INFO
        for f in findings:
            sev = f.severity()
            worst = min(worst, sev)
            label = f"pdf_{f.kind}_{f.name}"
            self.reports[label] = Report(
                f"{f.kind}: {f.name}"
                + (f" (×{f.count})" if f.count > 1 else "")
                + (" [triggered at opening]" if f.triggered_at_opening else ""),
                short=f"{f.kind}:{f.name}",
                label=label.replace("@", "_at_"),
                severity=sev,
                verbosity=1,
                order=24,
                data={
                    "kind": f.kind, "name": f.name, "count": f.count,
                    "rights": list(f.rights),
                    "triggered_at_opening": f.triggered_at_opening,
                },
            )

        # Per-profile rollup so the analyst sees "this PDF would trigger
        # under standard / strong / paranoid" at a glance.
        profile_summary = {}
        for profile_name in ("standard", "strong", "paranoid"):
            verdicts = _pdf_policy.evaluate(findings, profile_name)
            profile_summary[profile_name] = [
                {"kind": v.finding.kind, "name": v.finding.name,
                 "blocked_by": list(v.blocked_by),
                 "severity": v.severity.name}
                for v in verdicts
            ]

        triggered_under = [name for name, v in profile_summary.items() if v]
        if triggered_under:
            std_count = len(profile_summary["standard"])
            strong_count = len(profile_summary["strong"])
            paranoid_count = len(profile_summary["paranoid"])
            text_lines = []
            for name, verdicts in profile_summary.items():
                if not verdicts:
                    continue
                text_lines.append(f"  [{name}] would block:")
                for v in verdicts:
                    text_lines.append(
                        f"    - {v['kind']}/{v['name']} "
                        f"({v['severity']}, blocked by {','.join(v['blocked_by'])})"
                    )
            # Severity for the overall finding = worst per-finding severity
            # we collected above (already in `worst`).
            self.reports["pdfcop_policy"] = Report(
                "PDF would trigger under: " + ", ".join(triggered_under)
                + f"\n  standard: {std_count}, strong: {strong_count}, "
                f"paranoid: {paranoid_count} blocking finding(s)\n"
                + "\n".join(text_lines),
                short="pdfcop: " + "/".join(triggered_under),
                label="pdfcop_policy",
                severity=worst,
                verbosity=0,
                order=23,
                data={"triggered_under": triggered_under,
                      "by_profile": profile_summary},
            )

    def analysis(self):
        if not PyPDF2:
            logging.warning("PyPDF2 is not installed, cannot analyze PDF files.")
            # Even without PyPDF2 we can still run the byte-level policy scan
            self.modules['policy'] = self.policy_check
            super().analysis()
            return

        self.modules['parser'] = self.parse_pdf
        self.modules['pdf2text'] = self.get_text
        self.modules['embeddedFiles'] = self.getAttachments
        self.modules['embedded_js'] = self.extract_js
        self.modules['resources'] = self.extract_resources
        self.modules['incremental_updates'] = self.detect_incremental_updates
        self.modules['policy'] = self.policy_check
        self.modules['preview'] = self.generate_preview

        super().analysis()
