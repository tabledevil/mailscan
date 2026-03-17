# Plan: Unified Office Document Analyzer with Fallback

## Problem

Office documents (DOCX, XLSX, PPTX) are ZIP archives containing XML. Currently:
- **DocxAnalyzer** opens the ZIP, does some structural checks, then creates child Structure objects for **every** internal file
- Each child gets dispatched to generic analyzers (OfficeXMLAnalyzer, OfficeRelationshipAnalyzer, VBAProjectAnalyzer, or even base Analyzer)
- This means dozens of XML files show up in the report tree that are internal plumbing (styles.xml, fontTable.xml, theme1.xml, etc.) — noise
- If DocxAnalyzer weren't registered, the file would fall through to ZipAnalyzer (same MIME won't match, but the concept applies)
- Only DOCX is covered today — XLSX and PPTX have no dedicated analyzer at all

## Design

### 1. New unified `OfficeDocumentAnalyzer` (replaces DocxAnalyzer)

A single analyzer that handles all OOXML formats end-to-end:

**MIME types:**
- `application/vnd.openxmlformats-officedocument.wordprocessingml.document` (DOCX)
- `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` (XLSX)
- `application/vnd.openxmlformats-officedocument.presentationml.presentation` (PPTX)
- Plus macro-enabled variants: `.macroenabled.*`

**What it does internally (no child dispatch for these):**
- **Relationship analysis** — parse all `.rels` files inline, detect external links, remote templates, NTLM leaks (absorbs OfficeRelationshipAnalyzer logic)
- **XML threat scanning** — scan document XML for DDE, XXE, suspicious tags, encoded payloads (absorbs OfficeXMLAnalyzer logic)
- **VBA detection** — detect `vbaProject.bin` presence (absorbs VBAProjectAnalyzer logic for office context)
- **Structural checks** — ActiveX, OLE embeddings, embedded fonts (existing DocxAnalyzer logic)

**What it emits as children (only truly interesting items):**
- Embedded OLE objects (`word/embeddings/`, `ppt/embeddings/`, `xl/embeddings/`)
- VBA project binaries (`vbaProject.bin`) — still emitted as child for deep analysis
- ActiveX binaries (`activeX*.bin`)
- Embedded media that is suspicious or non-standard
- Any file that is **unreferenced** by relationships (orphan files = suspicious)

**What it does NOT emit as children:**
- Standard XML parts (document.xml, styles.xml, fontTable.xml, etc.)
- Standard relationship files (.rels)
- Content types file ([Content_Types].xml)
- Theme files, settings, etc.

### 2. Fallback mechanism in `get_analyzer()`

Add an **analyzer fallback** concept to the dispatch system:

```python
class Analyzer:
    fallback_analyzer = None  # Class attribute, set by subclasses
```

**How it works:**
- `OfficeDocumentAnalyzer` sets a `self.success` flag during `analysis()`
- If the analysis raises an exception or the analyzer explicitly sets `self.success = False`, the Structure class catches this and re-dispatches to the fallback
- `OfficeDocumentAnalyzer.fallback_analyzer = ZipAnalyzer` (conceptually — actual reference by name to avoid import issues)
- This means: if the Office analyzer can't parse the document (corrupt, password-protected in a way it can't handle, etc.), the system automatically falls back to treating it as a plain ZIP

**Implementation in `structure.py`:**
```python
# In Structure.__init__, after analyzer creation:
self.analyzer = Analyzer.get_analyzer(self.mime_type, struct=self)(self)
if hasattr(self.analyzer, 'success') and self.analyzer.success is False:
    fallback_cls = self.analyzer.get_fallback()
    if fallback_cls:
        self.analyzer = fallback_cls(self)
```

### 3. Changes to existing analyzers

- **DocxAnalyzer** — removed (replaced by OfficeDocumentAnalyzer)
- **OfficeRelationshipAnalyzer** — kept but no longer triggered for office-internal .rels files (the unified analyzer handles those). Still available for standalone .rels files outside office containers if that ever occurs.
- **OfficeXMLAnalyzer** — kept but same story. Its parent check already limits it to DocxAnalyzer context, which will no longer exist.
- **VBAProjectAnalyzer** — kept as-is for vbaProject.bin found outside office documents (e.g., standalone .bin files). The office analyzer handles it when inside an office doc.
- **ZipAnalyzer** — unchanged, serves as fallback

### 4. File changes

| File | Action |
|------|--------|
| `Analyzers/OfficeDocumentAnalyzer.py` | **NEW** — unified office analyzer |
| `Analyzers/DocxAnalyzer.py` | **DELETE** — replaced by OfficeDocumentAnalyzer |
| `Analyzers/__init__.py` | Replace `DocxAnalyzer` with `OfficeDocumentAnalyzer` in list |
| `structure.py` | Add fallback mechanism (~5 lines in `Structure.__init__`) |
| `Analyzers/OfficeXMLAnalyzer.py` | Update parent check to include `OfficeDocumentAnalyzer` (backward compat) |

### 5. Orphan file detection (bonus forensic value)

The office analyzer will:
1. Parse all `.rels` files to build a set of **referenced** internal paths
2. Compare against the actual ZIP file list
3. Any file present in the ZIP but **not referenced** by any relationship = orphan
4. Orphan files are suspicious (could be hidden payloads) → report + emit as children

### 6. What the user sees (before vs after)

**Before:** A DOCX analysis shows 30+ child items (every XML file inside the ZIP), most with no findings.

**After:** A DOCX analysis shows a comprehensive office-level report with all findings inline, and only truly interesting children (embedded objects, VBA, orphans) appear in the tree.
