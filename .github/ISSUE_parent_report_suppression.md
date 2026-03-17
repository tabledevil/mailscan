# Add parent analyzer report suppression for child analyzers

## Problem

When a "conductor" analyzer like `DocxAnalyzer` unpacks a container and creates child `Structure` objects, the child analyzers currently use awkward filtering hacks to determine whether they should run:

- `OfficeXMLAnalyzer` (line 20) checks `self.struct.parent.analyzer.__class__.__name__ in ['DocxAnalyzer']` — a string-based class name check to avoid circular imports
- `OfficeRelationshipAnalyzer` (line 13) checks `self.struct.filename.endswith('.rels')` to avoid running on non-rels XML files

These hacks are fragile and won't scale as more Office analyzers are added (e.g. XLSX, PPTX).

## Proposed Solution

Add a mechanism for a parent/conductor analyzer to **mute or suppress reports** from child analyzers, rather than having child analyzers sniff their parent to decide whether to run.

Possible approaches:
1. **Report suppression by parent** — conductor analyzer declares which child report keys or analyzer types to hide/mute
2. **Verbosity/visibility flag on reports** — parent can mark child reports as hidden, renderers respect this
3. **Analyzer context propagation** — parent passes a context dict to children indicating the container type, replacing string-based class name checks

### Benefits
- Child analyzers run unconditionally on matching MIME types (no parent-sniffing hacks)
- The conductor decides what's relevant to surface
- Cleaner separation of concerns
- Easier to add new Office format analyzers (XLSX, PPTX) that reuse the same child analyzers

## Files Affected

- `structure.py` — `Report` and/or `Analyzer` base class changes
- `Analyzers/DocxAnalyzer.py` — adopt new suppression mechanism
- `Analyzers/OfficeXMLAnalyzer.py` — remove parent class name check (line 20)
- `Analyzers/OfficeRelationshipAnalyzer.py` — remove `.rels` filename check (line 13)
