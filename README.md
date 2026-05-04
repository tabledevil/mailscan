# MATT: Mail Analysis and Triage Tool

MATT is a modular file analysis tool designed to dissect and extract information from various file types, with a primary focus on email files.

## Overall Flow

MATT is a modular file analysis tool. The main entry point is
`matt.py`, which takes one or more files as input.

Here's the general flow:

1. **Initialization.** `matt.py` parses CLI flags and walks the
   provided file paths.

2. **Structure creation.** For each file, a `Structure` object
   (`structure.py`) reads the raw data and determines its MIME type
   via a **provider chain** — `python_magic` → `file` command →
   `magika` → stdlib `mimetypes` fallback (`Utils/filetype.py`).
   The cache key combines `(sha256, basename, mime_type)` so
   identical bytes seen under different filenames don't mask
   filename-based detections.

3. **Multi-dispatch analysis.** Every Analyzer subclass that
   `can_analyze()` the Structure runs against it
   (`Analyzer.run_all_analyzers`). The highest-`specificity`
   analyzer is **primary**; the rest are **contributors** that
   fill gaps without overriding primary findings. Specificity
   levels: 5=generic (PlainText), 10=container (Zip, 7z, OLE),
   15=semi (HTML), 20=format (Email, PDF, Docx, Mbox, Msg),
   25=sub-analyzer.

4. **Reports + children.** Analyzers populate `self.reports` with
   findings and `self.childitems` with nested `Structure` objects
   (e.g. zip entries, MIME parts, embedded PDF files). Children
   recurse through the same pipeline.

5. **Root-only post-pass.** Once the tree is built, the root
   Structure runs `_build_ioc_aggregate` (collects URLs/IPs/
   domains/emails/hashes from every node, defangs them) and
   `_build_capability_hints` (flags YARA/VT skipped because
   unconfigured).

6. **Rendering.** `Structure.get_report(format=...)` dispatches to
   `renderers/`. Available formats: `rich` (default), `text`,
   `json`, `markdown`, `html`, `timeline`.

7. **Optional extraction.** `-x` writes every reachable Structure
   to disk preserving the container hierarchy and original
   filenames; a `manifest.json` at the root maps every on-disk
   path to hashes/MIME/severity.

## Usage

To analyze one or more files, run `matt.py` with the file paths as arguments:

```bash
python3 matt.py <file1> <file2> ...
```

You can use the `-x` or `--extract` flag to extract all parts of the file (e.g., email attachments) into a directory named `extract` in the current working directory.

```bash
python3 matt.py -x <file>
```

## Installation

MATT supports two installation paths. The Docker path is recommended
when handling **untrusted samples** — it bundles box-js, libzbar,
poppler, and the rest of the optional analyzer stack in a REMnux-based
image with the right permissions and isolation.

### Docker (recommended for analyzing untrusted samples)

```bash
make build              # builds tabledevil/matt locally
make check              # matt --check inside the container
make shell              # interactive shell, ./data:/data mount
make test               # host-safe tests
make test-dynamic       # docker-only tests (box-js, libzbar, dynamic analysis)
```

Direct invocation against a sample (mount the directory, run `matt`):

```bash
docker run --rm -v "$(pwd)/samples:/data" tabledevil/matt \
    matt /data/suspicious.eml --format json
```

The image is based on `tabledevil/file-analysis:latest` (REMnux-derived)
and ships:

- Python 3.10 venv with all optional extras (`office`, `pdf`, `html`,
  `msg`, `7z`, `mime`, `tui`, `fuzzy`, `yara`, `js`, `qr`, `dev`)
- `libzbar0` — QR / barcode decoding for the QRAnalyzer
- `poppler-utils` — PDF page rendering (`pdftoppm`)
- `box-js` — dynamic JavaScript sandbox; verified at build time
- `MATT_IN_DOCKER=1` env var — unlocks `@pytest.mark.docker` tests
  that detonate attacker-controlled bytes (refused on the host)

The build fails loudly if `matt --check` reports unsatisfied core
dependencies, so a successful image is guaranteed analyzer-complete.

### Bare-metal install

Install the core dependencies (required for basic analysis) with pip:

```bash
pip install .
```

If you are installing in an offline environment, you can use:

```bash
pip install . --no-build-isolation
```

The project uses the modern PEP-517 `setuptools.build_meta` backend
declared in `pyproject.toml`. A legacy `setup.py` is also present for
tooling that hasn't migrated yet, but `pyproject.toml` is canonical.

Optional features are provided via extras. **Quote the extras name**
in shells that interpret square brackets as glob characters (zsh,
fish):

```bash
pip install '.[all]'
```

Available extras: `office`, `pdf`, `html`, `msg`, `7z`, `lang`, `mime`,
`tui`, `fuzzy`, `fuzzy-ssdeep`, `yara`, `js`, `qr`, `rar`, `dev`.
Check what's missing on your system with:

```bash
matt --check
```

For mbox analysis, the standard library `mailbox` module is used and requires no extra dependencies.

#### System dependencies

Some optional features need system libraries:

| Extra | System dep | Debian/Ubuntu | macOS (brew) |
|-------|-----------|---------------|--------------|
| `(core)` | libmagic | `apt-get install libmagic1` | `brew install libmagic` |
| `qr` | libzbar | `apt-get install libzbar0` | `brew install zbar` |
| `pdf` | poppler-utils | `apt-get install poppler-utils` | `brew install poppler` |
| `js` (dynamic) | box-js (npm) | `npm install -g box-js` | `npm install -g box-js` |

Dynamic JavaScript analysis (box-js) detonates attacker-controlled
bytes — only run it inside the MATT Docker container or an equally
isolated sandbox. The bare-metal install of `js` covers static
deobfuscation only.

## Cloud Testing With Sample Files

The repository keeps encrypted sample archives in `testfiles/` so cloud runners can execute reproducible tests without storing extracted payloads in Git.

Run corpus tests:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Optional decryption test (for environments like Jules) requires a secret:

- `SAMPLE_ZIP_PASSWORD`: password for encrypted ZIP samples (commonly `infected`)

Example:

```bash
SAMPLE_ZIP_PASSWORD=infected python -m unittest discover -s tests -p "test_*.py"
```
