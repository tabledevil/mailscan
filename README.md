# MATT: Mail Analysis and Triage Tool

MATT is a modular file analysis tool designed to dissect and extract information from various file types, with a primary focus on email files.

## Overall Flow

The system is designed as a modular file analysis tool. The main entry point is `matt.py`, which is a command-line script that takes one or more files as input.

Here's the general flow:

1.  **Initialization:** `matt.py` takes a file path from the command line.

2.  **Structure Creation:** For each file, it creates a `Structure` object (from `structure.py`). The `Structure` object is the central data container for a file and its analysis results. It reads the raw data of the file and determines its MIME type using the `python-magic` library.

3.  **Analyzer Selection:** The `Structure` object then uses the `Analyzer.get_analyzer(mimetype)` method to find a suitable analyzer for the file's MIME type. The system looks through all the available `Analyzer` subclasses (defined in the `Analyzers/` directory) and finds one that lists the file's MIME type in its `compatible_mime_types` list.

4.  **Analysis:** Once the correct analyzer is found, it's instantiated. The analyzer's `analysis()` method is called, which in turn runs various analysis modules. For example, the `EmailAnalyzer` will use the `eml.py` module to parse the email's headers and structure.

5.  **Report Generation:** During analysis, the analyzer populates the `Structure` object with reports and information it discovers. For example, the `EmailAnalyzer` adds reports for the sender, recipient, and subject of the email.

6.  **Handling of Nested Files:** If the analyzer finds nested files (like email attachments or files in a zip archive), it creates new `Structure` objects for each of them. These children are then analyzed recursively in the same way, creating a hierarchical structure.

7.  **Output:** Finally, `matt.py` calls the `get_report()` method on the top-level `Structure` object. This method generates a formatted, indented report of all the information gathered from the file and its children. If the `--extract` flag is used, the `extract()` method is called to save all the parts of the file (e.g., email attachments) to disk.

In essence, the system uses a flexible, modular design where `Structure` objects represent files and `Analyzer` objects are responsible for processing them based on their type. This makes it easy to extend the tool by simply adding new analyzer classes for different file types.

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

This project uses the legacy `setup.py` build to avoid build-time downloads in restricted environments.

Optional features are provided via extras. For example:

```bash
pip install .[all]
```

Available extras: `office`, `pdf`, `html`, `msg`, `7z`, `lang`, `mime`,
`tui`, `fuzzy`, `yara`, `js`, `qr`, `dev`. Check what's missing on your
system with:

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
