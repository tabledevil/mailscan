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

## Dependencies

This project has several dependencies that need to be installed. You can install them using pip:

```bash
pip install python-magic chardet python-dateutil pytz extract-msg PyPDF2
```

**Note:** The `python-magic` library depends on the `libmagic` library. You may need to install it using your system's package manager. For example, on Debian/Ubuntu:

```bash
sudo apt-get install libmagic1
```
