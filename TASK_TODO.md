# TODO: CSV Export Fixes

Following the review of PR #7961380c01 (Optimized getallfromfields.py), two issues were identified in the `eml.py` `get_csv` method that need to be addressed in a future task:

1.  **CSV Escaping**:
    - The current implementation manually constructs CSV strings with double quotes but does not escape quotes *inside* the fields.
    - Example: `Subject: test "quote"` produces malformed CSV.
    - Solution: Use Python's `csv` module or implement RFC4180 escaping.

2.  **Subject Truncation**:
    - Currently, only `self.subject[0]` is used, but `self.subject` is a list that might contain multiple fragments (e.g., from decoded MIME headers).
    - Example: Multilingual or split-encoded subjects.
    - Solution: Join all fragments in `self.subject` with a space or other separator before exporting.

These should be fixed in a new PR/branch.
