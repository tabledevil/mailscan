"""Temporary file management for MATT."""

import logging
import os
import shutil
import tempfile

log = logging.getLogger("matt")


class TempFileManager:
    """Context manager for creating and managing temporary files and directories."""

    def __init__(self):
        self.temp_dir = None

    def __enter__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="matt_")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir:
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                log.warning(f"Failed to clean up temp directory {self.temp_dir}: {e}")
            finally:
                self.temp_dir = None
        return False  # never suppress exceptions

    def create_temp_file(self, data=b"", suffix="", prefix="matt_"):
        """Create a temporary file with the given data.

        Returns the path to the created file.
        """
        if not self.temp_dir:
            raise RuntimeError(
                "Temporary directory not created. Use this class with a 'with' statement."
            )
        fd, path = tempfile.mkstemp(dir=self.temp_dir, suffix=suffix, prefix=prefix)
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)
        return path

    def get_temp_dir_path(self):
        """Return the path to the temporary directory, or None."""
        return self.temp_dir

    def get_created_files(self):
        """Return a list of all files in the temporary directory (recursive)."""
        if not self.temp_dir:
            return []
        result = []
        for root, _dirs, files in os.walk(self.temp_dir):
            for f in files:
                result.append(os.path.join(root, f))
        return result
