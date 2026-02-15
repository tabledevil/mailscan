import tempfile
import shutil
import os

class TempFileManager:
    """
    A context manager for creating and managing temporary files and directories.
    """
    def __init__(self):
        self.temp_dir = None

    def __enter__(self):
        self.temp_dir = tempfile.mkdtemp()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir:
            shutil.rmtree(self.temp_dir)

    def create_temp_file(self, data=b''):
        """
        Creates a temporary file with the given data.
        Returns the path to the file.
        """
        if not self.temp_dir:
            raise Exception("Temporary directory not created. Use this class with a 'with' statement.")

        fd, path = tempfile.mkstemp(dir=self.temp_dir)
        with os.fdopen(fd, 'wb') as tmp:
            tmp.write(data)
        return path

    def get_temp_dir_path(self):
        """
        Returns the path to the temporary directory.
        """
        return self.temp_dir

    def get_created_files(self):
        """
        Returns a list of paths to all files in the temporary directory.
        """
        if not self.temp_dir:
            return []
        return [os.path.join(self.temp_dir, f) for f in os.listdir(self.temp_dir)]
