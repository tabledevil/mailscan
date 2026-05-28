import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from structure import Structure


class ZipStructureTests(unittest.TestCase):
    def tearDown(self):
        Structure.clear_cache()

    def _make_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("docs/", b"")
            zf.writestr("docs/nested/", b"")
            zf.writestr("docs/nested/readme.txt", b"hello from zip")
            zf.writestr("top.txt", b"top level")
        return buf.getvalue()

    def test_zip_members_keep_directory_hierarchy(self):
        struct = Structure.create(
            data=self._make_zip(),
            filename="archive.zip",
            mime_type="application/zip",
        )

        root_children = struct.get_children()
        self.assertEqual(
            ["docs", "top.txt"], [child.filename for child in root_children]
        )

        docs = root_children[0]
        self.assertTrue(docs.is_directory)
        self.assertEqual("docs", docs.archive_path)
        self.assertEqual("DirectoryAnalyzer", type(docs.analyzer).__name__)

        nested = docs.get_children()[0]
        self.assertTrue(nested.is_directory)
        self.assertEqual("docs/nested", nested.archive_path)

        readme = nested.get_children()[0]
        self.assertFalse(readme.is_directory)
        self.assertEqual("readme.txt", readme.filename)
        self.assertEqual("docs/nested/readme.txt", readme.archive_path)
        self.assertEqual(b"hello from zip", readme.rawdata)

    def test_zip_directory_nodes_show_up_in_json_report(self):
        struct = Structure.create(
            data=self._make_zip(),
            filename="archive.zip",
            mime_type="application/zip",
        )

        report = json.loads(struct.get_report(report_format="json", verbosity=1))
        docs = report["children"][0]
        nested = docs["children"][0]

        self.assertEqual("docs", docs["info"]["filename"])
        self.assertEqual("inode/directory", docs["info"]["mime_type"])
        self.assertEqual("DirectoryAnalyzer", docs["info"]["analyzer_name"])
        self.assertEqual("nested", nested["info"]["filename"])

    def test_recursive_extract_recreates_archive_directories(self):
        struct = Structure.create(
            data=self._make_zip(),
            filename="archive.zip",
            mime_type="application/zip",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            struct.extract(basepath=tmpdir, filenames=True, recursive=True)

            base = Path(tmpdir) / "archive" / "children"
            self.assertTrue((base / "docs" / "nested").is_dir())
            self.assertEqual(
                b"hello from zip",
                (base / "docs" / "nested" / "readme.txt").read_bytes(),
            )
            self.assertEqual(b"top level", (base / "top.txt").read_bytes())


if __name__ == "__main__":
    unittest.main()
