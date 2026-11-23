import json
import unittest

from structure import Structure


class StructureCacheTests(unittest.TestCase):
    """Duplicate content stays visible per location.

    Analysis is shared only for the same bytes under the same name and type
    (security: ``readme.txt`` must not mask the same bytes as ``payload.js``,
    see test_cache_filename_collision.py).  Duplicate *display* counts the
    content across all names."""

    def tearDown(self):
        Structure.clear_cache()

    def test_duplicate_bytes_keep_occurrence_metadata(self):
        first = Structure.create(data=b"same payload", filename="first.txt", index=1)
        second = Structure.create(data=b"same payload", filename="second.txt", index=2)

        self.assertIsNot(first, second)
        self.assertIsNot(first.analyzer, second.analyzer)   # different names
        self.assertEqual("first.txt", first.filename)
        self.assertEqual("second.txt", second.filename)
        self.assertEqual(1, first.index)
        self.assertEqual(2, second.index)
        self.assertEqual(2, first.duplicate_count)
        self.assertEqual(2, second.duplicate_count)
        self.assertEqual(1, first.duplicate_occurrence)
        self.assertEqual(2, second.duplicate_occurrence)

    def test_same_name_other_location_shares_analysis(self):
        first = Structure.create(data=b"same payload", filename="a.txt", index=1)
        second = Structure.create(data=b"same payload", filename="a.txt", index=7, level=2)

        self.assertIsNot(first, second)
        self.assertIs(first.analyzer, second.analyzer)
        self.assertEqual((1, 0), (first.index, first.level))
        self.assertEqual((7, 2), (second.index, second.level))
        self.assertEqual(2, second.duplicate_occurrence)

    def test_duplicate_report_is_occurrence_specific(self):
        first = Structure.create(data=b"same payload", filename="first.txt", index=1)
        second = Structure.create(data=b"same payload", filename="second.txt", index=2)

        first_report = json.loads(first.get_report(report_format="json"))
        second_report = json.loads(second.get_report(report_format="json"))

        first_duplicate = [
            r for r in first_report["reports"] if r["label"] == "duplicate"
        ][0]
        second_duplicate = [
            r for r in second_report["reports"] if r["label"] == "duplicate"
        ][0]

        self.assertEqual("Duplicate content occurrence 1 of 2", first_duplicate["text"])
        self.assertEqual("Duplicate content occurrence 2 of 2", second_duplicate["text"])


if __name__ == "__main__":
    unittest.main()
