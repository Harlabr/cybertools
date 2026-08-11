import unittest

from cybertools import normalize_url


class TestHelpers(unittest.TestCase):
    def test_normalize_url_adds_scheme_and_path(self):
        self.assertEqual(normalize_url("Example.COM"), "https://example.com/")

    def test_normalize_url_preserves_query(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.COM/a?x=1"),
            "https://example.com/a?x=1",
        )


if __name__ == "__main__":
    unittest.main()
