"""Regression coverage for malformed local API key stores."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_mcp import common


class APIKeyStoreTests(unittest.TestCase):
    def test_non_object_json_is_treated_as_missing_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text('["unexpected"]', encoding="utf-8")
            with patch.object(common, "KEYS_PATH", str(path)):
                self.assertIsNone(common.api_key("test_store_regression_key"))


if __name__ == "__main__":
    unittest.main()
