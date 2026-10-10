#!/usr/bin/env python3
"""DATA_DIR follows AGENTHUB_ROOT after refresh_paths; tests never write the repo data/."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent
TMP = tempfile.mkdtemp(prefix="agenthub-paths-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

from hubv1.store import data_dir, refresh_paths  # noqa: E402
from hubv1 import workspace as ws  # noqa: E402
from hubv1 import xfer  # noqa: E402
from hubv1 import publisher  # noqa: E402
from hubv1 import chat  # noqa: E402
from hubv1 import assets  # noqa: E402


class PathTests(unittest.TestCase):
    def setUp(self):
        refresh_paths()

    def test_helpers_use_temp_root(self):
        root = Path(os.environ["AGENTHUB_ROOT"])
        self.assertEqual(data_dir(), root / "data")
        self.assertEqual(ws.wsblobs_dir().parent, data_dir())
        self.assertEqual(xfer.uploads_dir().parent, data_dir())
        self.assertEqual(publisher.secrets_dir().parent, data_dir())
        self.assertTrue(str(chat.archive_path("th_test", "2026-01-01")).startswith(str(root)))
        digest = assets.put_asset(b"path-test-bytes")
        self.assertTrue((data_dir() / "assets" / digest).is_file())

    def test_refresh_paths_moves_imported_modules(self):
        other = tempfile.mkdtemp(prefix="agenthub-paths-b-")
        prev = os.environ["AGENTHUB_ROOT"]
        prev_db = os.environ.get("AGENTHUB_DB")
        try:
            os.environ["AGENTHUB_ROOT"] = other
            os.environ["AGENTHUB_DB"] = str(Path(other) / "data" / "hub.db")
            refresh_paths()
            self.assertEqual(data_dir(), Path(other) / "data")
            self.assertEqual(ws.wsblobs_dir(), Path(other) / "data" / "wsblobs")
            self.assertEqual(xfer.uploads_dir(), Path(other) / "data" / "uploads")
            self.assertEqual(publisher.secrets_dir(), Path(other) / "data" / "secrets")
        finally:
            os.environ["AGENTHUB_ROOT"] = prev
            if prev_db:
                os.environ["AGENTHUB_DB"] = prev_db
            refresh_paths()

    def test_repo_data_dir_untouched_by_helpers(self):
        marker = REPO / "data" / ".path-test-marker"
        before = marker.exists()
        ws.wsblobs_dir()
        xfer.uploads_dir()
        publisher.secrets_dir()
        self.assertEqual(marker.exists(), before)
        self.assertNotEqual(data_dir(), REPO / "data")


if __name__ == "__main__":
    unittest.main(verbosity=2)
