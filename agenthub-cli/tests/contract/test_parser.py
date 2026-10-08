import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(ROOT))

from agenthub_cli.cli import main  # noqa: E402


class ParserTests(unittest.TestCase):
    def test_help(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_stub_exit_10(self):
        code = main(["chat"])
        self.assertEqual(code, 10)

    def test_no_token_flag(self):
        from agenthub_cli.cli import build_parser

        text = build_parser().format_help()
        self.assertNotIn("--token", text)
        self.assertNotIn("AH_TOKEN=", text)


if __name__ == "__main__":
    unittest.main()
