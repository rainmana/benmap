from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from benmap.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "nmap-benmap.xml"


class CliTests(unittest.TestCase):
    def test_analyze_json_reports_ineligibility_without_failure(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(
                [
                    "analyze",
                    str(FIXTURE),
                    "--feature",
                    "content_length",
                    "--format",
                    "json",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertFalse(payload["eligible"])
        self.assertEqual(payload["sample_count"], 1)

    def test_observations_jsonl(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["observations", str(FIXTURE), "--format", "jsonl"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["target"], "192.0.2.10")

    def test_missing_observations_returns_error(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = main(["analyze", str(Path(__file__))])

        self.assertEqual(exit_code, 2)
        self.assertIn("error", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
