import unittest
from pathlib import Path

from click.testing import CliRunner

from sigmux.cli import main

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


class TestCli(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_targets_lists_all_backends(self):
        result = self.runner.invoke(main, ["targets"])
        self.assertEqual(result.exit_code, 0)
        for name in ("elasticsearch", "sentinel", "splunk", "logscale", "qradar", "chronicle", "sumologic"):
            self.assertIn(name, result.output)

    def test_convert_single_rule_all_targets(self):
        rule_path = EXAMPLES_DIR / "mimikatz_execution.yml"
        result = self.runner.invoke(main, ["convert", str(rule_path)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("splunk", result.output)
        self.assertIn("elasticsearch", result.output)
        self.assertIn("sentinel", result.output)
        self.assertIn("logscale", result.output)
        self.assertIn("qradar", result.output)
        self.assertIn("chronicle", result.output)
        self.assertIn("sumologic", result.output)

    def test_convert_directory_writes_files(self):
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                main,
                [
                    "convert",
                    str(EXAMPLES_DIR),
                    "--target",
                    "splunk",
                    "--out",
                    "out",
                ],
            )
            self.assertEqual(result.exit_code, 0, result.output)
            written = sorted(Path("out").glob("*.splunk.spl"))
            self.assertEqual(len(written), 4)

    def test_convert_directory_writes_correct_extensions_per_target(self):
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                main,
                ["convert", str(EXAMPLES_DIR), "--out", "out"],
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(len(list(Path("out").glob("*.splunk.spl"))), 4)
            self.assertEqual(len(list(Path("out").glob("*.elasticsearch.json"))), 4)
            self.assertEqual(len(list(Path("out").glob("*.sentinel.kql"))), 4)
            self.assertEqual(len(list(Path("out").glob("*.logscale.lql"))), 4)
            self.assertEqual(len(list(Path("out").glob("*.qradar.aql"))), 4)
            self.assertEqual(len(list(Path("out").glob("*.chronicle.yaral"))), 4)
            self.assertEqual(len(list(Path("out").glob("*.sumologic.sumo"))), 4)

    def test_unknown_target_reported(self):
        rule_path = EXAMPLES_DIR / "mimikatz_execution.yml"
        result = self.runner.invoke(
            main, ["convert", str(rule_path), "--target", "nope"]
        )
        self.assertNotEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
