import json
import unittest

from sigmux.backends import get_backend
from sigmux.rule import SigmaRule

RULE_TEXT = r"""
title: Exercise all node types
logsource: {category: process_creation, product: windows}
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flag:
    CommandLine|contains: '-enc'
  filter:
    ParentImage|endswith: '\explorer.exe'
  condition: selection_image and selection_flag and not filter
"""


class TestSplunkBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("splunk")

    def test_renders_and_or_not(self):
        out = self.backend.render(self.rule)
        self.assertIn("Image=*\\powershell.exe", out)
        self.assertIn(" OR ", out)
        self.assertIn(" AND ", out)
        self.assertIn("NOT ParentImage=*\\explorer.exe", out)
        self.assertIn('CommandLine=*-enc*', out)


class TestElasticsearchBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("elasticsearch")

    def test_renders_valid_json_bool_query(self):
        out = self.backend.render(self.rule)
        parsed = json.loads(out)
        top = parsed["query"]["bool"]["must"]
        # First must-clause is the OR'd Image wildcard match.
        self.assertIn("should", top[0]["bool"])
        # Last must-clause is the negated filter.
        self.assertIn("must_not", top[-1]["bool"])


class TestSentinelBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("sentinel")

    def test_renders_table_and_where(self):
        out = self.backend.render(self.rule)
        self.assertTrue(out.startswith("DeviceProcessEvents\n| where "))
        self.assertIn(' has "-enc"', out)
        self.assertIn("not (ParentImage endswith", out)

    def test_default_table_fallback(self):
        rule = SigmaRule.from_yaml(
            """
            title: t
            logsource: {product: unknown_product}
            detection:
              selection: {Field: value}
              condition: selection
            """
        )
        out = self.backend.render(rule)
        self.assertTrue(out.startswith("SecurityEvent\n"))


class TestUnknownTarget(unittest.TestCase):
    def test_raises_helpful_error(self):
        from sigmux.backends import get_backend

        with self.assertRaises(ValueError):
            get_backend("not-a-real-siem")


if __name__ == "__main__":
    unittest.main()
