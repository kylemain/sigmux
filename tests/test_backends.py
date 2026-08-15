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


class TestElasticBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("elastic")

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


class TestCrowdStrikeBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("crowdstrike")

    def test_renders_and_or_not(self):
        out = self.backend.render(self.rule)
        self.assertIn("Image = *\\powershell.exe", out)
        self.assertIn(" or ", out)
        self.assertIn(" and ", out)
        self.assertIn("not (ParentImage = *\\explorer.exe)", out)
        self.assertIn("CommandLine = *-enc*", out)

    def test_quotes_values_with_spaces(self):
        rule = SigmaRule.from_yaml(
            """
            title: t
            logsource: {product: windows}
            detection:
              selection: {CommandLine|contains: 'invoke mimikatz'}
              condition: selection
            """
        )
        out = self.backend.render(rule)
        self.assertIn('CommandLine = "*invoke mimikatz*"', out)


class TestSumoLogicBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("sumologic")

    def test_renders_and_or_not(self):
        out = self.backend.render(self.rule)
        self.assertIn("Image=*\\powershell.exe", out)
        self.assertIn(" OR ", out)
        self.assertIn(" AND ", out)
        self.assertIn("NOT ParentImage=*\\explorer.exe", out)
        self.assertIn("CommandLine=*-enc*", out)


class TestQRadarBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("qradar")

    def test_renders_select_where(self):
        out = self.backend.render(self.rule)
        self.assertTrue(out.startswith("SELECT UTF8(payload) AS payload FROM events WHERE "))
        self.assertIn("Image LIKE '%\\powershell.exe'", out)
        self.assertIn(" AND ", out)
        self.assertIn(" OR ", out)
        self.assertIn("NOT (ParentImage LIKE '%\\explorer.exe')", out)

    def test_quotes_are_escaped(self):
        rule = SigmaRule.from_yaml(
            """
            title: t
            logsource: {product: windows}
            detection:
              selection: {Field: "O'Brien"}
              condition: selection
            """
        )
        out = self.backend.render(rule)
        self.assertIn("Field = 'O''Brien'", out)


class TestChronicleBackend(unittest.TestCase):
    def setUp(self):
        self.rule = SigmaRule.from_yaml(RULE_TEXT)
        self.backend = get_backend("chronicle")

    def test_renders_rule_skeleton(self):
        out = self.backend.render(self.rule)
        self.assertTrue(out.startswith("rule Exercise_all_node_types {"))
        self.assertIn('$e.metadata.event_type = "PROCESS_LAUNCH"', out)
        self.assertIn('$e.CommandLine contains "-enc"', out)
        self.assertIn("re.regex($e.Image,", out)
        self.assertIn(" and ", out)
        self.assertIn("not (", out)
        self.assertTrue(out.rstrip().endswith("condition:\n    $e\n}"))

    def test_default_event_type_fallback(self):
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
        self.assertIn('"GENERIC_EVENT"', out)

    def test_rule_name_sanitized_and_meta_block(self):
        rule = SigmaRule.from_yaml(
            """
            title: "Suspicious: PowerShell (Encoded)!"
            id: abc-123
            level: high
            description: "Flags encoded PowerShell execution"
            logsource: {category: process_creation}
            detection:
              selection: {CommandLine|contains: '-enc'}
              condition: selection
            """
        )
        out = self.backend.render(rule)
        header = out.splitlines()[0]
        self.assertRegex(header, r"^rule [A-Za-z_][A-Za-z0-9_]*\s*\{$")
        self.assertIn("Suspicious", header)
        self.assertIn('description = "Flags encoded PowerShell execution"', out)
        self.assertIn('severity = "HIGH"', out)
        self.assertIn('reference = "abc-123"', out)


class TestUnknownTarget(unittest.TestCase):
    def test_raises_helpful_error(self):
        from sigmux.backends import get_backend

        with self.assertRaises(ValueError):
            get_backend("not-a-real-siem")


if __name__ == "__main__":
    unittest.main()
