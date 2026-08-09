import unittest

from sigmux.ast_nodes import And, FieldMatch, Or
from sigmux.rule import SigmaRule


def _rule(text: str) -> SigmaRule:
    return SigmaRule.from_yaml(text)


class TestFieldModifiers(unittest.TestCase):
    def test_plain_equals(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                EventID: 4688
              condition: selection
            """
        )
        self.assertIsInstance(rule.ast, FieldMatch)
        self.assertEqual(rule.ast.modifier, "eq")
        self.assertEqual(rule.ast.value, "4688")

    def test_explicit_contains(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                CommandLine|contains: mimikatz
              condition: selection
            """
        )
        self.assertEqual(rule.ast.modifier, "contains")
        self.assertEqual(rule.ast.value, "mimikatz")

    def test_wildcard_inference_contains(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                CommandLine: '*mimikatz*'
              condition: selection
            """
        )
        self.assertEqual(rule.ast.modifier, "contains")
        self.assertEqual(rule.ast.value, "mimikatz")

    def test_wildcard_inference_endswith(self):
        rule = _rule(
            r"""
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                Image: '*\powershell.exe'
              condition: selection
            """
        )
        self.assertEqual(rule.ast.modifier, "endswith")
        self.assertEqual(rule.ast.value, "\\powershell.exe")

    def test_list_of_values_is_or(self):
        rule = _rule(
            r"""
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                Image|endswith:
                  - '\powershell.exe'
                  - '\pwsh.exe'
              condition: selection
            """
        )
        self.assertIsInstance(rule.ast, Or)
        self.assertEqual(len(rule.ast.children), 2)

    def test_all_modifier_is_and(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                CommandLine|contains|all:
                  - foo
                  - bar
              condition: selection
            """
        )
        self.assertIsInstance(rule.ast, And)
        self.assertEqual(len(rule.ast.children), 2)

    def test_multiple_fields_is_and(self):
        rule = _rule(
            r"""
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                EventID: 4688
                Image|endswith: '\cmd.exe'
              condition: selection
            """
        )
        self.assertIsInstance(rule.ast, And)
        self.assertEqual(len(rule.ast.children), 2)

    def test_list_of_maps_is_or_of_and(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                - FieldA: 1
                  FieldB: 2
                - FieldC: 3
              condition: selection
            """
        )
        self.assertIsInstance(rule.ast, Or)
        self.assertEqual(len(rule.ast.children), 2)
        self.assertIsInstance(rule.ast.children[0], And)
        self.assertIsInstance(rule.ast.children[1], FieldMatch)

    def test_bare_keyword_list(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection:
                - mimikatz
                - sekurlsa
              condition: selection
            """
        )
        self.assertIsInstance(rule.ast, Or)
        self.assertEqual(rule.ast.children[0].field, "_raw")


class TestConditionLanguage(unittest.TestCase):
    def test_and_between_selections(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              sel_a: {FieldA: 1}
              sel_b: {FieldB: 2}
              condition: sel_a and sel_b
            """
        )
        self.assertIsInstance(rule.ast, And)

    def test_or_between_selections(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              sel_a: {FieldA: 1}
              sel_b: {FieldB: 2}
              condition: sel_a or sel_b
            """
        )
        self.assertIsInstance(rule.ast, Or)

    def test_not(self):
        from sigmux.ast_nodes import Not

        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              sel_a: {FieldA: 1}
              filt: {FieldB: 2}
              condition: sel_a and not filt
            """
        )
        self.assertIsInstance(rule.ast, And)
        self.assertIsInstance(rule.ast.children[1], Not)

    def test_parentheses_change_grouping(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              a: {FieldA: 1}
              b: {FieldB: 2}
              c: {FieldC: 3}
              condition: a and (b or c)
            """
        )
        self.assertIsInstance(rule.ast, And)
        self.assertIsInstance(rule.ast.children[1], Or)

    def test_one_of_glob(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection_a: {FieldA: 1}
              selection_b: {FieldB: 2}
              other: {FieldC: 3}
              condition: 1 of selection_*
            """
        )
        self.assertIsInstance(rule.ast, Or)
        self.assertEqual(len(rule.ast.children), 2)

    def test_all_of_glob(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              selection_a: {FieldA: 1}
              selection_b: {FieldB: 2}
              condition: all of selection_*
            """
        )
        self.assertIsInstance(rule.ast, And)
        self.assertEqual(len(rule.ast.children), 2)

    def test_all_of_them(self):
        rule = _rule(
            """
            title: t
            logsource: {category: process_creation}
            detection:
              sel_a: {FieldA: 1}
              sel_b: {FieldB: 2}
              condition: all of them
            """
        )
        self.assertIsInstance(rule.ast, And)
        self.assertEqual(len(rule.ast.children), 2)

    def test_unknown_selection_raises(self):
        with self.assertRaises(ValueError):
            _rule(
                """
                title: t
                logsource: {category: process_creation}
                detection:
                  sel_a: {FieldA: 1}
                  condition: sel_b
                """
            )

    def test_missing_condition_raises(self):
        with self.assertRaises(ValueError):
            _rule(
                """
                title: t
                logsource: {category: process_creation}
                detection:
                  sel_a: {FieldA: 1}
                """
            )


if __name__ == "__main__":
    unittest.main()
