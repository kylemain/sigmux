"""Parser for Sigma's boolean `condition` mini-language.

Supports identifiers, `and` / `or` / `not`, parentheses, and the aggregate
forms `1 of <glob>`, `all of <glob>`, `1 of them`, and `all of them`.
"""
from __future__ import annotations

import fnmatch
import re as _re
from typing import Dict, List

from .ast_nodes import And, Node, Or

_TOKEN_RE = _re.compile(r"\(|\)|[A-Za-z0-9_][A-Za-z0-9_*]*")


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall(text)


class _Parser:
    def __init__(self, tokens: List[str], selections: Dict[str, Node]):
        self.tokens = tokens
        self.pos = 0
        self.selections = selections

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def advance(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def expect(self, tok):
        actual = self.advance()
        if actual != tok:
            raise ValueError(f"Expected '{tok}' but found '{actual}' in condition")
        return actual

    def parse(self) -> Node:
        node = self.parse_or()
        if self.pos != len(self.tokens):
            raise ValueError(f"Unexpected trailing tokens: {self.tokens[self.pos:]}")
        return node

    def parse_or(self) -> Node:
        children = [self.parse_and()]
        while self.peek() == "or":
            self.advance()
            children.append(self.parse_and())
        return children[0] if len(children) == 1 else Or(children)

    def parse_and(self) -> Node:
        children = [self.parse_not()]
        while self.peek() == "and":
            self.advance()
            children.append(self.parse_not())
        return children[0] if len(children) == 1 else And(children)

    def parse_not(self) -> Node:
        if self.peek() == "not":
            self.advance()
            from .ast_nodes import Not

            return Not(self.parse_not())
        return self.parse_atom()

    def parse_atom(self) -> Node:
        tok = self.peek()
        if tok == "(":
            self.advance()
            node = self.parse_or()
            self.expect(")")
            return node
        if tok in ("1", "all"):
            return self.parse_aggregate()
        if tok is None:
            raise ValueError("Unexpected end of condition")
        self.advance()
        return self._resolve(tok)

    def parse_aggregate(self) -> Node:
        quantifier = self.advance()  # "1" or "all"
        self.expect("of")
        pattern = self.advance()
        if pattern is None:
            raise ValueError("Expected a selection name or glob after 'of'")
        if pattern == "them":
            names = list(self.selections.keys())
        else:
            names = [n for n in self.selections if fnmatch.fnmatch(n, pattern)]
        if not names:
            raise ValueError(f"No selections match pattern '{pattern}'")
        nodes = [self.selections[n] for n in names]
        if len(nodes) == 1:
            return nodes[0]
        return And(nodes) if quantifier == "all" else Or(nodes)

    def _resolve(self, name: str) -> Node:
        if name not in self.selections:
            raise ValueError(f"Condition references unknown selection '{name}'")
        return self.selections[name]


def parse_condition(text: str, selections: Dict[str, Node]) -> Node:
    tokens = _tokenize(text)
    if not tokens:
        raise ValueError("Empty condition")
    return _Parser(tokens, selections).parse()
