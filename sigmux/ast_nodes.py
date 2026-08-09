"""AST node types for a parsed Sigma detection condition.

The tree is intentionally tiny: everything Sigma's detection language can
express reduces to four shapes once selections have been resolved into
their component field matches.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


class Node:
    """Base class for all AST nodes."""


@dataclass
class FieldMatch(Node):
    field: str
    modifier: str  # one of: eq, contains, startswith, endswith, re
    value: str


@dataclass
class And(Node):
    children: List[Node] = field(default_factory=list)


@dataclass
class Or(Node):
    children: List[Node] = field(default_factory=list)


@dataclass
class Not(Node):
    child: Node
